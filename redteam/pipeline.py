"""4層パイプライン統合 — Ingestion → Analysis → Reporting"""
from __future__ import annotations

import uuid
from pathlib import Path

from .analyzer import analyze
from .config import DEFAULT_MODEL, get_parameters
from .extractor import extract_attack_surface
from .fixer import generate_fixes
from .formatters import save_report
from .llm_client import LLMClient
from .models import (
    AttackSurfaceMap,
    AuditInput,
    AuditMode,
    AuditReport,
    AuditSummary,
    DirAuditReport,
    FileAuditResult,
    Issue,
    Severity,
    StaticAnalysisResult,
    TargetType,
)
from .ignorer import IgnoreRules, filter_issues, load_ignore_rules, should_skip_file
from .normalizer import normalize
from .scorer import assign_issue_ids, assign_priority, sort_issues_by_priority
from .static_tools import run_static_analysis

# ディレクトリ監査で対象とする拡張子とその自動判定タイプ
_EXT_TO_TYPE: dict[str, TargetType] = {
    ".py": "code", ".js": "code", ".ts": "code", ".jsx": "code", ".tsx": "code",
    ".go": "code", ".rs": "code", ".java": "code", ".rb": "code", ".php": "code",
    ".c": "code", ".cpp": "code", ".cs": "code", ".swift": "code", ".kt": "code",
    ".sh": "code", ".bash": "code",
    ".yaml": "api", ".yml": "api", ".json": "api", ".toml": "api",
    ".md": "spec", ".rst": "spec", ".txt": "spec",
}

_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", "dist", "build", ".mypy_cache", ".pytest_cache", "coverage",
}

_MAX_FILE_BYTES = 200_000  # 200KB 超はスキップ


def run_audit(
    audit_input: AuditInput,
    mode: AuditMode = "deep",
    enable_static: bool = True,
    model: str = DEFAULT_MODEL,
    backend: str = "api",
    log_dir: Path | None = None,
    ignore_rules: IgnoreRules | None = None,
    rules_file: Path | None = None,
) -> AuditReport:
    """
    メイン監査パイプライン。

    Layer 1 (Ingestion):  正規化・チャンク分割・機密マスキング
    Layer 2 (Analysis):   攻撃面抽出 + 静的解析
    Layer 3 (Analysis):   LLM敵対的分析（静的解析結果を統合）
    Layer 4 (Analysis):   修正案生成
    Reporting:            スコアリング・出力
    """
    scan_id = str(uuid.uuid4())
    params = get_parameters(mode)
    client = LLMClient(model=model, backend=backend)

    # ── Layer 1: Ingestion ────────────────────────────────────────────
    normalized = normalize(audit_input)

    # ── Layer 2: Attack Surface + Static Analysis ─────────────────────
    surface = extract_attack_surface(normalized, client, params)

    static_results: StaticAnalysisResult = StaticAnalysisResult()
    if enable_static and audit_input.file_path:
        static_results = run_static_analysis(
            content=normalized.masked_content,
            file_path=audit_input.file_path,
            target_type=normalized.target_type,
            rules_file=rules_file,
        )
    elif enable_static:
        # ファイルパスなしの場合もコンテンツから静的解析を実行
        static_results = run_static_analysis(
            content=normalized.masked_content,
            file_path="",
            target_type=normalized.target_type,
            rules_file=rules_file,
        )

    # ── Layer 3: Adversarial Analysis ────────────────────────────────
    issues = analyze(normalized, surface, static_results, client, params, mode)

    # ── Layer 4: Fix Generation ───────────────────────────────────────
    issues = generate_fixes(issues, normalized, client, params)

    # ── Reporting ─────────────────────────────────────────────────────
    issues = [assign_priority(i) for i in issues]
    issues = sort_issues_by_priority(issues)
    issues = assign_issue_ids(issues)

    # severity_filter の適用
    if audit_input.severity_filter:
        _sev_rank = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
        threshold = _sev_rank.get(audit_input.severity_filter, 1)
        issues = [i for i in issues if _sev_rank.get(i.severity, 0) >= threshold]

    # ignore_rules の適用
    if ignore_rules and not ignore_rules.is_empty:
        issues = filter_issues(issues, ignore_rules)

    # 差分追跡（patch モード）
    if mode == "patch" and audit_input.previous_findings:
        issues = _apply_diff_tracking(issues, audit_input.previous_findings)

    summary = _build_summary(issues, static_results, normalized.mask_count)

    report = AuditReport(
        scan_id=scan_id,
        target_type=normalized.target_type,
        tech_stack=normalized.tech_stack,
        audit_mode=mode,
        file_path=audit_input.file_path,
        parameters=params,
        summary=summary,
        attack_surface=surface,
        issues=issues,
        static_analysis=static_results,
    )

    # ログ保存
    if log_dir is not None:
        save_report(report, log_dir)

    return report


def run_dir_audit(
    target_dir: Path,
    mode: AuditMode = "deep",
    enable_static: bool = True,
    model: str = DEFAULT_MODEL,
    backend: str = "api",
    log_dir: Path | None = None,
    target_type: TargetType | None = None,
    tech_stack: list[str] | None = None,
    system_overview: str = "",
    exposure: str = "internal",
    severity_filter: Severity | None = None,
    extensions: set[str] | None = None,
    verbose: bool = True,
    ignore_rules: IgnoreRules | None = None,
) -> DirAuditReport:
    """
    ディレクトリ丸ごと監査。
    対象ファイルを再帰的に収集し、ファイルごとに run_audit() を実行して集約する。
    """
    import sys

    scan_id = str(uuid.uuid4())
    allowed_exts = extensions if extensions else set(_EXT_TO_TYPE.keys())
    tech_stack = tech_stack or []
    rules = ignore_rules or IgnoreRules()

    # ファイル収集
    target_files: list[Path] = []
    skipped: list[str] = []

    for p in sorted(target_dir.rglob("*")):
        # 組み込みスキップディレクトリ判定
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if not p.is_file():
            continue
        if p.suffix.lower() not in allowed_exts:
            continue
        if p.stat().st_size > _MAX_FILE_BYTES:
            skipped.append(str(p))
            if verbose:
                print(f"  ⚠️  スキップ（サイズ超過）: {p}", file=sys.stderr)
            continue
        # .redteam-ignore のファイルパターン照合
        if should_skip_file(p, rules, base_dir=target_dir):
            skipped.append(str(p))
            if verbose:
                print(f"  🚫 スキップ（ignore ルール）: {p}", file=sys.stderr)
            continue
        target_files.append(p)

    if verbose:
        print(f"📂 対象ファイル: {len(target_files)} 件", file=sys.stderr)

    file_results: list[FileAuditResult] = []

    for i, fp in enumerate(target_files, 1):
        if verbose:
            print(f"  [{i}/{len(target_files)}] {fp}", file=sys.stderr)

        try:
            content = fp.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            skipped.append(str(fp))
            file_results.append(FileAuditResult(file_path=str(fp), error=str(e), report=_empty_report(fp, mode)))
            continue

        detected_type = target_type or _EXT_TO_TYPE.get(fp.suffix.lower(), "code")

        audit_input = AuditInput(
            target_content=content,
            target_type=detected_type,
            tech_stack=tech_stack,
            system_overview=system_overview,
            exposure_level=exposure,  # type: ignore
            severity_filter=severity_filter,
            file_path=str(fp.resolve()),
        )

        try:
            report = run_audit(
                audit_input=audit_input,
                mode=mode,
                enable_static=enable_static,
                model=model,
                backend=backend,
                log_dir=None,  # ディレクトリ監査は最後にまとめて保存
                ignore_rules=rules,
            )
            file_results.append(FileAuditResult(file_path=str(fp), report=report))
        except Exception as e:
            file_results.append(FileAuditResult(
                file_path=str(fp),
                error=str(e),
                report=_empty_report(fp, mode),
            ))

    # 集約サマリー
    all_issues: list[Issue] = []
    for fr in file_results:
        if not fr.error:
            all_issues.extend(fr.report.issues)

    static_total = StaticAnalysisResult()
    for fr in file_results:
        if not fr.error:
            static_total = StaticAnalysisResult(
                semgrep_ran=static_total.semgrep_ran or fr.report.static_analysis.semgrep_ran,
                gitleaks_ran=static_total.gitleaks_ran or fr.report.static_analysis.gitleaks_ran,
                findings=static_total.findings + fr.report.static_analysis.findings,
            )

    aggregated_summary = _build_summary(all_issues, static_total, 0)

    dir_report = DirAuditReport(
        scan_id=scan_id,
        target_dir=str(target_dir.resolve()),
        audit_mode=mode,
        file_count=len(target_files),
        skipped_files=skipped,
        file_results=file_results,
        aggregated_summary=aggregated_summary,
    )

    if log_dir is not None:
        from .formatters import format_dir_json, format_dir_markdown, format_dir_sarif
        log_dir.mkdir(parents=True, exist_ok=True)
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        (log_dir / f"{ts}_{scan_id[:8]}_dir_report.json").write_text(
            format_dir_json(dir_report), encoding="utf-8"
        )
        (log_dir / f"{ts}_{scan_id[:8]}_dir_report.md").write_text(
            format_dir_markdown(dir_report), encoding="utf-8"
        )

    return dir_report


def _empty_report(fp: Path, mode: AuditMode) -> AuditReport:
    """エラー時のプレースホルダーレポート"""
    from .config import get_parameters
    return AuditReport(
        scan_id=str(uuid.uuid4()),
        target_type="code",
        tech_stack=[],
        audit_mode=mode,
        file_path=str(fp),
        parameters=get_parameters(mode),
        summary=AuditSummary(),
        attack_surface=AttackSurfaceMap(),
        issues=[],
        static_analysis=StaticAnalysisResult(),
    )


def _build_summary(
    issues: list[Issue],
    static_results: StaticAnalysisResult,
    mask_count: int,
) -> AuditSummary:
    by_severity: dict[str, int] = {}
    human_confirmation = 0
    static_count = 0
    llm_count = 0

    for issue in issues:
        by_severity[issue.severity] = by_severity.get(issue.severity, 0) + 1
        if issue.needs_human_confirmation:
            human_confirmation += 1
        if issue.source in ("semgrep", "gitleaks"):
            static_count += 1
        else:
            llm_count += 1

    return AuditSummary(
        total_issues=len(issues),
        by_severity=by_severity,
        needs_human_confirmation=human_confirmation,
        static_findings=static_count,
        llm_findings=llm_count,
        masked_secrets_count=mask_count,
    )


def _apply_diff_tracking(
    new_issues: list[Issue],
    previous_issues: list[Issue],
) -> list[Issue]:
    """
    前回監査との差分を追跡する。
    fingerprint をキーとして以下を分類:
    - 新規: first_seen_scan_id を現在のscannに設定
    - 再登場（regression）: status=open で regression=True
    """
    prev_fps: dict[str, Issue] = {i.fingerprint: i for i in previous_issues if i.fingerprint}

    result: list[Issue] = []
    for issue in new_issues:
        fp = issue.fingerprint or issue.compute_fingerprint()
        prev = prev_fps.get(fp)

        if prev and prev.status == "resolved":
            # 解決済みが再登場 → regression
            result.append(
                issue.model_copy(update={
                    "fingerprint": fp,
                    "regression": True,
                    "first_seen_scan_id": prev.first_seen_scan_id or "",
                })
            )
        elif prev:
            # 継続中
            result.append(
                issue.model_copy(update={
                    "fingerprint": fp,
                    "first_seen_scan_id": prev.first_seen_scan_id or "",
                })
            )
        else:
            # 新規
            result.append(issue.model_copy(update={"fingerprint": fp}))

    return result
