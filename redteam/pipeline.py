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
    Issue,
    StaticAnalysisResult,
)
from .normalizer import normalize
from .scorer import assign_issue_ids, assign_priority, sort_issues_by_priority
from .static_tools import run_static_analysis


def run_audit(
    audit_input: AuditInput,
    mode: AuditMode = "deep",
    enable_static: bool = True,
    model: str = DEFAULT_MODEL,
    backend: str = "api",
    log_dir: Path | None = None,
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
        )
    elif enable_static:
        # ファイルパスなしの場合もコンテンツから静的解析を実行
        static_results = run_static_analysis(
            content=normalized.masked_content,
            file_path="",
            target_type=normalized.target_type,
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
