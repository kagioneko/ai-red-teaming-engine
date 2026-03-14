"""
マルチエージェント監査パイプライン — Attacker / Skeptic / Defender / Judge

通常の単一LLM監査より高精度だが、LLM呼び出しが4倍になるため時間・コストが増加する。
重要なファイルの深堀りや、CI/CD の pre-merge チェックに適している。
"""
from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

from .config import DEFAULT_MODEL, get_parameters
from .extractor import extract_attack_surface
from .fixer import generate_fixes
from .llm_client import LLMClient
from .models import (
    AttackSurfaceMap,
    AuditInput,
    AuditMode,
    AuditParameters,
    AuditReport,
    AuditSummary,
    Issue,
    StaticAnalysisResult,
)
from .normalizer import normalize
from .prompts import (
    ATTACKER_SYSTEM,
    DEFENDER_SYSTEM,
    JUDGE_SYSTEM,
    SKEPTIC_SYSTEM,
    format_analyze,
    format_fix,
    format_judge_merge,
    format_skeptic_review,
    build_system_prompt,
)
from .scorer import assign_issue_ids, assign_priority, sort_issues_by_priority
from .static_tools import run_static_analysis


def run_multi_agent_audit(
    audit_input: AuditInput,
    mode: AuditMode = "deep",
    enable_static: bool = True,
    model: str = DEFAULT_MODEL,
    backend: str = "api",
    log_dir: Path | None = None,
    verbose: bool = True,
) -> AuditReport:
    """
    4エージェント構成の監査パイプライン。

    Phase 1: Attacker  — 攻撃視点で指摘を列挙（高感度）
    Phase 2: Skeptic   — 各指摘を批判的検証（誤検知排除）
    Phase 3: Defender  — 確認済み指摘に修正案を生成
    Phase 4: Judge     — 統合・マージ・最終優先度付け
    """
    scan_id = str(uuid.uuid4())
    params = get_parameters(mode)

    def log(msg: str) -> None:
        if verbose:
            print(msg, file=sys.stderr)

    # ── Ingestion ────────────────────────────────────────────────────
    normalized = normalize(audit_input)
    content = normalized.masked_content

    # ── Static Analysis ──────────────────────────────────────────────
    static_results = StaticAnalysisResult()
    if enable_static and audit_input.file_path:
        static_results = run_static_analysis(
            content=content,
            file_path=audit_input.file_path,
            target_type=normalized.target_type,
        )

    # ── Attack Surface ────────────────────────────────────────────────
    log("  🎯 [1/4] Attacker: 攻撃面を抽出中...")
    attacker_client = LLMClient(model=model, backend=backend)
    surface = extract_attack_surface(normalized, attacker_client, params)

    # ── Phase 1: Attacker ─────────────────────────────────────────────
    log("  🔴 [2/4] Attacker: 脆弱性を列挙中...")
    attacker_client2 = LLMClient(
        model=model,
        backend=backend,
        system_override=ATTACKER_SYSTEM,
    )
    static_text = _format_static_findings(static_results)
    attacker_prompt = format_analyze(
        content=content,
        target_type=normalized.target_type,
        tech_stack=normalized.tech_stack,
        exposure_level=normalized.exposure_level,
        assets=normalized.assets_to_protect,
        attack_surface_json=surface.model_dump_json(indent=2),
        static_findings_text=static_text,
        file_path=audit_input.file_path or "",
    )
    attacker_raw = attacker_client2.call(attacker_prompt)
    attacker_issues: list[Issue] = _parse_issues(attacker_raw)
    log(f"     → {len(attacker_issues)} 件の指摘を検出")

    # ── Phase 2: Skeptic ─────────────────────────────────────────────
    log("  🔵 [3/4] Skeptic: 指摘を批判的検証中...")
    skeptic_client = LLMClient(
        model=model,
        backend=backend,
        system_override=SKEPTIC_SYSTEM,
    )
    skeptic_prompt = format_skeptic_review(
        issues_json=json.dumps(
            [i.model_dump(exclude_none=True) for i in attacker_issues],
            indent=2,
            ensure_ascii=False,
        ),
        content=content,
    )
    skeptic_raw = skeptic_client.call(skeptic_prompt)
    skeptic_reviews = _parse_json_list(skeptic_raw)
    confirmed, fp_count = _count_verdicts(skeptic_reviews)
    log(f"     → 確認: {confirmed} 件 / 誤検知疑い: {fp_count} 件")

    # ── Phase 3: Defender ─────────────────────────────────────────────
    log("  🟢 [4/4] Defender: 修正案を生成中...")
    # confirmed または needs_more_info の指摘のみに絞って修正案生成
    confirmed_issues = _filter_by_skeptic(attacker_issues, skeptic_reviews)
    defender_client = LLMClient(
        model=model,
        backend=backend,
        system_override=DEFENDER_SYSTEM,
    )
    issues_with_fixes = generate_fixes(
        confirmed_issues,
        normalized,
        defender_client,
        params,
    )

    # ── Phase 4: Judge ────────────────────────────────────────────────
    log("  ⚖️  [Judge] 統合・最終優先度付け中...")
    judge_client = LLMClient(
        model=model,
        backend=backend,
        system_override=JUDGE_SYSTEM,
    )
    judge_prompt = format_judge_merge(
        attacker_json=json.dumps(
            [i.model_dump(exclude_none=True) for i in attacker_issues],
            indent=2,
            ensure_ascii=False,
        ),
        skeptic_json=json.dumps(skeptic_reviews, indent=2, ensure_ascii=False),
        defender_json=json.dumps(
            [i.model_dump(exclude_none=True) for i in issues_with_fixes],
            indent=2,
            ensure_ascii=False,
        ),
    )
    judge_raw = judge_client.call(judge_prompt)
    final_issues: list[Issue] = _parse_issues(judge_raw)
    log(f"     → 最終: {len(final_issues)} 件")

    # ── Scoring & Report ─────────────────────────────────────────────
    final_issues = [assign_priority(i) for i in final_issues]
    final_issues = sort_issues_by_priority(final_issues)
    final_issues = assign_issue_ids(final_issues)

    if audit_input.severity_filter:
        _sev_rank = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
        threshold = _sev_rank.get(audit_input.severity_filter, 1)
        final_issues = [i for i in final_issues if _sev_rank.get(i.severity, 0) >= threshold]

    summary = _build_summary(final_issues, static_results, normalized.mask_count)
    report = AuditReport(
        scan_id=scan_id,
        target_type=normalized.target_type,
        tech_stack=normalized.tech_stack,
        audit_mode=mode,
        file_path=audit_input.file_path,
        parameters=params,
        summary=summary,
        attack_surface=surface,
        issues=final_issues,
        static_analysis=static_results,
    )

    if log_dir is not None:
        from .formatters import save_report
        save_report(report, log_dir)

    return report


def _parse_issues(raw: str) -> list[Issue]:
    """LLM 出力から Issue リストを抽出・パース"""
    import re
    match = re.search(r"```(?:json)?\s*(\[[\s\S]+?\])\s*```", raw)
    cleaned = match.group(1) if match else raw[raw.find("["):] if "[" in raw else "[]"
    try:
        data = json.loads(cleaned)
        if not isinstance(data, list):
            return []
        return [Issue.model_validate(item) for item in data if isinstance(item, dict)]
    except Exception:
        return []


def _parse_json_list(raw: str) -> list[dict]:
    """LLM 出力から JSON リストを抽出"""
    try:
        start = raw.find("[")
        end = raw.rfind("]") + 1
        if start != -1 and end > start:
            return json.loads(raw[start:end])
    except (json.JSONDecodeError, ValueError):
        pass
    return []


def _count_verdicts(reviews: list[dict]) -> tuple[int, int]:
    confirmed = sum(1 for r in reviews if r.get("verdict") == "confirmed")
    fp = sum(1 for r in reviews if r.get("verdict") == "false_positive")
    return confirmed, fp


def _filter_by_skeptic(issues: list[Issue], reviews: list[dict]) -> list[Issue]:
    """Skeptic が false_positive と判定した指摘を除外し、confidence を更新"""
    result: list[Issue] = []
    for i, issue in enumerate(issues):
        review = next((r for r in reviews if r.get("issue_index") == i), None)
        if review and review.get("verdict") == "false_positive":
            continue
        if review:
            adj_conf = review.get("adjusted_confidence", issue.confidence)
            adj_sev = review.get("adjusted_severity", issue.severity)
            needs_confirm = review.get("verdict") == "needs_more_info"
            result.append(issue.model_copy(update={
                "confidence": adj_conf,
                "severity": adj_sev,
                "needs_human_confirmation": needs_confirm or issue.needs_human_confirmation,
            }))
        else:
            result.append(issue)
    return result


def _format_static_findings(static: StaticAnalysisResult) -> str:
    if not static.findings:
        return "（静的解析なし）"
    lines = []
    for f in static.findings:
        lines.append(f"[{f.tool}] {f.rule_id} @ line {f.line}: {f.message}")
    return "\n".join(lines)


def _build_summary(
    issues: list[Issue],
    static_results: StaticAnalysisResult,
    mask_count: int,
) -> AuditSummary:
    by_severity: dict[str, int] = {}
    human_confirmation = 0
    for issue in issues:
        by_severity[issue.severity] = by_severity.get(issue.severity, 0) + 1
        if issue.needs_human_confirmation:
            human_confirmation += 1
    return AuditSummary(
        total_issues=len(issues),
        by_severity=by_severity,
        needs_human_confirmation=human_confirmation,
        static_findings=len(static_results.findings),
        llm_findings=len(issues),
        masked_secrets_count=mask_count,
    )
