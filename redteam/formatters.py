"""JSON / Markdown レポート出力 — Reporting Layer"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from .models import AuditReport, Issue

_SEVERITY_EMOJI = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
    "Info": "⚪",
}


def format_json(report: AuditReport) -> str:
    """SPEC Section 11.2 準拠のJSON出力"""
    return report.model_dump_json(indent=2, exclude_none=True)


def format_markdown(report: AuditReport) -> str:
    """人間向けMarkdownレポート"""
    lines: list[str] = []

    # ヘッダー
    lines += [
        f"# AI-Red-Teaming-Engine 監査レポート",
        f"",
        f"> **注意**: このレポートはプロトタイプ版エンジン (v{report.engine_version}) による出力です。",
        f"> 全ての指摘は人間による最終確認が必要です。",
        f"",
        f"## 概要",
        f"",
        f"| 項目 | 内容 |",
        f"|------|------|",
        f"| Scan ID | `{report.scan_id}` |",
        f"| 対象種別 | {report.target_type} |",
        f"| ファイル | {report.file_path or '（直接入力）'} |",
        f"| 監査モード | {report.audit_mode} |",
        f"| 技術スタック | {', '.join(report.tech_stack)} |",
        f"| 生成日時 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |",
        f"",
    ]

    # サマリー
    s = report.summary
    lines += [
        f"## 指摘サマリー",
        f"",
        f"**合計: {s.total_issues} 件**",
        f"",
        f"| Severity | 件数 |",
        f"|----------|------|",
    ]
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = s.by_severity.get(sev, 0)
        if count > 0:
            lines.append(f"| {_SEVERITY_EMOJI.get(sev, '')} {sev} | {count} |")

    lines += [
        f"",
        f"- 人間確認が必要: **{s.needs_human_confirmation} 件**",
        f"- LLM検出: {s.llm_findings} 件 / 静的解析検出: {s.static_findings} 件",
        f"- マスク済みシークレット: {s.masked_secrets_count} 件",
        f"",
    ]

    # 攻撃面マップ
    surf = report.attack_surface
    lines += ["## 攻撃面マップ", ""]
    if surf.external_inputs:
        lines.append(f"**外部入力点**: {', '.join(surf.external_inputs)}")
    if surf.auth_boundaries:
        lines.append(f"**認証境界**: {', '.join(surf.auth_boundaries)}")
    if surf.persistence_points:
        lines.append(f"**永続化箇所**: {', '.join(surf.persistence_points)}")
    if surf.tool_calls:
        lines.append(f"**ツール呼び出し**: {', '.join(surf.tool_calls)}")
    lines.append("")

    # 指摘一覧
    lines += ["## 指摘一覧", ""]

    for issue in report.issues:
        emoji = _SEVERITY_EMOJI.get(issue.severity, "")
        lines += [
            f"---",
            f"",
            f"### {issue.issue_id}: {issue.title}",
            f"",
            f"| | |",
            f"|--|--|",
            f"| **Severity** | {emoji} {issue.severity} |",
            f"| **Confidence** | {issue.confidence} |",
            f"| **Category** | {issue.category} |",
            f"| **Source** | {issue.source} |",
            f"| **Affected Area** | {issue.affected_area or '—'} |",
            f"| **Priority Score** | {issue.priority} |",
            f"| **Fingerprint** | `{issue.fingerprint}` |",
            f"",
        ]

        if issue.why_this_matters:
            lines += [f"**なぜ問題か**", f"", f"{issue.why_this_matters}", f""]

        if issue.attack_perspective:
            lines += [f"**攻撃者視点**", f"", f"{issue.attack_perspective}", f""]

        if issue.evidence:
            lines += [f"**根拠**", f"", f"```", f"{issue.evidence}", f"```", f""]

        if issue.conditions_for_failure:
            lines += [f"**成立条件**", f"", f"{issue.conditions_for_failure}", f""]

        if issue.minimal_fix:
            lines += [f"**最小修正案**", f"", f"{issue.minimal_fix}", f""]

        if issue.hardening_suggestion:
            lines += [f"**強化案**", f"", f"{issue.hardening_suggestion}", f""]

        if issue.false_positive_risk:
            lines += [f"**誤検知リスク**", f"", f"{issue.false_positive_risk}", f""]

        lines += [
            f"**人間確認が必要**: {'Yes ⚠️' if issue.needs_human_confirmation else 'No'}",
            f"",
        ]

    return "\n".join(lines)


def save_report(
    report: AuditReport,
    log_dir: Path,
    formats: list[str] = ("json", "md"),
) -> dict[str, Path]:
    """レポートをファイルに保存し、保存パスの辞書を返す"""
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    saved: dict[str, Path] = {}

    if "json" in formats:
        json_path = log_dir / f"{ts}_{report.scan_id[:8]}_report.json"
        json_path.write_text(format_json(report), encoding="utf-8")
        saved["json"] = json_path

    if "md" in formats:
        md_path = log_dir / f"{ts}_{report.scan_id[:8]}_report.md"
        md_path.write_text(format_markdown(report), encoding="utf-8")
        saved["md"] = md_path

    return saved
