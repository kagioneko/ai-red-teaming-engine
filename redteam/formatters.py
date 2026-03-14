"""JSON / Markdown / SARIF レポート出力 — Reporting Layer"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import AuditReport, CompareReport, DirAuditReport, Issue

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


_SARIF_LEVEL = {
    "Critical": "error",
    "High":     "error",
    "Medium":   "warning",
    "Low":      "note",
    "Info":     "none",
}


def format_sarif(report: AuditReport) -> str:
    """SARIF 2.1.0 形式出力（GitHub Security Tab / VS Code 対応）"""
    rules: list[dict] = []
    rule_ids_seen: set[str] = set()
    results: list[dict] = []

    for issue in report.issues:
        rule_id = f"RTE-{issue.category.replace(' ', '-')}-{issue.severity}"
        if rule_id not in rule_ids_seen:
            rule_ids_seen.add(rule_id)
            rules.append({
                "id": rule_id,
                "name": f"{issue.category.replace(' ', '')}Check",
                "shortDescription": {"text": issue.title},
                "fullDescription": {"text": issue.why_this_matters or issue.title},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(issue.severity, "warning")},
                "properties": {"tags": ["security", issue.category, issue.severity]},
            })

        location: dict = {}
        file_uri = issue.file or report.file_path
        if file_uri:
            region: dict = {}
            if issue.line_start is not None:
                region["startLine"] = issue.line_start
            if issue.line_end is not None:
                region["endLine"] = issue.line_end
            location = {
                "physicalLocation": {
                    "artifactLocation": {"uri": str(file_uri), "uriBaseId": "%SRCROOT%"},
                    **({"region": region} if region else {}),
                }
            }

        result: dict = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(issue.severity, "warning"),
            "message": {
                "text": f"[{issue.confidence} confidence] {issue.title}\n{issue.why_this_matters}".strip()
            },
            "fingerprints": {"primaryLocationLineHash": issue.fingerprint},
            "properties": {
                "priority": issue.priority,
                "source": issue.source,
                "needsHumanConfirmation": issue.needs_human_confirmation,
            },
        }
        if location:
            result["locations"] = [location]
        results.append(result)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI-Red-Teaming-Engine",
                        "version": report.engine_version,
                        "informationUri": "https://github.com/EmiliaLab/ai-red-teaming-engine",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "scanId": report.scan_id,
                    "auditMode": report.audit_mode,
                    "targetType": report.target_type,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def format_dir_json(dir_report: DirAuditReport) -> str:
    """ディレクトリ監査JSONレポート"""
    return dir_report.model_dump_json(indent=2, exclude_none=True)


def format_dir_markdown(dir_report: DirAuditReport) -> str:
    """ディレクトリ監査Markdownレポート"""
    lines: list[str] = []
    s = dir_report.aggregated_summary

    lines += [
        "# AI-Red-Teaming-Engine ディレクトリ監査レポート",
        "",
        "> **注意**: このレポートはプロトタイプ版エンジンによる出力です。全ての指摘は人間による最終確認が必要です。",
        "",
        "## 概要",
        "",
        f"| 項目 | 内容 |",
        f"|------|------|",
        f"| Scan ID | `{dir_report.scan_id}` |",
        f"| 対象ディレクトリ | `{dir_report.target_dir}` |",
        f"| 監査モード | {dir_report.audit_mode} |",
        f"| 走査ファイル数 | {dir_report.file_count} |",
        f"| スキップ数 | {len(dir_report.skipped_files)} |",
        f"| 生成日時 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |",
        "",
        "## 集約サマリー",
        "",
        f"**合計: {s.total_issues} 件**",
        "",
        "| Severity | 件数 |",
        "|----------|------|",
    ]
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = s.by_severity.get(sev, 0)
        if count > 0:
            emoji = _SEVERITY_EMOJI.get(sev, "")
            lines.append(f"| {emoji} {sev} | {count} |")

    lines += [
        "",
        f"- 人間確認が必要: **{s.needs_human_confirmation} 件**",
        f"- LLM検出: {s.llm_findings} 件 / 静的解析検出: {s.static_findings} 件",
        "",
        "## ファイル別結果",
        "",
    ]

    for fr in dir_report.file_results:
        if fr.error:
            lines.append(f"### ❌ `{fr.file_path}`")
            lines.append(f"エラー: {fr.error}")
            lines.append("")
            continue

        rpt = fr.report
        rs = rpt.summary
        lines.append(f"### 📄 `{fr.file_path}`")
        lines.append("")

        sev_parts = []
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            cnt = rs.by_severity.get(sev, 0)
            if cnt > 0:
                sev_parts.append(f"{_SEVERITY_EMOJI.get(sev, '')} {sev}:{cnt}")
        if sev_parts:
            lines.append(f"**指摘**: {' / '.join(sev_parts)}")
        else:
            lines.append("**指摘**: なし ✅")
        lines.append("")

        for issue in rpt.issues:
            emoji = _SEVERITY_EMOJI.get(issue.severity, "")
            lines.append(
                f"- {emoji} **[{issue.severity}]** `{issue.issue_id}` {issue.title}"
                + (f" — {issue.affected_area}" if issue.affected_area else "")
            )
        lines.append("")

    if dir_report.skipped_files:
        lines += ["## スキップされたファイル", ""]
        for f in dir_report.skipped_files:
            lines.append(f"- `{f}`")
        lines.append("")

    return "\n".join(lines)


def format_dir_sarif(dir_report: DirAuditReport) -> str:
    """ディレクトリ監査SARIF 2.1.0 出力（全ファイルを1 run にマージ）"""
    rules: list[dict] = []
    rule_ids_seen: set[str] = set()
    results: list[dict] = []

    for fr in dir_report.file_results:
        if fr.error:
            continue
        for issue in fr.report.issues:
            rule_id = f"RTE-{issue.category.replace(' ', '-')}-{issue.severity}"
            if rule_id not in rule_ids_seen:
                rule_ids_seen.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": f"{issue.category.replace(' ', '')}Check",
                    "shortDescription": {"text": issue.title},
                    "defaultConfiguration": {"level": _SARIF_LEVEL.get(issue.severity, "warning")},
                    "properties": {"tags": ["security", issue.category, issue.severity]},
                })

            file_uri = issue.file or fr.file_path
            region: dict = {}
            if issue.line_start is not None:
                region["startLine"] = issue.line_start
            if issue.line_end is not None:
                region["endLine"] = issue.line_end

            result: dict = {
                "ruleId": rule_id,
                "level": _SARIF_LEVEL.get(issue.severity, "warning"),
                "message": {"text": f"[{issue.confidence}] {issue.title}"},
                "fingerprints": {"primaryLocationLineHash": issue.fingerprint},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(file_uri),
                                "uriBaseId": "%SRCROOT%",
                            },
                            **({"region": region} if region else {}),
                        }
                    }
                ],
            }
            results.append(result)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AI-Red-Teaming-Engine",
                        "version": dir_report.engine_version,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "scanId": dir_report.scan_id,
                    "auditMode": dir_report.audit_mode,
                    "targetDir": dir_report.target_dir,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def format_compare_markdown(compare: CompareReport) -> str:
    """バックエンド比較レポート Markdown"""
    lines: list[str] = []
    b1, b2 = compare.backends[0], compare.backends[1] if len(compare.backends) > 1 else "?"

    lines += [
        "# AI-Red-Teaming-Engine バックエンド比較レポート",
        "",
        f"> **対象ファイル**: `{compare.file_path}`",
        f"> **監査モード**: {compare.audit_mode}",
        f"> **比較**: `{b1}` vs `{b2}`",
        "",
        f"## 一致率: {compare.agreement_rate:.1f}%",
        "",
    ]

    # 各バックエンドのサマリー
    lines.append("## 各バックエンドのサマリー")
    lines.append("")
    lines.append(f"| 項目 | {b1} | {b2} |")
    lines.append("|------|------|------|")

    r1 = next((r for r in compare.backend_results if r.backend == b1), None)
    r2 = next((r for r in compare.backend_results if r.backend == b2), None)

    if r1 and r2:
        lines.append(f"| 合計指摘数 | {r1.report.summary.total_issues} | {r2.report.summary.total_issues} |")
        for sev in ["Critical", "High", "Medium", "Low"]:
            c1 = r1.report.summary.by_severity.get(sev, 0)
            c2 = r2.report.summary.by_severity.get(sev, 0)
            if c1 or c2:
                emoji = _SEVERITY_EMOJI.get(sev, "")
                lines.append(f"| {emoji} {sev} | {c1} | {c2} |")
        lines.append(f"| 実行時間 | {r1.elapsed_sec:.1f}s | {r2.elapsed_sec:.1f}s |")
    lines.append("")

    # 両方が検出した問題
    if compare.issues_both:
        lines.append(f"## ✅ 両方が検出（{len(compare.issues_both)}件）")
        lines.append("")
        for ci in compare.issues_both:
            emoji = _SEVERITY_EMOJI.get(ci.severity, "")
            lines.append(f"- {emoji} **[{ci.severity}]** [{ci.category}] {ci.title}")
        lines.append("")

    # バックエンド固有の検出
    for backend in compare.backends:
        only = compare.issues_only.get(backend, [])
        if only:
            lines.append(f"## 🔵 `{backend}` のみが検出（{len(only)}件）")
            lines.append("")
            for ci in only:
                emoji = _SEVERITY_EMOJI.get(ci.severity, "")
                lines.append(f"- {emoji} **[{ci.severity}]** [{ci.category}] {ci.title}")
            lines.append("")

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
