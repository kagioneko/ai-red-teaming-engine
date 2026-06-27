"""JSON / Markdown / SARIF / HTML レポート出力 — Reporting Layer"""
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

_CONFIDENCE_PREFIX = {
    "High":   "🚨 確認済み脆弱性",
    "Medium": "⚠️  要確認",
    "Low":    "💬 参考情報（誤検知の可能性あり）",
}

_CONFIDENCE_INVESTIGATE_NOTE = {
    "Low": "詳しく調査が必要な場合は `--investigate` オプションで再スキャンしてください。",
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
        conf_prefix = _CONFIDENCE_PREFIX.get(issue.confidence, "")
        lines += [
            f"---",
            f"",
            f"### {conf_prefix} — {issue.issue_id}: {issue.title}",
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

        if issue.confidence == "Low":
            lines += [
                f"> 💬 用途によっては安全な可能性があります。一応ご報告します。",
                f"> 詳しく調査が必要な場合は `--investigate` オプションで再スキャンできます。",
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


_SEV_COLOR = {
    "Critical": "#e53e3e",
    "High":     "#dd6b20",
    "Medium":   "#d69e2e",
    "Low":      "#38a169",
    "Info":     "#718096",
}

_SEV_BG = {
    "Critical": "#fff5f5",
    "High":     "#fffaf0",
    "Medium":   "#fffff0",
    "Low":      "#f0fff4",
    "Info":     "#f7fafc",
}


def format_html(report: AuditReport) -> str:
    """ブラウザで見られるインタラクティブHTMLレポート"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    s = report.summary

    sev_bars = ""
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = s.by_severity.get(sev, 0)
        if count == 0:
            continue
        color = _SEV_COLOR.get(sev, "#718096")
        emoji = _SEVERITY_EMOJI.get(sev, "")
        sev_bars += f"""
        <div class="sev-row">
          <span class="sev-label" style="color:{color}">{emoji} {sev}</span>
          <span class="sev-count" style="background:{color}">{count}</span>
        </div>"""

    issues_html = ""
    for issue in report.issues:
        color = _SEV_COLOR.get(issue.severity, "#718096")
        bg    = _SEV_BG.get(issue.severity, "#f7fafc")
        emoji = _SEVERITY_EMOJI.get(issue.severity, "")
        conf_label = _CONFIDENCE_PREFIX.get(issue.confidence, issue.confidence)

        def row(label: str, val: str) -> str:
            if not val:
                return ""
            return f'<tr><th>{label}</th><td>{val}</td></tr>'

        evidence_block = ""
        if issue.evidence:
            evidence_block = f'<pre class="evidence">{_esc(issue.evidence)}</pre>'

        details = "".join([
            row("なぜ問題か", _esc(issue.why_this_matters or "")),
            row("攻撃者視点", _esc(issue.attack_perspective or "")),
            row("成立条件", _esc(issue.conditions_for_failure or "")),
            row("最小修正案", _esc(issue.minimal_fix or "")),
            row("強化案", _esc(issue.hardening_suggestion or "")),
            row("誤検知リスク", _esc(issue.false_positive_risk or "")),
        ])

        issues_html += f"""
        <details class="issue-card" style="border-left:4px solid {color};background:{bg}">
          <summary>
            <span class="issue-sev" style="color:{color}">{emoji} {issue.severity}</span>
            <span class="issue-id">{issue.issue_id}</span>
            <span class="issue-title">{_esc(issue.title)}</span>
            <span class="issue-conf">{conf_label}</span>
          </summary>
          <div class="issue-body">
            <table class="meta-table">
              {row("Category", _esc(issue.category))}
              {row("Affected Area", _esc(issue.affected_area or "—"))}
              {row("Source", _esc(issue.source))}
              {row("Priority", str(issue.priority))}
              {row("Fingerprint", f'<code>{issue.fingerprint}</code>')}
              {row("人間確認", "⚠️ Yes" if issue.needs_human_confirmation else "No")}
            </table>
            {evidence_block}
            <table class="detail-table">{details}</table>
          </div>
        </details>"""

    surf = report.attack_surface
    surf_items = ""
    for label, items in [
        ("外部入力点", surf.external_inputs),
        ("認証境界", surf.auth_boundaries),
        ("永続化箇所", surf.persistence_points),
        ("ツール呼び出し", surf.tool_calls),
    ]:
        if items:
            tags = "".join(f'<span class="tag">{_esc(i)}</span>' for i in items)
            surf_items += f'<div class="surf-row"><b>{label}</b>: {tags}</div>'

    html = f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI-Red-Teaming-Engine Report — {_esc(report.file_path or "scan")}</title>
<style>
  :root{{--bg:#f8fafc;--card:#fff;--border:#e2e8f0;--text:#2d3748;--muted:#718096}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--bg);color:var(--text);line-height:1.6}}
  header{{background:#1a202c;color:#fff;padding:1.5rem 2rem}}
  header h1{{font-size:1.4rem;font-weight:700}}
  header p{{color:#a0aec0;font-size:.85rem;margin-top:.25rem}}
  .container{{max-width:960px;margin:2rem auto;padding:0 1rem}}
  .card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.25rem;margin-bottom:1rem}}
  .card h2{{font-size:1rem;font-weight:600;margin-bottom:.75rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}}
  .meta-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:.5rem}}
  .meta-item{{font-size:.85rem}}.meta-item b{{display:block;color:var(--muted);font-size:.75rem}}
  .sev-row{{display:flex;align-items:center;gap:.5rem;margin:.2rem 0}}
  .sev-label{{font-size:.9rem;font-weight:600;min-width:100px}}
  .sev-count{{background:#333;color:#fff;border-radius:9999px;padding:.1rem .6rem;font-size:.8rem;font-weight:700}}
  .surf-row{{margin:.3rem 0;font-size:.9rem}}
  .tag{{display:inline-block;background:#edf2f7;border-radius:4px;padding:.1rem .4rem;margin:.1rem;font-size:.8rem}}
  details.issue-card{{border-radius:6px;margin:.6rem 0;overflow:hidden}}
  details.issue-card summary{{display:flex;align-items:center;gap:.6rem;padding:.75rem 1rem;cursor:pointer;list-style:none;flex-wrap:wrap}}
  details.issue-card summary::-webkit-details-marker{{display:none}}
  details.issue-card summary::before{{content:"▶";font-size:.65rem;transition:.15s}}
  details[open].issue-card summary::before{{content:"▼"}}
  .issue-sev{{font-weight:700;font-size:.85rem;min-width:90px}}
  .issue-id{{font-family:monospace;font-size:.8rem;color:var(--muted)}}
  .issue-title{{flex:1;font-weight:600;font-size:.9rem}}
  .issue-conf{{font-size:.75rem;color:var(--muted)}}
  .issue-body{{padding:1rem 1.25rem;border-top:1px solid rgba(0,0,0,.06)}}
  table.meta-table,table.detail-table{{width:100%;border-collapse:collapse;margin:.5rem 0;font-size:.85rem}}
  table th{{width:130px;text-align:left;color:var(--muted);font-weight:600;padding:.3rem .5rem;white-space:nowrap;vertical-align:top}}
  table td{{padding:.3rem .5rem;vertical-align:top}}
  pre.evidence{{background:#1a202c;color:#e2e8f0;border-radius:6px;padding:.75rem;font-size:.8rem;overflow-x:auto;margin:.5rem 0;white-space:pre-wrap}}
  footer{{text-align:center;color:var(--muted);font-size:.8rem;padding:2rem 0}}
</style>
</head>
<body>
<header>
  <h1>🛡️ AI-Red-Teaming-Engine 監査レポート</h1>
  <p>Scan ID: {report.scan_id} &nbsp;|&nbsp; 生成: {now} &nbsp;|&nbsp; Engine v{report.engine_version}</p>
</header>
<div class="container">

  <div class="card">
    <h2>概要</h2>
    <div class="meta-grid">
      <div class="meta-item"><b>対象ファイル</b>{_esc(report.file_path or "（直接入力）")}</div>
      <div class="meta-item"><b>対象種別</b>{_esc(report.target_type)}</div>
      <div class="meta-item"><b>監査モード</b>{_esc(report.audit_mode)}</div>
      <div class="meta-item"><b>技術スタック</b>{_esc(", ".join(report.tech_stack))}</div>
      <div class="meta-item"><b>合計指摘数</b>{s.total_issues} 件</div>
      <div class="meta-item"><b>人間確認必要</b>{s.needs_human_confirmation} 件</div>
    </div>
  </div>

  <div class="card">
    <h2>指摘サマリー</h2>
    {sev_bars}
    <p style="margin-top:.75rem;font-size:.85rem;color:var(--muted)">
      LLM検出: {s.llm_findings} 件 &nbsp;/&nbsp; 静的解析検出: {s.static_findings} 件 &nbsp;/&nbsp; マスク済みシークレット: {s.masked_secrets_count} 件
    </p>
  </div>

  {'<div class="card"><h2>攻撃面マップ</h2>' + surf_items + '</div>' if surf_items else ''}

  <div class="card">
    <h2>指摘一覧 ({s.total_issues} 件)</h2>
    {issues_html if issues_html else '<p style="color:var(--muted)">指摘なし ✅</p>'}
  </div>

</div>
<footer>⚠️ このレポートはプロトタイプ版エンジンによる出力です。全ての指摘は人間による最終確認が必要です。</footer>
</body>
</html>"""
    return html


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


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
