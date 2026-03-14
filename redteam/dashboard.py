"""
Web UIダッシュボード — logs/ の監査レポートをブラウザで可視化

起動:
    python3 -m redteam.dashboard           # デフォルト: localhost:7374
    python3 -m redteam.dashboard --port 8080 --logs-dir /path/to/logs
    redteam-dashboard                      # pip install 後
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

import click

try:
    from flask import Flask, abort, jsonify, render_template_string, request
except ImportError:
    print(
        "Flask が見つかりません。インストールしてください:\n"
        "  pip install flask\n"
        "または:\n"
        "  pip install 'ai-red-teaming-engine[dashboard]'",
        file=sys.stderr,
    )
    sys.exit(1)

# ─── 定数 ────────────────────────────────────────────────────────────────────

_DEFAULT_PORT = 7374
_DEFAULT_LOGS = Path(__file__).parent.parent / "logs"

# 重大度ごとの色
_SEVERITY_COLOR = {
    "Critical": "#e53e3e",
    "High":     "#dd6b20",
    "Medium":   "#d69e2e",
    "Low":      "#38a169",
    "Info":     "#718096",
}

# ─── HTML テンプレート ────────────────────────────────────────────────────────

_INDEX_HTML = """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RedTeam Dashboard</title>
<style>
  :root {
    --bg: #0f1117; --card: #1a1d27; --border: #2d3148;
    --text: #e2e8f0; --muted: #718096; --accent: #7c3aed;
    --critical: #e53e3e; --high: #dd6b20; --medium: #d69e2e;
    --low: #38a169; --info: #718096;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
  header { background: var(--card); border-bottom: 1px solid var(--border); padding: 16px 24px; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 1.25rem; font-weight: 700; }
  header span { color: var(--muted); font-size: 0.85rem; }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  .grid { display: grid; grid-template-columns: 320px 1fr; gap: 20px; }
  /* サイドバー */
  .sidebar { position: sticky; top: 24px; max-height: calc(100vh - 80px); overflow-y: auto; }
  .scan-list { display: flex; flex-direction: column; gap: 8px; }
  .scan-item { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; cursor: pointer; transition: border-color .15s; }
  .scan-item:hover, .scan-item.active { border-color: var(--accent); }
  .scan-item .scan-id { font-size: 0.75rem; color: var(--muted); font-family: monospace; }
  .scan-item .scan-file { font-size: 0.875rem; font-weight: 600; margin: 4px 0 6px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .scan-item .scan-meta { font-size: 0.75rem; color: var(--muted); }
  .badge-row { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 6px; }
  .badge { border-radius: 4px; padding: 2px 6px; font-size: 0.7rem; font-weight: 700; color: #fff; }
  .badge-C { background: var(--critical); }
  .badge-H { background: var(--high); }
  .badge-M { background: var(--medium); }
  .badge-L { background: var(--low); }
  .badge-I { background: var(--info); }
  /* メインパネル */
  #panel { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 24px; }
  .empty-state { display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 400px; color: var(--muted); gap: 12px; }
  .empty-state .icon { font-size: 3rem; }
  /* スキャン詳細 */
  .detail-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 20px; }
  .detail-title { font-size: 1.1rem; font-weight: 700; }
  .detail-subtitle { color: var(--muted); font-size: 0.85rem; margin-top: 4px; }
  .stats-row { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }
  .stat-card { background: var(--bg); border: 1px solid var(--border); border-radius: 8px; padding: 12px 16px; min-width: 100px; }
  .stat-val { font-size: 1.75rem; font-weight: 800; line-height: 1; }
  .stat-lbl { font-size: 0.7rem; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: .05em; }
  .issues-title { font-size: 0.9rem; font-weight: 600; margin-bottom: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
  .issue-card { border-left: 3px solid var(--border); padding: 12px 14px; margin-bottom: 10px; background: var(--bg); border-radius: 0 6px 6px 0; }
  .issue-card.sev-Critical { border-left-color: var(--critical); }
  .issue-card.sev-High { border-left-color: var(--high); }
  .issue-card.sev-Medium { border-left-color: var(--medium); }
  .issue-card.sev-Low { border-left-color: var(--low); }
  .issue-card.sev-Info { border-left-color: var(--info); }
  .issue-top { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
  .issue-sev { font-size: 0.7rem; font-weight: 700; padding: 2px 6px; border-radius: 4px; color: #fff; }
  .issue-title { font-weight: 600; font-size: 0.9rem; }
  .issue-cat { font-size: 0.75rem; color: var(--muted); margin-left: auto; }
  .issue-desc { font-size: 0.82rem; color: var(--muted); line-height: 1.5; }
  .issue-evidence { font-size: 0.78rem; font-family: monospace; background: var(--card); padding: 6px 8px; border-radius: 4px; margin-top: 6px; white-space: pre-wrap; overflow-x: auto; }
  .filter-bar { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
  .filter-btn { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 4px 10px; font-size: 0.8rem; cursor: pointer; color: var(--text); transition: border-color .15s; }
  .filter-btn:hover, .filter-btn.active { border-color: var(--accent); color: var(--accent); }
  .score-ring { font-size: 0.85rem; }
  .score-val { font-size: 1.4rem; font-weight: 800; }
  /* ローディング */
  .loading { display: flex; align-items: center; gap: 8px; color: var(--muted); }
  .spinner { width: 18px; height: 18px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  /* スクロールバー */
  ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: transparent; } ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
</style>
</head>
<body>
<header>
  <span style="font-size:1.4rem;">🛡️</span>
  <h1>RedTeam Dashboard</h1>
  <span>AI-Red-Teaming-Engine</span>
  <span style="margin-left:auto;font-size:0.8rem;">
    <span id="scan-count">読込中…</span>
  </span>
</header>
<div class="container">
  <div class="grid">
    <div class="sidebar">
      <div class="scan-list" id="scan-list">
        <div class="loading"><div class="spinner"></div>スキャン一覧を読み込み中…</div>
      </div>
    </div>
    <div id="panel">
      <div class="empty-state">
        <div class="icon">🔍</div>
        <div>左のスキャン一覧からレポートを選択してください</div>
      </div>
    </div>
  </div>
</div>

<script>
const SEV_COLOR = {Critical:'#e53e3e',High:'#dd6b20',Medium:'#d69e2e',Low:'#38a169',Info:'#718096'};
let currentFilter = 'ALL';
let currentIssues = [];

async function loadScans() {
  const res = await fetch('/api/scans');
  const scans = await res.json();
  const list = document.getElementById('scan-list');
  document.getElementById('scan-count').textContent = scans.length + ' スキャン';
  if (!scans.length) {
    list.innerHTML = '<div style="color:var(--muted);font-size:.85rem;padding:12px">logs/ にレポートがありません</div>';
    return;
  }
  list.innerHTML = scans.map(s => `
    <div class="scan-item" onclick="loadDetail('${s.scan_id}')" id="item-${s.scan_id}">
      <div class="scan-id">${s.scan_id}</div>
      <div class="scan-file" title="${s.file}">${s.file}</div>
      <div class="scan-meta">${s.mode} · ${s.ts}</div>
      <div class="badge-row">
        ${s.critical?`<span class="badge badge-C">C:${s.critical}</span>`:''}
        ${s.high?`<span class="badge badge-H">H:${s.high}</span>`:''}
        ${s.medium?`<span class="badge badge-M">M:${s.medium}</span>`:''}
        ${s.low?`<span class="badge badge-L">L:${s.low}</span>`:''}
        ${s.info?`<span class="badge badge-I">I:${s.info}</span>`:''}
        ${(!s.critical&&!s.high&&!s.medium&&!s.low&&!s.info)?'<span class="badge badge-I">0件</span>':''}
      </div>
    </div>`).join('');
}

async function loadDetail(scanId) {
  document.querySelectorAll('.scan-item').forEach(el => el.classList.remove('active'));
  const item = document.getElementById('item-'+scanId);
  if(item) item.classList.add('active');

  const panel = document.getElementById('panel');
  panel.innerHTML = '<div class="loading" style="padding:40px"><div class="spinner"></div>読み込み中…</div>';

  const res = await fetch('/api/scans/'+scanId);
  if(!res.ok){ panel.innerHTML='<div class="empty-state"><div class="icon">⚠️</div><div>レポートが見つかりません</div></div>'; return; }
  const d = await res.json();
  currentIssues = d.issues || [];
  currentFilter = 'ALL';
  renderDetail(d);
}

function renderDetail(d) {
  const s = d.summary || {};
  const issues = filterIssues(currentIssues, currentFilter);
  const sevCounts = {Critical:s.critical||0, High:s.high||0, Medium:s.medium||0, Low:s.low||0, Info:s.info||0};
  const panel = document.getElementById('panel');
  panel.innerHTML = `
    <div class="detail-header">
      <div>
        <div class="detail-title">${d.file_path || d.target_file || '不明'}</div>
        <div class="detail-subtitle">${d.audit_mode||''} · ${d.tech_stack||'自動検出'} · scan_id: ${d.scan_id}</div>
      </div>
      <div class="score-ring">スコア<br><span class="score-val" style="color:${riskColor(d.overall_risk||s.overall_risk)}">${d.overall_risk||s.overall_risk||calcRisk(sevCounts)}</span></div>
    </div>
    <div class="stats-row">
      ${Object.entries(sevCounts).map(([k,v])=>`
        <div class="stat-card">
          <div class="stat-val" style="color:${SEV_COLOR[k]}">${v}</div>
          <div class="stat-lbl">${k}</div>
        </div>`).join('')}
      <div class="stat-card">
        <div class="stat-val">${s.total_issues||0}</div>
        <div class="stat-lbl">合計</div>
      </div>
    </div>
    <div class="filter-bar">
      ${['ALL','Critical','High','Medium','Low','Info'].map(f=>`
        <button class="filter-btn${f===currentFilter?' active':''}" onclick="setFilter('${f}')">${f}</button>`).join('')}
    </div>
    <div class="issues-title">${issues.length} 件の問題</div>
    <div id="issues-list">
      ${issues.map(renderIssue).join('') || '<div style="color:var(--muted);font-size:.85rem">該当する問題はありません</div>'}
    </div>`;
}

function renderIssue(issue) {
  const sev = issue.severity || 'Info';
  const color = SEV_COLOR[sev] || '#718096';
  const desc = issue.why_this_matters || issue.description || '';
  const fix = issue.minimal_fix || issue.hardening_suggestion || issue.fix_suggestion || '';
  const lineInfo = (issue.line_start||issue.line_end) ? ` L${issue.line_start||'?'}-${issue.line_end||'?'}` : '';
  const conf = issue.confidence ? ` · 確信度:${issue.confidence}` : '';
  return `<div class="issue-card sev-${sev}">
    <div class="issue-top">
      <span class="issue-sev" style="background:${color}">${sev}</span>
      <span class="issue-title">${esc(issue.title||'')}</span>
      <span class="issue-cat">${esc(issue.category||'')}${lineInfo}${conf}</span>
    </div>
    <div class="issue-desc">${esc(desc)}</div>
    ${issue.evidence?`<div class="issue-evidence">${esc(issue.evidence)}</div>`:''}
    ${fix?`<div class="issue-desc" style="margin-top:6px;color:#a0aec0">💡 ${esc(fix)}</div>`:''}
  </div>`;
}

function filterIssues(issues, filter) {
  if(filter==='ALL') return issues;
  return issues.filter(i=>i.severity===filter);
}

function setFilter(f) {
  currentFilter = f;
  document.querySelectorAll('.filter-btn').forEach(b=>{
    b.classList.toggle('active', b.textContent===f);
  });
  const list = document.getElementById('issues-list');
  const issues = filterIssues(currentIssues, f);
  list.innerHTML = issues.map(renderIssue).join('') ||
    '<div style="color:var(--muted);font-size:.85rem">該当する問題はありません</div>';
  const title = document.querySelector('.issues-title');
  if(title) title.textContent = issues.length + ' 件の問題';
}

function calcRisk(counts) {
  if(counts.Critical>0) return 'Critical';
  if(counts.High>0) return 'High';
  if(counts.Medium>0) return 'Medium';
  if(counts.Low>0) return 'Low';
  return 'Info';
}

function riskColor(risk) {
  return SEV_COLOR[risk] || 'var(--text)';
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

loadScans();
</script>
</body>
</html>"""

# ─── Flask アプリ ──────────────────────────────────────────────────────────────

app = Flask(__name__)
_logs_dir: Path = _DEFAULT_LOGS


def _load_report(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _count_by_severity(report: dict) -> dict[str, int]:
    """サマリーから重大度別カウントを取得（複数の形式に対応）"""
    s = report.get("summary", {})
    # 形式1: summary.by_severity = {"Critical": 4, "High": 5, ...}
    by_sev = s.get("by_severity", {})
    if by_sev:
        return {
            "critical": by_sev.get("Critical", 0) + by_sev.get("critical", 0),
            "high":     by_sev.get("High", 0) + by_sev.get("high", 0),
            "medium":   by_sev.get("Medium", 0) + by_sev.get("medium", 0),
            "low":      by_sev.get("Low", 0) + by_sev.get("low", 0),
            "info":     by_sev.get("Info", 0) + by_sev.get("info", 0),
        }
    # 形式2: summary.critical / summary.high / ...（フラット）
    return {
        "critical": s.get("critical", 0),
        "high":     s.get("high", 0),
        "medium":   s.get("medium", 0),
        "low":      s.get("low", 0),
        "info":     s.get("info", 0),
    }


def _summarize(report: dict, filename: str = "") -> dict:
    """スキャン一覧表示用のサマリーを生成"""
    # ファイル名からタイムスタンプを取得（例: 20260314_190038_xxx_report.json）
    ts = ""
    if filename:
        parts = filename.split("_")
        if len(parts) >= 2 and len(parts[0]) == 8:
            try:
                ts = datetime.strptime(f"{parts[0]}_{parts[1]}", "%Y%m%d_%H%M%S").strftime("%m/%d %H:%M")
            except ValueError:
                pass
    counts = _count_by_severity(report)
    return {
        "scan_id": report.get("scan_id", ""),
        "file": report.get("file_path") or report.get("target_file") or "不明",
        "mode": report.get("audit_mode", "?"),
        "ts": ts or report.get("scan_id", "")[:8],
        **counts,
    }


@app.route("/")
def index():
    return render_template_string(_INDEX_HTML)


@app.route("/api/scans")
def api_scans():
    """logs/*.json を日付降順で返す"""
    reports = []
    for p in sorted(_logs_dir.glob("*.json"), reverse=True):
        data = _load_report(p)
        if data:
            reports.append(_summarize(data, p.name))
    return jsonify(reports)


@app.route("/api/scans/<path:scan_id>")
def api_scan_detail(scan_id: str):
    """特定スキャンの詳細を返す（scan_id フィールドで検索）"""
    for p in sorted(_logs_dir.glob("*.json"), reverse=True):
        data = _load_report(p)
        if data.get("scan_id") == scan_id:
            # issues をフラットリスト形式に整形して返す
            issues = _flatten_issues(data)
            data["issues"] = issues
            return jsonify(data)
    abort(404)


def _flatten_issues(report: dict) -> list[dict]:
    """issuesをフラットなリストに変換（AuditReport形式に対応）"""
    raw = report.get("issues", [])
    if not raw:
        return []
    result = []
    for item in raw:
        if isinstance(item, dict):
            result.append(item)
    return result


@app.route("/api/stats")
def api_stats():
    """全スキャンの集計統計"""
    total_issues = 0
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    scan_count = 0
    for p in _logs_dir.glob("*.json"):
        data = _load_report(p)
        if not data:
            continue
        scan_count += 1
        counts = _count_by_severity(data)
        for sev, cnt in counts.items():
            by_severity[sev] = by_severity.get(sev, 0) + cnt
            total_issues += cnt
    return jsonify({"scan_count": scan_count, "total_issues": total_issues, "by_severity": by_severity})


# ─── エントリポイント ────────────────────────────────────────────────────────

@click.command()
@click.option("--port", default=_DEFAULT_PORT, show_default=True, help="ポート番号")
@click.option(
    "--logs-dir",
    "logs_dir",
    default=str(_DEFAULT_LOGS),
    show_default=True,
    help="logs/ ディレクトリのパス",
)
@click.option("--host", default="127.0.0.1", show_default=True, help="ホスト")
def run(port: int, logs_dir: str, host: str) -> None:
    """RedTeam Dashboard を起動してブラウザで監査レポートを確認する"""
    global _logs_dir
    _logs_dir = Path(logs_dir)
    if not _logs_dir.exists():
        click.echo(f"⚠️  logs ディレクトリが見つかりません: {_logs_dir}", err=True)
        _logs_dir.mkdir(parents=True, exist_ok=True)
        click.echo(f"   作成しました: {_logs_dir}", err=True)

    click.echo(f"\n🛡️  RedTeam Dashboard 起動中...")
    click.echo(f"   URL  : http://{host}:{port}")
    click.echo(f"   logs : {_logs_dir.resolve()}")
    click.echo("   Ctrl+C で停止\n")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    run()
