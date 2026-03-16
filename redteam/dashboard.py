"""
Web UIダッシュボード — logs/ の監査レポートをブラウザで可視化 & カスタムルール管理

起動:
    python3 -m redteam.dashboard           # デフォルト: localhost:7374
    python3 -m redteam.dashboard --port 8080 --logs-dir /path/to/logs
    redteam-dashboard                      # pip install 後
"""
from __future__ import annotations

import json
import re
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

try:
    import yaml as _yaml
except ImportError:
    _yaml = None  # type: ignore[assignment]

# ─── 定数 ────────────────────────────────────────────────────────────────────

_DEFAULT_PORT = 7374
_DEFAULT_LOGS = Path(__file__).parent.parent / "logs"
_DEFAULT_RULES = Path(__file__).parent.parent / ".redteam-rules.yaml"

_SEVERITY_COLOR = {
    "Critical": "#e53e3e",
    "High":     "#dd6b20",
    "Medium":   "#d69e2e",
    "Low":      "#38a169",
    "Info":     "#718096",
}
_VALID_SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]

# ─── 共通 CSS / ヘッダー部品 ─────────────────────────────────────────────────

_COMMON_STYLE = """
  :root {
    --bg: #0f1117; --card: #1a1d27; --border: #2d3148;
    --text: #e2e8f0; --muted: #718096; --accent: #7c3aed;
    --accent2: #5b21b6;
    --critical: #e53e3e; --high: #dd6b20; --medium: #d69e2e;
    --low: #38a169; --info: #718096;
    --success: #38a169; --danger: #e53e3e;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
  header { background: var(--card); border-bottom: 1px solid var(--border); padding: 12px 24px; display: flex; align-items: center; gap: 12px; }
  header h1 { font-size: 1.2rem; font-weight: 700; }
  header .sub { color: var(--muted); font-size: 0.82rem; }
  nav { display: flex; gap: 4px; margin-left: 24px; }
  nav a { color: var(--muted); text-decoration: none; font-size: 0.85rem; padding: 4px 12px; border-radius: 6px; transition: background .15s, color .15s; }
  nav a:hover { background: var(--border); color: var(--text); }
  nav a.active { background: var(--accent); color: #fff; }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  .badge { border-radius: 4px; padding: 2px 6px; font-size: 0.7rem; font-weight: 700; color: #fff; }
  .badge-C { background: var(--critical); } .badge-H { background: var(--high); }
  .badge-M { background: var(--medium); } .badge-L { background: var(--low); } .badge-I { background: var(--info); }
  .loading { display: flex; align-items: center; gap: 8px; color: var(--muted); }
  .spinner { width: 18px; height: 18px; border: 2px solid var(--border); border-top-color: var(--accent); border-radius: 50%; animation: spin .7s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  ::-webkit-scrollbar { width: 6px; } ::-webkit-scrollbar-track { background: transparent; } ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  button { cursor: pointer; border: none; border-radius: 6px; font-size: 0.82rem; padding: 6px 14px; transition: opacity .15s; }
  button:hover { opacity: .85; }
  input, select, textarea { background: var(--bg); border: 1px solid var(--border); border-radius: 6px; color: var(--text); font-size: 0.85rem; padding: 7px 10px; width: 100%; outline: none; font-family: inherit; }
  input:focus, select:focus, textarea:focus { border-color: var(--accent); }
  label { font-size: 0.78rem; color: var(--muted); display: block; margin-bottom: 4px; }
  .form-group { margin-bottom: 12px; }
  .toast { position: fixed; bottom: 24px; right: 24px; padding: 10px 18px; border-radius: 8px; font-size: 0.85rem; font-weight: 600; opacity: 0; pointer-events: none; transition: opacity .3s; z-index: 999; }
  .toast.show { opacity: 1; }
  .toast.ok { background: var(--success); color: #fff; }
  .toast.err { background: var(--danger); color: #fff; }
"""

_NAV_TEMPLATE = """
<header>
  <span style="font-size:1.4rem;">🛡️</span>
  <h1>RedTeam Dashboard</h1>
  <span class="sub">AI-Red-Teaming-Engine</span>
  <nav>
    <a href="/" id="nav-scan">スキャン一覧</a>
    <a href="/rules" id="nav-rules">カスタムルール</a>
  </nav>
  <span style="margin-left:auto;font-size:0.8rem;" id="header-info"></span>
</header>
"""

# ─── スキャン一覧ページ ───────────────────────────────────────────────────────

_INDEX_HTML = """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RedTeam Dashboard</title>
<style>
""" + _COMMON_STYLE + """
  .grid { display: grid; grid-template-columns: 320px 1fr; gap: 20px; }
  .sidebar { position: sticky; top: 24px; max-height: calc(100vh - 80px); overflow-y: auto; }
  .scan-list { display: flex; flex-direction: column; gap: 8px; }
  .scan-item { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 12px 14px; cursor: pointer; transition: border-color .15s; }
  .scan-item:hover, .scan-item.active { border-color: var(--accent); }
  .scan-item .scan-id { font-size: 0.75rem; color: var(--muted); font-family: monospace; }
  .scan-item .scan-file { font-size: 0.875rem; font-weight: 600; margin: 4px 0 6px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .scan-item .scan-meta { font-size: 0.75rem; color: var(--muted); }
  .badge-row { display: flex; gap: 4px; flex-wrap: wrap; margin-top: 6px; }
  #panel { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 24px; }
  .empty-state { display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 400px; color: var(--muted); gap: 12px; }
  .empty-state .icon { font-size: 3rem; }
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
</style>
</head>
<body>
""" + _NAV_TEMPLATE + """
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
document.getElementById('nav-scan').classList.add('active');
const SEV_COLOR = {Critical:'#e53e3e',High:'#dd6b20',Medium:'#d69e2e',Low:'#38a169',Info:'#718096'};
let currentFilter = 'ALL';
let currentIssues = [];

async function loadScans() {
  const res = await fetch('/api/scans');
  const scans = await res.json();
  const list = document.getElementById('scan-list');
  document.getElementById('header-info').textContent = scans.length + ' スキャン';
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

function riskColor(risk) { return ({Critical:'#e53e3e',High:'#dd6b20',Medium:'#d69e2e',Low:'#38a169',Info:'#718096'})[risk] || 'var(--text)'; }
function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

loadScans();
</script>
</body>
</html>"""

# ─── カスタムルール管理ページ ─────────────────────────────────────────────────

_RULES_HTML = """<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>カスタムルール — RedTeam Dashboard</title>
<style>
""" + _COMMON_STYLE + """
  .rules-layout { display: grid; grid-template-columns: 1fr 420px; gap: 20px; align-items: start; }
  /* ルール一覧 */
  .rules-list { display: flex; flex-direction: column; gap: 10px; }
  .rule-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 14px 16px; display: flex; align-items: flex-start; gap: 12px; transition: border-color .15s; }
  .rule-card:hover { border-color: var(--accent); }
  .rule-card.disabled { opacity: .45; }
  .rule-info { flex: 1; min-width: 0; }
  .rule-header { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
  .rule-id { font-family: monospace; font-size: 0.75rem; color: var(--muted); }
  .rule-name { font-weight: 600; font-size: 0.9rem; }
  .rule-pattern { font-family: monospace; font-size: 0.78rem; color: var(--muted); background: var(--bg); padding: 3px 7px; border-radius: 4px; margin-bottom: 4px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 400px; }
  .rule-meta { font-size: 0.75rem; color: var(--muted); }
  .rule-actions { display: flex; gap: 6px; flex-shrink: 0; }
  .btn-edit { background: var(--accent); color: #fff; }
  .btn-delete { background: transparent; border: 1px solid var(--border); color: var(--muted); }
  .btn-delete:hover { border-color: var(--danger); color: var(--danger); }
  .btn-toggle { background: transparent; border: 1px solid var(--border); color: var(--muted); font-size: 0.75rem; }
  /* 右パネル */
  .right-panel { position: sticky; top: 24px; display: flex; flex-direction: column; gap: 16px; }
  .panel-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }
  .panel-title { font-size: 0.9rem; font-weight: 700; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
  .btn-primary { background: var(--accent); color: #fff; padding: 8px 18px; font-size: 0.85rem; }
  .btn-secondary { background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: 8px 14px; }
  .btn-danger { background: var(--danger); color: #fff; padding: 8px 14px; }
  .btn-row { display: flex; gap: 8px; margin-top: 14px; }
  /* テスト結果 */
  .test-result { margin-top: 10px; }
  .hit-line { background: var(--bg); border-left: 3px solid var(--accent); padding: 4px 8px; font-family: monospace; font-size: 0.78rem; margin-bottom: 4px; border-radius: 0 4px 4px 0; }
  .hit-line .lineno { color: var(--muted); margin-right: 8px; }
  .hit-line .match-text { color: #f6e05e; }
  .no-hit { color: var(--muted); font-size: 0.82rem; }
  /* 空状態 */
  .empty-rules { text-align: center; padding: 48px 24px; color: var(--muted); }
  .empty-rules .icon { font-size: 2.5rem; margin-bottom: 12px; }
  /* ページ上部 */
  .page-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
  .page-title { font-size: 1.1rem; font-weight: 700; }
  .page-sub { font-size: 0.82rem; color: var(--muted); margin-top: 2px; }
  .sev-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; }
</style>
</head>
<body>
""" + _NAV_TEMPLATE + """
<div class="container">
  <div class="page-header">
    <div>
      <div class="page-title">カスタムルール管理</div>
      <div class="page-sub" id="rules-path">ファイル: 読込中…</div>
    </div>
    <button class="btn-primary" onclick="startAdd()">＋ 新規ルール追加</button>
  </div>
  <div class="rules-layout">
    <div>
      <div class="rules-list" id="rules-list">
        <div class="loading"><div class="spinner"></div>読み込み中…</div>
      </div>
    </div>
    <div class="right-panel">
      <!-- フォームパネル -->
      <div class="panel-card" id="form-panel" style="display:none">
        <div class="panel-title" id="form-title">✏️ ルール追加</div>
        <div class="form-group">
          <label>ID <span style="color:var(--muted)">(例: CUS-001)</span></label>
          <input id="f-id" placeholder="CUS-001">
        </div>
        <div class="form-group">
          <label>名前 *</label>
          <input id="f-name" placeholder="危険な eval 使用">
        </div>
        <div class="form-group">
          <label>パターン (正規表現) *</label>
          <input id="f-pattern" placeholder="eval\\s*\\(" oninput="liveTest()">
        </div>
        <div class="form-group">
          <label>重大度</label>
          <select id="f-severity">
            <option>Critical</option><option>High</option>
            <option selected>Medium</option><option>Low</option><option>Info</option>
          </select>
        </div>
        <div class="form-group">
          <label>カテゴリ</label>
          <input id="f-category" placeholder="Code Injection">
        </div>
        <div class="form-group">
          <label>メッセージ</label>
          <input id="f-message" placeholder="eval() はコードインジェクションのリスクがあります">
        </div>
        <div class="form-group">
          <label>ファイルGlob <span style="color:var(--muted)">(省略可: 例 *.py)</span></label>
          <input id="f-glob" placeholder="*.py">
        </div>
        <div class="form-group" style="display:flex;align-items:center;gap:8px">
          <input type="checkbox" id="f-enabled" checked style="width:auto">
          <label for="f-enabled" style="margin:0;color:var(--text)">有効</label>
        </div>
        <div class="btn-row">
          <button class="btn-primary" onclick="saveRule()">保存</button>
          <button class="btn-secondary" onclick="cancelForm()">キャンセル</button>
          <button class="btn-danger" id="btn-delete-form" style="display:none;margin-left:auto" onclick="deleteCurrentRule()">削除</button>
        </div>
      </div>

      <!-- パターンテストパネル -->
      <div class="panel-card">
        <div class="panel-title">🧪 パターンテスト</div>
        <div class="form-group">
          <label>テストするパターン (正規表現)</label>
          <input id="t-pattern" placeholder="eval\\s*\\(" oninput="runTest()">
        </div>
        <div class="form-group">
          <label>テスト対象コード</label>
          <textarea id="t-code" rows="8" placeholder="ここにコードを貼り付けてテスト" oninput="runTest()" style="font-family:monospace;font-size:0.8rem;resize:vertical"></textarea>
        </div>
        <div class="test-result" id="test-result"></div>
      </div>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
document.getElementById('nav-rules').classList.add('active');

const SEV_COLOR = {Critical:'#e53e3e',High:'#dd6b20',Medium:'#d69e2e',Low:'#38a169',Info:'#718096'};
let rules = [];
let editingId = null;

function esc(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

function toast(msg, type='ok') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = 'toast ' + type + ' show';
  setTimeout(() => el.classList.remove('show'), 2500);
}

async function loadRules() {
  const res = await fetch('/api/rules');
  const data = await res.json();
  rules = data.rules || [];
  document.getElementById('rules-path').textContent = 'ファイル: ' + (data.file || '未設定');
  document.getElementById('header-info').textContent = rules.length + ' ルール';
  renderRules();
}

function renderRules() {
  const list = document.getElementById('rules-list');
  if (!rules.length) {
    list.innerHTML = '<div class="empty-rules"><div class="icon">📋</div><div>ルールがありません</div><div style="font-size:.82rem;margin-top:8px">「新規ルール追加」から追加してください</div></div>';
    return;
  }
  list.innerHTML = rules.map(r => {
    const color = SEV_COLOR[r.severity] || '#718096';
    const disabled = r.enabled === false;
    return `<div class="rule-card${disabled?' disabled':''}">
      <div class="rule-info">
        <div class="rule-header">
          <span class="badge" style="background:${color}">${r.severity}</span>
          <span class="rule-id">${esc(r.id||'')}</span>
          <span class="rule-name">${esc(r.name||'')}</span>
          ${disabled?'<span style="font-size:.7rem;color:var(--muted);margin-left:auto">無効</span>':''}
        </div>
        <div class="rule-pattern" title="${esc(r.pattern||'')}">${esc(r.pattern||'')}</div>
        <div class="rule-meta">${esc(r.category||'')}${r.file_glob?' · '+esc(r.file_glob):''} · ${esc(r.message||'')}</div>
      </div>
      <div class="rule-actions">
        <button class="btn-edit" onclick="startEdit('${esc(r.id||'')}')">編集</button>
        <button class="btn-delete" onclick="deleteRule('${esc(r.id||'')}')">削除</button>
      </div>
    </div>`;
  }).join('');
}

function startAdd() {
  editingId = null;
  document.getElementById('form-title').textContent = '✏️ ルール追加';
  document.getElementById('f-id').value = 'CUS-' + String(rules.length + 1).padStart(3,'0');
  document.getElementById('f-name').value = '';
  document.getElementById('f-pattern').value = '';
  document.getElementById('f-severity').value = 'Medium';
  document.getElementById('f-category').value = '';
  document.getElementById('f-message').value = '';
  document.getElementById('f-glob').value = '';
  document.getElementById('f-enabled').checked = true;
  document.getElementById('btn-delete-form').style.display = 'none';
  document.getElementById('form-panel').style.display = 'block';
  document.getElementById('f-name').focus();
}

function startEdit(ruleId) {
  const r = rules.find(x => x.id === ruleId);
  if (!r) return;
  editingId = ruleId;
  document.getElementById('form-title').textContent = '✏️ ルール編集';
  document.getElementById('f-id').value = r.id || '';
  document.getElementById('f-name').value = r.name || '';
  document.getElementById('f-pattern').value = r.pattern || '';
  document.getElementById('f-severity').value = r.severity || 'Medium';
  document.getElementById('f-category').value = r.category || '';
  document.getElementById('f-message').value = r.message || '';
  document.getElementById('f-glob').value = r.file_glob || '';
  document.getElementById('f-enabled').checked = r.enabled !== false;
  document.getElementById('btn-delete-form').style.display = 'block';
  document.getElementById('form-panel').style.display = 'block';
  // テストパネルにパターンをコピー
  document.getElementById('t-pattern').value = r.pattern || '';
  runTest();
}

function cancelForm() {
  document.getElementById('form-panel').style.display = 'none';
  editingId = null;
}

async function saveRule() {
  const rule = {
    id: document.getElementById('f-id').value.trim(),
    name: document.getElementById('f-name').value.trim(),
    pattern: document.getElementById('f-pattern').value.trim(),
    severity: document.getElementById('f-severity').value,
    category: document.getElementById('f-category').value.trim(),
    message: document.getElementById('f-message').value.trim(),
    file_glob: document.getElementById('f-glob').value.trim() || null,
    enabled: document.getElementById('f-enabled').checked,
  };
  if (!rule.name || !rule.pattern) { toast('名前とパターンは必須です', 'err'); return; }

  try { new RegExp(rule.pattern); } catch(e) { toast('正規表現が無効です: ' + e.message, 'err'); return; }

  const res = await fetch('/api/rules', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({rule, editing_id: editingId}),
  });
  const data = await res.json();
  if (!res.ok) { toast(data.error || '保存に失敗しました', 'err'); return; }
  toast('✅ 保存しました');
  cancelForm();
  loadRules();
}

async function deleteRule(ruleId) {
  if (!confirm(`ルール "${ruleId}" を削除しますか？`)) return;
  const res = await fetch('/api/rules/' + encodeURIComponent(ruleId), {method: 'DELETE'});
  if (!res.ok) { toast('削除に失敗しました', 'err'); return; }
  toast('🗑️ 削除しました');
  loadRules();
}

function deleteCurrentRule() {
  if (editingId) { cancelForm(); deleteRule(editingId); }
}

// ─── パターンテスト ───────────────────────────────────────────────────────────

function liveTest() {
  // フォームのパターンをテストパネルにも反映
  document.getElementById('t-pattern').value = document.getElementById('f-pattern').value;
  runTest();
}

function runTest() {
  const patStr = document.getElementById('t-pattern').value;
  const code = document.getElementById('t-code').value;
  const resultEl = document.getElementById('test-result');

  if (!patStr) { resultEl.innerHTML = ''; return; }

  let pat;
  try { pat = new RegExp(patStr, 'g'); }
  catch(e) { resultEl.innerHTML = `<div style="color:var(--danger);font-size:.8rem">❌ 正規表現エラー: ${esc(e.message)}</div>`; return; }

  if (!code) { resultEl.innerHTML = '<div class="no-hit">テスト対象コードを入力してください</div>'; return; }

  const lines = code.split('\\n');
  const hits = [];
  lines.forEach((line, i) => {
    pat.lastIndex = 0;
    const m = pat.exec(line);
    if (m) hits.push({lineno: i+1, line, match: m[0]});
  });

  if (!hits.length) {
    resultEl.innerHTML = '<div class="no-hit">マッチなし</div>';
    return;
  }

  resultEl.innerHTML = `<div style="font-size:.78rem;color:var(--muted);margin-bottom:6px">${hits.length} 件マッチ</div>` +
    hits.map(h => {
      const highlighted = esc(h.line).replace(
        esc(h.match),
        `<span class="match-text">${esc(h.match)}</span>`
      );
      return `<div class="hit-line"><span class="lineno">L${h.lineno}</span>${highlighted}</div>`;
    }).join('');
}

loadRules();
</script>
</body>
</html>"""

# ─── Flask アプリ ──────────────────────────────────────────────────────────────

app = Flask(__name__)
_logs_dir: Path = _DEFAULT_LOGS
_rules_file: Path = _DEFAULT_RULES


def _load_report(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _count_by_severity(report: dict) -> dict[str, int]:
    s = report.get("summary", {})
    by_sev = s.get("by_severity", {})
    if by_sev:
        return {
            "critical": by_sev.get("Critical", 0) + by_sev.get("critical", 0),
            "high":     by_sev.get("High", 0) + by_sev.get("high", 0),
            "medium":   by_sev.get("Medium", 0) + by_sev.get("medium", 0),
            "low":      by_sev.get("Low", 0) + by_sev.get("low", 0),
            "info":     by_sev.get("Info", 0) + by_sev.get("info", 0),
        }
    return {
        "critical": s.get("critical", 0),
        "high":     s.get("high", 0),
        "medium":   s.get("medium", 0),
        "low":      s.get("low", 0),
        "info":     s.get("info", 0),
    }


def _summarize(report: dict, filename: str = "") -> dict:
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


# ─── ルール YAML ヘルパー ─────────────────────────────────────────────────────

def _load_rules_yaml() -> dict:
    if _yaml is None:
        return {"rules": []}
    if not _rules_file.exists():
        return {"rules": []}
    try:
        data = _yaml.safe_load(_rules_file.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {"rules": []}
    except Exception:
        return {"rules": []}


def _save_rules_yaml(data: dict) -> None:
    if _yaml is None:
        raise RuntimeError("PyYAML が必要です: pip install pyyaml")
    _rules_file.parent.mkdir(parents=True, exist_ok=True)
    _rules_file.write_text(
        _yaml.dump(data, allow_unicode=True, default_flow_style=False, sort_keys=False),
        encoding="utf-8",
    )


def _rule_to_dict(r: dict) -> dict:
    """不要なキーを除いて保存用 dict を作る"""
    d: dict = {}
    d["id"] = r.get("id", "")
    d["name"] = r.get("name", "")
    d["pattern"] = r.get("pattern", "")
    d["severity"] = r.get("severity", "Medium")
    d["category"] = r.get("category", "Custom")
    d["message"] = r.get("message", "")
    if r.get("file_glob"):
        d["file_glob"] = r["file_glob"]
    d["enabled"] = r.get("enabled", True)
    return d


# ─── スキャン関連ルート ────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(_INDEX_HTML)


@app.route("/api/scans")
def api_scans():
    reports = []
    for p in sorted(_logs_dir.glob("*.json"), reverse=True):
        data = _load_report(p)
        if data:
            reports.append(_summarize(data, p.name))
    return jsonify(reports)


@app.route("/api/scans/<path:scan_id>")
def api_scan_detail(scan_id: str):
    for p in sorted(_logs_dir.glob("*.json"), reverse=True):
        data = _load_report(p)
        if data.get("scan_id") == scan_id:
            data["issues"] = _flatten_issues(data)
            return jsonify(data)
    abort(404)


def _flatten_issues(report: dict) -> list[dict]:
    raw = report.get("issues", [])
    return [item for item in raw if isinstance(item, dict)]


@app.route("/api/stats")
def api_stats():
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


# ─── カスタムルール関連ルート ─────────────────────────────────────────────────

@app.route("/rules")
def rules_page():
    return render_template_string(_RULES_HTML)


@app.route("/api/rules", methods=["GET"])
def api_rules_list():
    """現在のカスタムルール一覧を返す"""
    data = _load_rules_yaml()
    return jsonify({
        "rules": data.get("rules") or [],
        "file": str(_rules_file),
    })


@app.route("/api/rules", methods=["POST"])
def api_rules_save():
    """ルールを追加または更新する"""
    body = request.get_json(silent=True) or {}
    rule = body.get("rule", {})
    editing_id: str | None = body.get("editing_id")

    if not rule.get("name") or not rule.get("pattern"):
        return jsonify({"error": "name と pattern は必須です"}), 400

    try:
        re.compile(rule["pattern"])
    except re.error as e:
        return jsonify({"error": f"無効な正規表現: {e}"}), 400

    if rule.get("severity") not in _VALID_SEVERITIES:
        rule["severity"] = "Medium"

    data = _load_rules_yaml()
    rules: list[dict] = data.get("rules") or []

    if editing_id:
        # 既存ルールを更新
        idx = next((i for i, r in enumerate(rules) if r.get("id") == editing_id), None)
        if idx is not None:
            rules[idx] = _rule_to_dict(rule)
        else:
            rules.append(_rule_to_dict(rule))
    else:
        # ID 重複チェック
        if any(r.get("id") == rule.get("id") for r in rules):
            return jsonify({"error": f"ID '{rule['id']}' は既に存在します"}), 409
        rules.append(_rule_to_dict(rule))

    data["rules"] = rules
    try:
        _save_rules_yaml(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"ok": True, "rule_id": rule.get("id")})


@app.route("/api/rules/<rule_id>", methods=["DELETE"])
def api_rules_delete(rule_id: str):
    """ルールを削除する"""
    data = _load_rules_yaml()
    rules: list[dict] = data.get("rules") or []
    new_rules = [r for r in rules if r.get("id") != rule_id]
    if len(new_rules) == len(rules):
        return jsonify({"error": "ルールが見つかりません"}), 404
    data["rules"] = new_rules
    try:
        _save_rules_yaml(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"ok": True})


@app.route("/api/rules/test", methods=["POST"])
def api_rules_test():
    """パターンをコードテキストに適用してヒット行を返す（サーバーサイド版）"""
    body = request.get_json(silent=True) or {}
    pattern_str = body.get("pattern", "")
    code = body.get("code", "")

    if not pattern_str:
        return jsonify({"error": "pattern は必須です"}), 400

    try:
        pat = re.compile(pattern_str)
    except re.error as e:
        return jsonify({"error": f"無効な正規表現: {e}"}), 400

    hits = []
    for lineno, line in enumerate(code.splitlines(), 1):
        m = pat.search(line)
        if m:
            hits.append({"lineno": lineno, "line": line.strip(), "match": m.group(0)})

    return jsonify({"hits": hits, "count": len(hits)})


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
@click.option(
    "--rules-file",
    "rules_file",
    default=str(_DEFAULT_RULES),
    show_default=True,
    help="カスタムルール YAML ファイルのパス",
)
@click.option("--host", default="127.0.0.1", show_default=True, help="ホスト")
def run(port: int, logs_dir: str, rules_file: str, host: str) -> None:
    """RedTeam Dashboard を起動してブラウザで監査レポートを確認する"""
    global _logs_dir, _rules_file
    _logs_dir = Path(logs_dir)
    _rules_file = Path(rules_file)

    if not _logs_dir.exists():
        click.echo(f"⚠️  logs ディレクトリが見つかりません: {_logs_dir}", err=True)
        _logs_dir.mkdir(parents=True, exist_ok=True)
        click.echo(f"   作成しました: {_logs_dir}", err=True)

    click.echo(f"\n🛡️  RedTeam Dashboard 起動中...")
    click.echo(f"   URL    : http://{host}:{port}")
    click.echo(f"   logs   : {_logs_dir.resolve()}")
    click.echo(f"   rules  : {_rules_file.resolve()}")
    click.echo("   Ctrl+C で停止\n")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    run()
