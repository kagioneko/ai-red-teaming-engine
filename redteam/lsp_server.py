"""
AI Red Teaming Engine — LSP サーバー

対応エディタ: VS Code / Cursor / Neovim / Zed / Emacs など LSP 対応エディタすべて

起動:
    redteam-lsp          # pip install 後（stdio モード）
    python3 -m redteam.lsp_server

エディタ側の設定例:
    Cursor / VS Code:  settings.json に languageServer 設定を追加
    Neovim:            nvim-lspconfig でカスタムサーバーとして登録
    Zed:               settings.json の lsp セクションに追加
"""
from __future__ import annotations

import asyncio
import logging
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import unquote, urlparse

from lsprotocol import types
from pygls.lsp.server import LanguageServer

# ─── ログ設定 ─────────────────────────────────────────────────────────────────

logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="[redteam-lsp] %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# ─── 定数 ────────────────────────────────────────────────────────────────────

SERVER_NAME = "redteam-lsp"
SERVER_VERSION = "0.1.0"

_SUPPORTED_LANGUAGES = {"python", "javascript", "typescript", "go", "java", "ruby"}
_SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".go", ".java", ".rb"}

# LSP DiagnosticSeverity マッピング
_SEV_MAP: dict[str, types.DiagnosticSeverity] = {
    "Critical": types.DiagnosticSeverity.Error,
    "High":     types.DiagnosticSeverity.Error,
    "Medium":   types.DiagnosticSeverity.Warning,
    "Low":      types.DiagnosticSeverity.Information,
    "Info":     types.DiagnosticSeverity.Hint,
}

# ─── サーバー初期化 ────────────────────────────────────────────────────────────

server = LanguageServer(SERVER_NAME, SERVER_VERSION)

# スキャン中ファイルを追跡（多重実行防止）
_scanning: set[str] = set()


# ─── ユーティリティ ────────────────────────────────────────────────────────────

def _uri_to_path(uri: str) -> Path:
    """LSP URI (file:///path/to/file.py) をローカルパスに変換"""
    parsed = urlparse(uri)
    return Path(unquote(parsed.path))


def _find_engine() -> str | None:
    """engine.py または redteam-scan コマンドを探す"""
    # 1. PATH 上の redteam-scan コマンド
    result = subprocess.run(["which", "redteam-scan"], capture_output=True, text=True)
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()

    # 2. このファイルから相対的に engine.py を探す
    here = Path(__file__).parent.parent
    candidate = here / "engine.py"
    if candidate.exists():
        return str(candidate)

    return None


def _get_config(ls: LanguageServer) -> dict:
    """LSP workspace configuration から設定を取得（デフォルト値付き）"""
    # pygls では設定取得が非同期なので、初回は固定デフォルト値を使う
    return {
        "mode": "deep",
        "min_severity": "Medium",
        "timeout": 120,
    }


# ─── スキャン実行 ──────────────────────────────────────────────────────────────

async def _scan_and_publish(ls: LanguageServer, uri: str) -> None:
    """ファイルをスキャンして診断結果をエディタに送信"""
    if uri in _scanning:
        log.info("スキャン中のためスキップ: %s", uri)
        return

    file_path = _uri_to_path(uri)

    if not file_path.exists():
        log.warning("ファイルが見つかりません: %s", file_path)
        return

    if file_path.suffix not in _SUPPORTED_EXTENSIONS:
        return

    engine = _find_engine()
    if not engine:
        log.error("engine.py / redteam-scan が見つかりません")
        ls.show_message(
            "RedTeam LSP: engine.py が見つかりません。pip install ai-red-teaming-engine を実行してください。",
            types.MessageType.Error,
        )
        return

    _scanning.add(uri)
    log.info("スキャン開始: %s", file_path.name)

    try:
        cfg = _get_config(ls)
        diagnostics = await _run_engine(engine, str(file_path), cfg)
        ls.publish_diagnostics(uri, diagnostics)
        log.info("診断完了: %d 件 → %s", len(diagnostics), file_path.name)
    except Exception as e:
        log.error("スキャンエラー: %s", e)
        ls.show_message(f"RedTeam LSP スキャンエラー: {e}", types.MessageType.Warning)
        ls.publish_diagnostics(uri, [])
    finally:
        _scanning.discard(uri)


async def _run_engine(engine_path: str, file_path: str, cfg: dict) -> list[types.Diagnostic]:
    """engine.py を非同期サブプロセスとして実行し、診断リストを返す"""
    import json

    # engine.py の場合は python3 経由、redteam-scan の場合は直接実行
    if engine_path.endswith(".py"):
        cmd = [sys.executable, engine_path, "--file", file_path,
               "--mode", cfg["mode"], "--format", "json", "--no-save-log"]
    else:
        cmd = [engine_path, "--file", file_path,
               "--mode", cfg["mode"], "--format", "json", "--no-save-log"]

    log.info("実行: %s", " ".join(cmd))

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=float(cfg["timeout"]),
        )
    except asyncio.TimeoutError:
        proc.kill()
        raise TimeoutError(f"スキャンタイムアウト ({cfg['timeout']}秒)")

    if stderr:
        log.debug("stderr: %s", stderr.decode(errors="replace")[:500])

    raw = stdout.decode(errors="replace")

    # JSON 部分を抜き出す
    import re
    m = re.search(r"\{[\s\S]*\}", raw)
    if not m:
        log.warning("JSON 出力が見つかりません。出力:\n%s", raw[:300])
        return []

    try:
        report = json.loads(m.group(0))
    except json.JSONDecodeError as e:
        log.error("JSON パースエラー: %s", e)
        return []

    return _report_to_diagnostics(report, cfg["min_severity"])


def _report_to_diagnostics(report: dict, min_severity: str) -> list[types.Diagnostic]:
    """RedTeam レポートを LSP Diagnostic リストに変換"""
    _sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    min_order = _sev_order.get(min_severity, 2)

    diagnostics: list[types.Diagnostic] = []
    issues: list[dict] = report.get("issues") or []

    for issue in issues:
        sev = issue.get("severity", "Info")
        if _sev_order.get(sev, 99) > min_order:
            continue

        line_start = max(0, int(issue.get("line_start") or 1) - 1)
        line_end = max(line_start, int(issue.get("line_end") or issue.get("line_start") or 1) - 1)

        title = issue.get("title", "(no title)")
        desc = issue.get("why_this_matters") or issue.get("description") or ""
        fix = (
            issue.get("minimal_fix")
            or issue.get("hardening_suggestion")
            or issue.get("fix_suggestion")
            or ""
        )

        message_parts = [f"[RedTeam/{sev}] {title}"]
        if desc:
            message_parts.append(desc)
        if fix:
            message_parts.append(f"💡 {fix}")

        diag = types.Diagnostic(
            range=types.Range(
                start=types.Position(line=line_start, character=0),
                end=types.Position(line=line_end, character=10000),
            ),
            message="\n".join(message_parts),
            severity=_SEV_MAP.get(sev, types.DiagnosticSeverity.Information),
            source="AI RedTeam",
            code=issue.get("category", sev),
        )
        diagnostics.append(diag)

    return diagnostics


# ─── LSP イベントハンドラ ──────────────────────────────────────────────────────

@server.feature(types.TEXT_DOCUMENT_DID_OPEN)
def did_open(ls: LanguageServer, params: types.DidOpenTextDocumentParams) -> None:
    """ファイルを開いた時にスキャン"""
    uri = params.text_document.uri
    log.info("didOpen: %s", uri)
    asyncio.ensure_future(_scan_and_publish(ls, uri))


@server.feature(types.TEXT_DOCUMENT_DID_SAVE)
def did_save(ls: LanguageServer, params: types.DidSaveTextDocumentParams) -> None:
    """ファイル保存時にスキャン"""
    uri = params.text_document.uri
    log.info("didSave: %s", uri)
    asyncio.ensure_future(_scan_and_publish(ls, uri))


@server.feature(types.TEXT_DOCUMENT_DID_CLOSE)
def did_close(ls: LanguageServer, params: types.DidCloseTextDocumentParams) -> None:
    """ファイルを閉じた時に診断結果をクリア"""
    uri = params.text_document.uri
    ls.publish_diagnostics(uri, [])
    log.info("didClose: クリア %s", uri)


# カスタムコマンド: エディタのコマンドパレットから手動スキャン
@server.command("redteam/scanFile")
async def scan_file_command(ls: LanguageServer, params: list) -> dict:
    """手動スキャンコマンド (redteam/scanFile)"""
    if not params:
        return {"error": "uri が必要です"}
    uri = params[0] if isinstance(params[0], str) else params[0].get("uri", "")
    await _scan_and_publish(ls, uri)
    return {"ok": True}


# ─── エントリポイント ────────────────────────────────────────────────────────

def main() -> None:
    """LSP サーバーをstdio モードで起動"""
    log.info("%s %s 起動", SERVER_NAME, SERVER_VERSION)
    server.start_io()


if __name__ == "__main__":
    main()
