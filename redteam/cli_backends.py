"""
CLI バックエンド — API キー不要でCLIツールをLLMとして使う

対応バックエンド:
  claude   → claude -p "..." （Claude Code CLI、認証済み）
  gemini   → gemini -p "..." （Gemini CLI、認証済み）
  codex    → codex exec "..." （OpenAI Codex CLI）
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from abc import ABC, abstractmethod

_TIMEOUT = 180  # 秒
_MAX_RETRIES = 2


class CLIBackendBase(ABC):
    """CLIツールをLLMとして使う基底クラス"""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def _run(self, prompt: str) -> str: ...

    def query(self, system: str, user: str) -> str:
        """system + user を結合してCLIに渡す"""
        combined = f"{system}\n\n---\n\n{user}"
        for attempt in range(_MAX_RETRIES + 1):
            try:
                return self._run(combined)
            except subprocess.TimeoutExpired:
                if attempt < _MAX_RETRIES:
                    time.sleep(2)
                    continue
                raise RuntimeError(f"{self.name} CLI がタイムアウトしました")
            except Exception as e:
                if attempt < _MAX_RETRIES:
                    time.sleep(2)
                    continue
                raise RuntimeError(f"{self.name} CLI エラー: {e}") from e
        return ""

    def query_json(self, system: str, user: str) -> str:
        """JSON出力を要求して返す（パースは呼び出し元が行う）"""
        json_user = (
            user
            + "\n\n**重要**: 出力はJSONのみとしてください。"
            "マークダウンコードブロック（```）を使わず、純粋なJSONのみを出力してください。"
        )
        return self.query(system, json_user)

    def available(self) -> bool:
        return shutil.which(self.name) is not None


class ClaudeCodeBackend(CLIBackendBase):
    """
    Claude Code CLI バックエンド。
    `claude -p "..."` で非インタラクティブ実行。
    API キー不要（Claude Code の認証を使う）。
    """

    @property
    def name(self) -> str:
        return "claude"

    def _run(self, prompt: str) -> str:
        result = subprocess.run(
            ["claude", "-p", prompt],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
        if result.returncode != 0 and result.stderr:
            # stderrがあっても部分結果がstdoutにある場合は続行
            pass
        return result.stdout.strip()


class GeminiBackend(CLIBackendBase):
    """
    Gemini CLI バックエンド。
    `gemini -p "..."` で非インタラクティブ実行。
    """

    @property
    def name(self) -> str:
        return "gemini"

    def _run(self, prompt: str) -> str:
        result = subprocess.run(
            ["gemini", "-p", prompt],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
        return result.stdout.strip()


class CodexBackend(CLIBackendBase):
    """
    OpenAI Codex CLI バックエンド。
    `codex exec "..."` で実行。
    """

    @property
    def name(self) -> str:
        return "codex"

    def _run(self, prompt: str) -> str:
        result = subprocess.run(
            ["codex", "exec", prompt],
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
        )
        return result.stdout.strip()


# バックエンド名 → クラスのマッピング
_BACKENDS: dict[str, type[CLIBackendBase]] = {
    "claude": ClaudeCodeBackend,
    "gemini": GeminiBackend,
    "codex": CodexBackend,
}


def get_cli_backend(name: str) -> CLIBackendBase:
    """バックエンド名からインスタンスを取得"""
    if name not in _BACKENDS:
        raise ValueError(
            f"未知のバックエンド: {name!r}。"
            f"使用可能: {list(_BACKENDS.keys())}"
        )
    backend = _BACKENDS[name]()
    if not backend.available():
        raise RuntimeError(
            f"{name} コマンドが見つかりません。インストールまたはPATHを確認してください。"
        )
    return backend


def list_available_backends() -> list[str]:
    """現在の環境で使用可能なバックエンドを返す"""
    return [
        name
        for name, cls in _BACKENDS.items()
        if cls().available()
    ]
