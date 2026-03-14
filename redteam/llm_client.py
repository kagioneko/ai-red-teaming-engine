"""
LLMクライアント — API または CLI バックエンドを統一インターフェースで使う

バックエンド選択:
  api    → Anthropic SDK（ANTHROPIC_API_KEY 必要）
  claude → Claude Code CLI（claude コマンド、認証済みなら API キー不要）
  gemini → Gemini CLI（gemini コマンド）
  codex  → Codex CLI（codex コマンド）
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from .config import DEFAULT_MODEL

T = TypeVar("T", bound=BaseModel)

_MAX_RETRIES = 2
_RETRY_DELAY = 2.0


class LLMClient:
    """
    統一LLMクライアント。

    backend引数でバックエンドを選択:
      "api"    → Anthropic SDK（デフォルト）
      "claude" → Claude Code CLI
      "gemini" → Gemini CLI
      "codex"  → Codex CLI
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        max_tokens: int = 8192,
        backend: str = "api",
        system_override: str | None = None,
    ):
        self.model = model
        self.max_tokens = max_tokens
        self.backend_name = backend
        self._backend = _create_backend(backend, model, max_tokens)
        self._system_override = system_override

    def call(self, user_prompt: str) -> str:
        """system_override が設定されている場合はそれを使用する簡易呼び出し"""
        system = self._system_override or ""
        return self._backend.query(system, user_prompt)

    def query(self, system: str, user: str) -> str:
        return self._backend.query(system, user)

    def query_json(self, system: str, user: str, schema: type[T]) -> T:
        """
        JSON出力を要求してPydanticモデルとしてパース。
        パース失敗時は最大2回リトライする。
        """
        json_system = system + (
            "\n\n出力は必ずJSONのみとし、マークダウンのコードブロックは使わないこと。"
            " 余分なテキストを付加しないこと。"
        )

        last_error: Exception | None = None
        current_user = user

        for attempt in range(_MAX_RETRIES + 1):
            raw = self._backend.query(json_system, current_user)
            try:
                cleaned = _extract_json(raw)
                data = json.loads(cleaned)
                return schema.model_validate(data)
            except (json.JSONDecodeError, ValidationError) as e:
                last_error = e
                if attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_DELAY)
                    current_user = (
                        f"前回の出力をJSON修正してください。エラー: {e}\n\n"
                        f"期待するスキーマ:\n{schema.model_json_schema()}"
                    )

        raise ValueError(f"JSON出力パース失敗 [{self.backend_name}]: {last_error}")


# ─── バックエンド実装 ──────────────────────────────────────────────────────────

class _BackendBase:
    def query(self, system: str, user: str) -> str:
        raise NotImplementedError


class _AnthropicAPIBackend(_BackendBase):
    """Anthropic SDK バックエンド"""

    def __init__(self, model: str, max_tokens: int):
        import anthropic
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise EnvironmentError(
                "ANTHROPIC_API_KEY が設定されていません。\n"
                "  - export ANTHROPIC_API_KEY=sk-ant-... を実行するか\n"
                "  - --backend claude/gemini/codex でAPIキー不要のCLIバックエンドを使用してください"
            )
        import anthropic as _anthropic
        self._client = _anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.max_tokens = max_tokens

    def query(self, system: str, user: str) -> str:
        import anthropic
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = self._client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    system=system,
                    messages=[{"role": "user", "content": user}],
                )
                return response.content[0].text
            except anthropic.RateLimitError:
                if attempt < _MAX_RETRIES:
                    time.sleep(_RETRY_DELAY * (attempt + 1))
                    continue
                raise
            except anthropic.APIError as e:
                raise RuntimeError(f"Claude API エラー: {e}") from e
        return ""


class _CLIBackend(_BackendBase):
    """CLI バックエンド共通基底"""

    def __init__(self, cmd: list[str], name: str):
        import shutil
        if not shutil.which(cmd[0]):
            raise RuntimeError(
                f"{name} コマンドが見つかりません。"
                f" PATH を確認してください: {cmd[0]}"
            )
        self._cmd = cmd
        self._name = name

    def query(self, system: str, user: str) -> str:
        import subprocess
        combined = f"{system}\n\n---\n\n{user}"
        for attempt in range(_MAX_RETRIES + 1):
            try:
                result = subprocess.run(
                    self._cmd + [combined],
                    capture_output=True,
                    text=True,
                    timeout=180,
                )
                output = result.stdout.strip()
                if not output and result.stderr:
                    # stderrにも出力がある場合（一部ツールはここに出す）
                    output = result.stderr.strip()
                return output
            except subprocess.TimeoutExpired:
                if attempt < _MAX_RETRIES:
                    time.sleep(2)
                    continue
                raise RuntimeError(f"{self._name} がタイムアウトしました")
        return ""


def _create_backend(backend: str, model: str, max_tokens: int) -> _BackendBase:
    if backend == "api":
        return _AnthropicAPIBackend(model, max_tokens)
    elif backend == "claude":
        return _CLIBackend(["claude", "-p"], "claude")
    elif backend == "gemini":
        return _CLIBackend(["gemini", "-p"], "gemini")
    elif backend == "codex":
        return _CLIBackend(["codex", "exec"], "codex")
    else:
        raise ValueError(
            f"未知のバックエンド: {backend!r}\n"
            f"使用可能: api, claude, gemini, codex"
        )


def _extract_json(text: str) -> str:
    """```json ... ``` ブロックや余分なテキストを除去してJSONを抽出"""
    match = re.search(r"```(?:json)?\s*([\s\S]+?)```", text)
    if match:
        return match.group(1).strip()

    start = min(
        (text.find("{") if "{" in text else len(text)),
        (text.find("[") if "[" in text else len(text)),
    )
    if start < len(text):
        return text[start:].strip()

    return text.strip()


def detect_available_backends() -> list[str]:
    """現在の環境で使用可能なバックエンドを検出して返す"""
    import shutil
    available = []
    if os.environ.get("ANTHROPIC_API_KEY"):
        available.append("api")
    if shutil.which("claude"):
        available.append("claude")
    if shutil.which("gemini"):
        available.append("gemini")
    if shutil.which("codex"):
        available.append("codex")
    return available
