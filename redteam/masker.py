"""機密マスキング処理 — Ingestion Layer"""
from __future__ import annotations

import re

# APIキー・トークン類（20文字以上の英数字+記号列）
_TOKEN_PATTERN = re.compile(
    r"""(?x)
    (?:
        (?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|bearer|secret[_-]?key|
           private[_-]?key|client[_-]?secret|api[_-]?secret)
        \s*[=:]\s*["']?
    )
    ([A-Za-z0-9_\-\.]{20,})
    """,
    re.IGNORECASE,
)

# パスワード変数
_PASSWORD_PATTERN = re.compile(
    r"""(?x)
    (?:password|passwd|pwd)
    \s*[=:]\s*["']([^"'\n]{4,})["']
    """,
    re.IGNORECASE,
)

# 環境変数にセットされる生シークレット（よくある形式）
_RAW_SECRET_PATTERN = re.compile(
    r"""(?x)
    (?:sk-[a-zA-Z0-9]{20,}          # OpenAI / Anthropic スタイル
    |  ghp_[a-zA-Z0-9]{30,}          # GitHub PAT
    |  xoxb-[0-9]+-[a-zA-Z0-9]+    # Slack Bot token
    |  AIza[0-9A-Za-z\-_]{35}       # Google API key
    |  AKIA[0-9A-Z]{16}             # AWS Access Key ID
    )
    """,
)

# DB接続文字列
_CONNSTR_PATTERN = re.compile(
    r"""(?x)
    (?:postgresql|mysql|mongodb|redis|sqlite)://
    [^\s"'<>]+
    """,
    re.IGNORECASE,
)

# IPv4アドレス（プライベート帯域のみ抑制）
_PRIVATE_IP_PATTERN = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})\b"
)


def mask_secrets(text: str, mask_ips: bool = False) -> tuple[str, int]:
    """
    機密情報を [MASKED] に置換する。

    Returns:
        (マスク済みテキスト, マスクした件数)
    """
    count = 0

    def replace_and_count(pattern: re.Pattern, repl: str, s: str) -> tuple[str, int]:
        matches = pattern.findall(s)
        new_s = pattern.sub(repl, s)
        return new_s, len(matches)

    text, n = replace_and_count(_RAW_SECRET_PATTERN, "[MASKED]", text)
    count += n

    text, n = replace_and_count(_TOKEN_PATTERN, "[MASKED_KEY]", text)
    count += n

    text, n = replace_and_count(_PASSWORD_PATTERN, "[MASKED_PASS]", text)
    count += n

    text, n = replace_and_count(_CONNSTR_PATTERN, "[MASKED_CONNSTR]", text)
    count += n

    if mask_ips:
        text, n = replace_and_count(_PRIVATE_IP_PATTERN, "[MASKED_IP]", text)
        count += n

    return text, count
