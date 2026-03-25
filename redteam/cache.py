"""スキャン結果キャッシュ — ファイルハッシュベースで再スキャンをスキップ"""
from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_CACHE_DIR = Path.home() / ".cache" / "redteam"


def compute_cache_key(content: str, mode: str, backend: str, tech_stack: list[str]) -> str:
    """コンテンツ + スキャン設定からキャッシュキーを生成"""
    payload = f"{content}||{mode}||{backend}||{','.join(sorted(tech_stack))}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_cache(cache_key: str) -> dict | None:
    """キャッシュがあれば読み込む。なければ None を返す"""
    path = _CACHE_DIR / f"{cache_key}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        logger.debug("キャッシュヒット: %s...", cache_key[:16])
        return data
    except Exception as e:
        logger.debug("キャッシュ読み込みエラー（無視）: %s", e)
        return None


def save_cache(cache_key: str, data: dict) -> None:
    """スキャン結果をキャッシュに保存"""
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = _CACHE_DIR / f"{cache_key}.json"
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        logger.debug("キャッシュ保存: %s...", cache_key[:16])
    except Exception as e:
        logger.debug("キャッシュ保存エラー（無視）: %s", e)


def invalidate_cache(cache_key: str) -> bool:
    """指定キーのキャッシュを削除。削除できたら True"""
    path = _CACHE_DIR / f"{cache_key}.json"
    if path.exists():
        path.unlink()
        return True
    return False


def clear_all_cache() -> int:
    """全キャッシュを削除。削除件数を返す"""
    if not _CACHE_DIR.exists():
        return 0
    count = 0
    for p in _CACHE_DIR.glob("*.json"):
        p.unlink()
        count += 1
    return count
