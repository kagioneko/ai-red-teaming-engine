"""
--watch モード — ファイル変更を検知して自動再監査

watchdog でファイルシステムを監視し、変更があれば
デバウンス後に監査パイプラインを再実行する。
"""
from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from typing import Callable

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer


_DEBOUNCE_SEC = 1.5   # 最後の変更から何秒後に再実行するか
_WATCH_EXTS = {
    ".py", ".js", ".ts", ".go", ".rs", ".java", ".rb", ".php",
    ".yaml", ".yml", ".json", ".toml", ".md", ".txt",
}


class _DebounceHandler(FileSystemEventHandler):
    """変更イベントをデバウンスして audit コールバックを呼び出す"""

    def __init__(
        self,
        on_change: Callable[[Path], None],
        watch_path: Path,
        exts: set[str],
    ) -> None:
        super().__init__()
        self._on_change = on_change
        self._watch_path = watch_path
        self._exts = exts
        self._timer: threading.Timer | None = None
        self._last_path: Path | None = None
        self._lock = threading.Lock()

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        p = Path(str(event.src_path))
        if p.suffix.lower() not in self._exts:
            return
        # .redteam-ignore / ログ / キャッシュを除外
        if any(part.startswith(".") or part in ("logs", "__pycache__")
               for part in p.parts):
            return

        with self._lock:
            self._last_path = p
            if self._timer:
                self._timer.cancel()
            self._timer = threading.Timer(_DEBOUNCE_SEC, self._fire)
            self._timer.daemon = True
            self._timer.start()

    def _fire(self) -> None:
        with self._lock:
            path = self._last_path
        if path:
            self._on_change(path)


def watch(
    target: Path,
    on_change: Callable[[Path], None],
    exts: set[str] | None = None,
) -> None:
    """
    target（ファイルまたはディレクトリ）を監視し、
    変更が検知されるたびに on_change(changed_path) を呼び出す。

    Ctrl+C で停止。
    """
    watch_exts = exts or _WATCH_EXTS
    watch_dir = target if target.is_dir() else target.parent

    handler = _DebounceHandler(
        on_change=on_change,
        watch_path=target,
        exts=watch_exts,
    )
    observer = Observer()
    observer.schedule(handler, str(watch_dir), recursive=target.is_dir())
    observer.start()

    print(f"\n👁  監視中: {target}  （Ctrl+C で停止）\n", file=sys.stderr)

    try:
        while True:
            time.sleep(0.5)
            if not observer.is_alive():
                break
    except KeyboardInterrupt:
        print("\n⛔ 監視を停止しました。", file=sys.stderr)
    finally:
        observer.stop()
        observer.join()
