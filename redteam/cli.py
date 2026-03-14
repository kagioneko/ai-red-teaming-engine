"""pip install 後の `redteam-scan` コマンドエントリポイント"""
import sys
from pathlib import Path

# パッケージとして呼ばれた場合でも engine.py を参照できるようにする
sys.path.insert(0, str(Path(__file__).parent.parent))

from engine import main  # noqa: E402

if __name__ == "__main__":
    main()
