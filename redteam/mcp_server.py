"""AI-Red-Teaming-Engine MCP サーバー

Claude から直接呼び出せる脆弱性監査ツール群を公開する。

起動方法:
    python -m redteam.mcp_server
    または
    redteam-mcp  # pyproject.toml のエントリポイント経由
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from mcp.server.fastmcp import FastMCP

# エンジン本体のパスを通す
sys.path.insert(0, str(Path(__file__).parent.parent))

from redteam.config import DEFAULT_MODEL
from redteam.formatters import format_markdown, format_dir_markdown
from redteam.ignorer import load_ignore_rules
from redteam.models import AuditInput, AuditMode, TargetType
from redteam.pipeline import run_audit, run_dir_audit

mcp = FastMCP(
    name="ai-red-teaming-engine",
    instructions=(
        "コード・仕様・AIエージェントを攻撃者視点でレビューする脆弱性監査エンジン。"
        "scan_file でファイルを、scan_code でスニペットを、scan_directory でディレクトリ全体をスキャンできる。"
    ),
)

# TargetType の選択肢（ドキュメント用）
_TARGET_TYPES = "code / spec / api / prompt / architecture / agent"
_AUDIT_MODES  = "safe（高速・低ノイズ）/ deep（詳細・推奨）/ patch（修正案付き）"


@mcp.tool()
def scan_code(
    code: str,
    target_type: str = "code",
    tech_stack: str = "",
    mode: str = "deep",
    system_overview: str = "",
    exposure_level: str = "internal",
    rules_file: str = "",
) -> str:
    """コードスニペットを直接渡して脆弱性監査を実行する。

    Args:
        code: 監査対象のコード / テキスト本文
        target_type: 対象種別。{_TARGET_TYPES}
        tech_stack: 使用技術をカンマ区切りで（例: "Python,FastAPI,PostgreSQL"）
        mode: 監査モード。{_AUDIT_MODES}
        system_overview: システムの概要説明（任意）
        exposure_level: 公開範囲 — public / internal / private
        rules_file: カスタムルールファイルのパス（.redteam-rules.yaml）。省略時はカレントディレクトリ・ホームディレクトリを自動検索
    """
    stack = [s.strip() for s in tech_stack.split(",") if s.strip()] or ["unknown"]
    rf = Path(rules_file).expanduser().resolve() if rules_file else None
    audit_input = AuditInput(
        target_content=code,
        target_type=_validate_target_type(target_type),
        tech_stack=stack,
        system_overview=system_overview,
        exposure_level=exposure_level,  # type: ignore[arg-type]
    )
    report = run_audit(audit_input, mode=_validate_mode(mode), rules_file=rf)
    return format_markdown(report)


@mcp.tool()
def scan_file(
    file_path: str,
    mode: str = "deep",
    tech_stack: str = "",
    system_overview: str = "",
    exposure_level: str = "internal",
) -> str:
    """ファイルを読み込んで脆弱性監査を実行する。

    Args:
        file_path: 監査対象ファイルの絶対パス（または相対パス）
        mode: 監査モード。{_AUDIT_MODES}
        tech_stack: 使用技術をカンマ区切りで（省略時は拡張子から自動判定）
        system_overview: システムの概要説明（任意）
        exposure_level: 公開範囲 — public / internal / private
    """
    path = Path(file_path).expanduser().resolve()
    if not path.exists():
        return f"エラー: ファイルが見つかりません — {path}"
    if not path.is_file():
        return f"エラー: ファイルではありません — {path}"

    content = path.read_text(encoding="utf-8", errors="replace")
    target_type = _infer_type_from_ext(path.suffix)
    stack = [s.strip() for s in tech_stack.split(",") if s.strip()] or ["unknown"]

    audit_input = AuditInput(
        target_content=content,
        target_type=target_type,
        tech_stack=stack,
        system_overview=system_overview,
        exposure_level=exposure_level,  # type: ignore[arg-type]
        file_path=str(path),
    )
    report = run_audit(audit_input, mode=_validate_mode(mode))
    return format_markdown(report)


@mcp.tool()
def scan_directory(
    dir_path: str,
    mode: str = "deep",
    tech_stack: str = "",
    system_overview: str = "",
    exposure_level: str = "internal",
    max_files: int = 20,
) -> str:
    """ディレクトリ配下のファイルを一括スキャンして脆弱性レポートを生成する。

    Args:
        dir_path: 監査対象ディレクトリの絶対パス（または相対パス）
        mode: 監査モード。{_AUDIT_MODES}
        tech_stack: 使用技術をカンマ区切りで（省略時は拡張子から自動判定）
        system_overview: システムの概要説明（任意）
        exposure_level: 公開範囲 — public / internal / private
        max_files: スキャンするファイル数の上限（デフォルト 20）
    """
    path = Path(dir_path).expanduser().resolve()
    if not path.exists():
        return f"エラー: ディレクトリが見つかりません — {path}"
    if not path.is_dir():
        return f"エラー: ディレクトリではありません — {path}"

    stack = [s.strip() for s in tech_stack.split(",") if s.strip()] or ["unknown"]
    ignore_rules = load_ignore_rules(path)

    dir_report = run_dir_audit(
        target_dir=path,
        mode=_validate_mode(mode),
        tech_stack=stack,
        system_overview=system_overview,
        exposure_level=exposure_level,
        ignore_rules=ignore_rules,
        max_files=max_files,
    )
    return format_dir_markdown(dir_report)


# ── ヘルパー ──────────────────────────────────────────────

_EXT_TO_TYPE: dict[str, TargetType] = {
    ".py": "code", ".js": "code", ".ts": "code", ".jsx": "code", ".tsx": "code",
    ".go": "code", ".rs": "code", ".java": "code", ".rb": "code", ".php": "code",
    ".c": "code", ".cpp": "code", ".cs": "code", ".swift": "code", ".kt": "code",
    ".sh": "code", ".bash": "code",
    ".yaml": "api", ".yml": "api", ".json": "api", ".toml": "api",
    ".md": "spec", ".rst": "spec", ".txt": "spec",
}


def _infer_type_from_ext(ext: str) -> TargetType:
    return _EXT_TO_TYPE.get(ext.lower(), "code")


def _validate_target_type(t: str) -> TargetType:
    valid: tuple[TargetType, ...] = ("code", "spec", "api", "prompt", "architecture", "agent")
    return t if t in valid else "code"  # type: ignore[return-value]


def _validate_mode(m: str) -> AuditMode:
    valid: tuple[AuditMode, ...] = ("safe", "deep", "agent-audit", "patch")
    return m if m in valid else "deep"  # type: ignore[return-value]


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
