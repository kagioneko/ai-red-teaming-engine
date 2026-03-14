"""チャンク分割ロジック — 関数・クラス境界優先 — Ingestion Layer"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass
class ChunkResult:
    chunks: list[str]
    total_lines: int
    strategy: str  # "single" | "function_boundary" | "line_split"
    imports: str = ""  # 各チャンクに付与するimport宣言


CHUNK_THRESHOLD_SMALL = 1000   # 以下はそのまま
CHUNK_THRESHOLD_LARGE = 5000   # 超えたら行分割
OVERLAP_LINES = 20


def chunk_content(content: str, language: str = "python") -> ChunkResult:
    """
    コード・文書をチャンクに分割する。
    - < 1000行: 単一チャンク
    - 1000〜5000行: 関数/クラス境界で分割（Pythonの場合はAST使用）
    - > 5000行: 行ベース分割（オーバーラップ付き）
    """
    lines = content.splitlines()
    total = len(lines)

    if total <= CHUNK_THRESHOLD_SMALL:
        return ChunkResult(chunks=[content], total_lines=total, strategy="single")

    if language == "python" and total <= CHUNK_THRESHOLD_LARGE:
        chunks = _split_by_ast(content, lines)
        if chunks:
            imports = _extract_imports(content)
            # 各チャンクにimportを前置
            chunks_with_imports = [
                imports + "\n" + c if imports and not c.startswith(imports) else c
                for c in chunks
            ]
            return ChunkResult(
                chunks=chunks_with_imports,
                total_lines=total,
                strategy="function_boundary",
                imports=imports,
            )

    # フォールバック: 行ベース分割
    chunks = _split_by_lines(lines, chunk_size=800, overlap=OVERLAP_LINES)
    return ChunkResult(chunks=chunks, total_lines=total, strategy="line_split")


def _extract_imports(content: str) -> str:
    """import/from行を抽出する"""
    import_lines = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            import_lines.append(line)
    return "\n".join(import_lines)


def _split_by_ast(content: str, lines: list[str]) -> list[str]:
    """Python ASTで関数・クラス境界を検出して分割"""
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return []

    # トップレベルの関数・クラスの行番号を収集
    boundaries: list[int] = [1]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if hasattr(node, "lineno"):
                boundaries.append(node.lineno)

    boundaries = sorted(set(boundaries))
    boundaries.append(len(lines) + 1)  # 終端

    chunks: list[str] = []
    current_start = 0
    current_lines: list[str] = []

    for i in range(len(boundaries) - 1):
        start_line = boundaries[i]
        end_line = boundaries[i + 1]
        block = lines[start_line - 1 : end_line - 1]

        current_lines.extend(block)

        # 800行を超えたらチャンクを確定
        if len(current_lines) >= 800:
            chunks.append("\n".join(current_lines))
            # オーバーラップ: 末尾OVERLAP_LINESを次チャンクの先頭に
            current_lines = current_lines[-OVERLAP_LINES:]

    if current_lines:
        chunks.append("\n".join(current_lines))

    return chunks if len(chunks) > 1 else []


def _split_by_lines(
    lines: list[str], chunk_size: int = 800, overlap: int = 20
) -> list[str]:
    """行ベースの分割（オーバーラップ付き）"""
    chunks: list[str] = []
    start = 0
    while start < len(lines):
        end = min(start + chunk_size, len(lines))
        chunks.append("\n".join(lines[start:end]))
        start = end - overlap if end < len(lines) else end
    return chunks
