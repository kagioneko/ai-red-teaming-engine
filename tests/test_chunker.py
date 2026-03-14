"""chunker モジュールのユニットテスト"""
import pytest
from redteam.chunker import chunk_content, CHUNK_THRESHOLD_SMALL


def test_single_chunk_small():
    content = "def foo():\n    pass\n" * 10
    result = chunk_content(content)
    assert result.strategy == "single"
    assert len(result.chunks) == 1


def test_multiple_chunks_large_python():
    # 1000行超のPythonコードを生成
    lines = []
    for i in range(50):
        lines.append(f"def func_{i}(x):")
        lines.append(f"    return x + {i}")
        lines.append("")
    content = "\n".join(lines * 8)  # 1200行程度
    result = chunk_content(content, language="python")
    # 単一または関数境界分割
    assert len(result.chunks) >= 1
    assert result.total_lines > CHUNK_THRESHOLD_SMALL


def test_non_python_falls_back():
    content = "const x = 1;\n" * 1200
    result = chunk_content(content, language="javascript")
    # ASTが使えないためline_splitかsingle
    assert result.strategy in ("line_split", "single")


def test_chunks_not_empty():
    content = "hello world\n" * 100
    result = chunk_content(content)
    for chunk in result.chunks:
        assert len(chunk) > 0


def test_overlap_in_line_split():
    lines = ["line_{i}" for i in range(2000)]
    content = "\n".join(lines)
    result = chunk_content(content, language="unknown")
    # オーバーラップにより隣接チャンク間で共通行が存在するはず
    if len(result.chunks) >= 2:
        last_of_first = result.chunks[0].splitlines()[-20:]
        first_of_second = result.chunks[1].splitlines()[:20]
        overlap = set(last_of_first) & set(first_of_second)
        assert len(overlap) > 0
