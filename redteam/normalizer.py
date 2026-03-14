"""Layer 1: Input Normalizer — Ingestion Layer"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .masker import mask_secrets
from .chunker import chunk_content, ChunkResult
from .models import AuditInput, TargetType

_EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".sh": "bash",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".md": "markdown",
    ".toml": "toml",
}

_EXT_TO_TYPE: dict[str, TargetType] = {
    ".py": "code",
    ".js": "code",
    ".ts": "code",
    ".tsx": "code",
    ".jsx": "code",
    ".go": "code",
    ".rs": "code",
    ".java": "code",
    ".rb": "code",
    ".php": "code",
    ".sh": "code",
    ".yaml": "spec",
    ".yml": "spec",
    ".json": "spec",
    ".md": "spec",
    ".toml": "spec",
}


@dataclass
class NormalizedInput:
    masked_content: str
    chunks: list[str]
    chunk_strategy: str
    target_type: TargetType
    tech_stack: list[str]
    language: str
    mask_count: int
    original_input: AuditInput
    file_path: str = ""


def normalize(audit_input: AuditInput) -> NormalizedInput:
    """入力を正規化する（マスキング → チャンク分割）"""
    # 機密マスキング
    masked, mask_count = mask_secrets(audit_input.target_content)

    # 言語・対象種別の推定
    language = _detect_language(audit_input.file_path, masked)
    target_type = audit_input.target_type or _detect_type(audit_input.file_path)

    # チャンク分割
    chunk_result: ChunkResult = chunk_content(masked, language=language)

    # tech_stackが未指定なら推定
    tech_stack = audit_input.tech_stack or _infer_tech_stack(masked, language)

    return NormalizedInput(
        masked_content=masked,
        chunks=chunk_result.chunks,
        chunk_strategy=chunk_result.strategy,
        target_type=target_type,
        tech_stack=tech_stack,
        language=language,
        mask_count=mask_count,
        original_input=audit_input,
        file_path=audit_input.file_path,
    )


def _detect_language(file_path: str, content: str) -> str:
    if file_path:
        ext = Path(file_path).suffix.lower()
        if ext in _EXT_TO_LANG:
            return _EXT_TO_LANG[ext]
    # shebangから推定
    first_line = content.splitlines()[0] if content else ""
    if "python" in first_line:
        return "python"
    if "node" in first_line or "javascript" in first_line:
        return "javascript"
    if "bash" in first_line or "sh" in first_line:
        return "bash"
    return "unknown"


def _detect_type(file_path: str) -> TargetType:
    if file_path:
        ext = Path(file_path).suffix.lower()
        return _EXT_TO_TYPE.get(ext, "code")
    return "code"


def _infer_tech_stack(content: str, language: str) -> list[str]:
    """importやrequireからtech_stackを推定"""
    stack = [language] if language != "unknown" else []
    content_lower = content.lower()
    candidates = {
        "fastapi": "FastAPI",
        "flask": "Flask",
        "django": "Django",
        "express": "Express",
        "next": "Next.js",
        "react": "React",
        "firebase": "Firebase",
        "supabase": "Supabase",
        "prisma": "Prisma",
        "sqlalchemy": "SQLAlchemy",
        "anthropic": "Anthropic SDK",
        "openai": "OpenAI SDK",
        "langchain": "LangChain",
    }
    for keyword, name in candidates.items():
        if keyword in content_lower:
            stack.append(name)
    return list(dict.fromkeys(stack))  # 重複排除・順序維持
