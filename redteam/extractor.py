"""Layer 2: Attack Surface Extractor — Analysis Layer"""
from __future__ import annotations

import json

from .llm_client import LLMClient
from .models import AttackSurfaceMap, AuditParameters
from .normalizer import NormalizedInput
from .prompts import build_system_prompt, format_extract_surface


def extract_attack_surface(
    normalized: NormalizedInput,
    client: LLMClient,
    params: AuditParameters,
) -> AttackSurfaceMap:
    """
    入力から攻撃面を抽出する。
    チャンクが複数ある場合は最初のチャンクを代表として使用し、
    全チャンク件数を概要に含める。
    """
    system = build_system_prompt(params, mode="safe")  # 攻撃面抽出は軽量モード
    inp = normalized.original_input

    # 代表チャンク（最初のチャンク）を使用
    representative_content = normalized.chunks[0] if normalized.chunks else normalized.masked_content

    user = format_extract_surface(
        content=representative_content,
        target_type=normalized.target_type,
        tech_stack=normalized.tech_stack,
        system_overview=inp.system_overview,
    )

    try:
        result = client.query_json(system, user, AttackSurfaceMap)
        return result
    except (ValueError, Exception):
        # パース失敗時は空のマップを返す（監査は継続）
        return AttackSurfaceMap()
