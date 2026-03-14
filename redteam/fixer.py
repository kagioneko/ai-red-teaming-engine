"""Layer 4: Evidence & Fix Generator — Analysis Layer"""
from __future__ import annotations

import json

from .llm_client import LLMClient
from .models import AuditParameters, Issue
from .normalizer import NormalizedInput
from .prompts import build_system_prompt, format_fix

_FIX_BATCH_SIZE = 5  # 1回のAPI呼び出しで処理するIssue数


def generate_fixes(
    issues: list[Issue],
    normalized: NormalizedInput,
    client: LLMClient,
    params: AuditParameters,
) -> list[Issue]:
    """
    各Issueに minimal_fix / hardening_suggestion を追加する。
    FixOrientation パラメータが低い場合はスキップ（高速化）。
    """
    if params.FixOrientation < 30:
        return issues  # 修正案生成を省略

    # Critical/Highのみ修正案を生成する場合（FixOrientation < 60）
    if params.FixOrientation < 60:
        high_priority = [i for i in issues if i.severity in ("Critical", "High")]
        others = [i for i in issues if i.severity not in ("Critical", "High")]
        fixed = _fix_batch(high_priority, normalized, client, params)
        return fixed + others

    # 全Issue対象
    return _fix_batch(issues, normalized, client, params)


def _fix_batch(
    issues: list[Issue],
    normalized: NormalizedInput,
    client: LLMClient,
    params: AuditParameters,
) -> list[Issue]:
    """バッチ処理で修正案を生成"""
    if not issues:
        return issues

    system = (
        "あなたは防御改善に特化した修正提案エンジンです。"
        " 指摘された脆弱性に対して、実用的・具体的な修正案を提案してください。"
        " 理想論に終始せず、実際のコードベースに即した修正を心がけてください。"
    )
    result: list[Issue] = []

    # バッチ処理
    for batch_start in range(0, len(issues), _FIX_BATCH_SIZE):
        batch = issues[batch_start : batch_start + _FIX_BATCH_SIZE]
        fixed_batch = _fix_single_batch(batch, normalized, client, params, system)
        result.extend(fixed_batch)

    return result


def _fix_single_batch(
    batch: list[Issue],
    normalized: NormalizedInput,
    client: LLMClient,
    params: AuditParameters,
    system: str,
) -> list[Issue]:
    issues_json = json.dumps(
        [i.model_dump() for i in batch],
        ensure_ascii=False,
        indent=2,
    )
    user = format_fix(
        issues_json=issues_json,
        content=normalized.masked_content,
        abuse_detail_limiter=params.AbuseDetailLimiter,
    )

    try:
        raw = client.query(system, user)
        cleaned = _extract_json_array(raw)
        data = json.loads(cleaned)
        if not isinstance(data, list) or len(data) != len(batch):
            return batch  # パース失敗時は元のbatchをそのまま返す

        updated: list[Issue] = []
        for original, fixed_data in zip(batch, data):
            if not isinstance(fixed_data, dict):
                updated.append(original)
                continue
            updated.append(
                original.model_copy(
                    update={
                        "minimal_fix": fixed_data.get("minimal_fix", original.minimal_fix),
                        "hardening_suggestion": fixed_data.get(
                            "hardening_suggestion", original.hardening_suggestion
                        ),
                    }
                )
            )
        return updated

    except Exception:
        return batch  # 失敗時は元のデータを保持


def _extract_json_array(text: str) -> str:
    import re
    match = re.search(r"```(?:json)?\s*(\[[\s\S]+?\])\s*```", text)
    if match:
        return match.group(1)
    start = text.find("[")
    return text[start:] if start >= 0 else "[]"
