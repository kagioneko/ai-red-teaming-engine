"""Layer 3: Adversarial Analyzer — Analysis Layer（中核モジュール）"""
from __future__ import annotations

import json
import logging

from pydantic import TypeAdapter

from .llm_client import LLMClient
from .models import (
    AttackSurfaceMap,
    AuditMode,
    AuditParameters,
    Issue,
    StaticAnalysisResult,
)
from .normalizer import NormalizedInput
from .prompts import build_system_prompt, format_analyze
from .static_tools import format_static_for_prompt

_IssueList = TypeAdapter(list[Issue])
logger = logging.getLogger(__name__)

# LLM出力で許可するsourceフィールド値（静的解析ツール名を偽称できないよう制限）
_LLM_VALID_SOURCES = frozenset({"llm", "merged", "custom"})

# Haiku トリアージ用モデル（APIバックエンド時のみ有効）
_HAIKU_MODEL = "claude-haiku-4-5-20251001"

# AIエージェント関連キーワード → トリアージをスキップして必ずSonnetで深掘り
_AI_KEYWORDS = frozenset({
    "llm", "prompt", "openai", "anthropic", "langchain", "claude", "gemini",
    "chatgpt", "completion", "embedding", "rag", "vector_store", "memory",
    "agent", "tool_call", "function_call", "system_prompt", "user_message",
    "chat_history", "context_window", "tokenize", "litellm", "haystack",
})


def analyze(
    normalized: NormalizedInput,
    surface: AttackSurfaceMap,
    static_results: StaticAnalysisResult,
    client: LLMClient,
    params: AuditParameters,
    mode: AuditMode = "deep",
    use_triage: bool = True,
    ai_triage_bypass: bool = True,
) -> list[Issue]:
    """
    敵対的前提でコード・仕様書を分析し、指摘リストを返す。
    チャンクが複数ある場合は順次処理して結果をマージする。
    """
    system = build_system_prompt(params, mode=mode)
    attack_surface_json = surface.model_dump_json(indent=2)
    static_findings_text = format_static_for_prompt(static_results)
    inp = normalized.original_input

    # Haiku トリアージクライアント（API バックエンドのみ）
    triage_client: LLMClient | None = None
    if use_triage and client.backend_name == "api":
        try:
            triage_client = LLMClient(model=_HAIKU_MODEL, backend="api")
        except Exception:
            triage_client = None  # トリアージ失敗時はスキップして深掘り続行

    all_issues: list[Issue] = []

    for i, chunk in enumerate(normalized.chunks):
        # Haiku トリアージ: クリーンと判定されたチャンクは Sonnet スキップ
        if triage_client is not None:
            if not _triage_chunk(chunk, normalized.file_path, triage_client, ai_triage_bypass):
                logger.debug("トリアージ: クリーン判定 → チャンク %d をスキップ", i + 1)
                continue

        chunk_issues = _analyze_chunk(
            chunk=chunk,
            target_type=normalized.target_type,
            tech_stack=normalized.tech_stack,
            exposure_level=inp.exposure_level,
            assets=inp.assets_to_protect,
            attack_surface_json=attack_surface_json,
            static_findings_text=static_findings_text if i == 0 else "（前チャンクで処理済み）",
            file_path=normalized.file_path,
            system=system,
            client=client,
        )
        all_issues.extend(chunk_issues)

    # 静的解析のみの指摘で未カバーのものを追加
    all_issues = _merge_static_only(all_issues, static_results)

    # 重複排除（同一タイトル + 同一affected_area）
    return _dedup_issues(all_issues)


def _is_ai_code(chunk: str) -> bool:
    """AIエージェント関連コードかどうか判定する"""
    lower = chunk.lower()
    return any(kw in lower for kw in _AI_KEYWORDS)


def _triage_chunk(chunk: str, file_path: str, haiku_client: LLMClient, ai_bypass: bool = True) -> bool:
    """
    Haiku による高速トリアージ。
    脆弱性の可能性があれば True（深掘り必要）、クリーンなら False（スキップ）。

    AIエージェント関連コードはトリアージをスキップして常に True を返す。
    プロンプトインジェクション等は文脈依存で Haiku では判断できないため。
    失敗時も安全側に倒して True を返す。
    """
    # AIコードはトリアージ不要 → 必ずSonnetで深掘り（ai_bypass=Trueの場合のみ）
    if ai_bypass and _is_ai_code(chunk):
        logger.debug("トリアージ: AIコード検知 → Sonnet深掘りを強制 (file=%s)", file_path)
        return True

    system = (
        "You are a security triage assistant. "
        "Respond with only 'yes' or 'no'."
    )
    user = (
        "Does this code likely contain security vulnerabilities "
        "(e.g. injection, hardcoded secrets, path traversal, insecure auth, SSRF)? "
        "Answer 'yes' or 'no' only.\n\n"
        f"```\n{chunk[:4000]}\n```"
    )
    try:
        answer = haiku_client.query(system, user).strip().lower()
        return answer.startswith("yes")
    except Exception as e:
        logger.debug("トリアージエラー (file=%s): %s → 深掘りにフォールバック", file_path, e)
        return True  # 安全側に倒す


def _analyze_chunk(
    chunk: str,
    target_type: str,
    tech_stack: list[str],
    exposure_level: str,
    assets: list[str],
    attack_surface_json: str,
    static_findings_text: str,
    file_path: str,
    system: str,
    client: LLMClient,
) -> list[Issue]:
    user = format_analyze(
        content=chunk,
        target_type=target_type,
        tech_stack=tech_stack,
        exposure_level=exposure_level,
        assets=assets,
        attack_surface_json=attack_surface_json,
        static_findings_text=static_findings_text,
        file_path=file_path,
    )

    try:
        raw = client.query(system, user)
        cleaned = _extract_json_array(raw)
        data = json.loads(cleaned)
        if not isinstance(data, list):
            return []
        issues = []
        for item in data:
            if not isinstance(item, dict):
                continue
            # LLMが静的解析ツール名（semgrep/gitleaks）を偽称できないよう上書き
            if item.get("source") not in _LLM_VALID_SOURCES:
                item["source"] = "llm"
            issues.append(Issue.model_validate(item))
        return issues
    except Exception as e:
        logger.warning("チャンク解析エラー (file=%s): %s", file_path, e, exc_info=True)
        return []


def _extract_json_array(text: str) -> str:
    """JSONの配列部分のみを抽出"""
    import re
    # ```json ... ``` ブロック
    match = re.search(r"```(?:json)?\s*(\[[\s\S]+?\])\s*```", text)
    if match:
        return match.group(1)
    # [ から始まる最初の配列
    start = text.find("[")
    if start >= 0:
        return text[start:]
    return "[]"


def _merge_static_only(issues: list[Issue], static_results: StaticAnalysisResult) -> list[Issue]:
    """
    静的解析結果のうち、LLM分析でカバーされていないものを追加する。
    LLMが同じ (file, line) を既に指摘済みなら追加しない（重複防止）。

    注: LLM issueは source="llm" に統一されているため、
        source名ではなく (file, line) で照合する。
    """
    # LLMが既に指摘した (file, line) のセット
    llm_covered: set[tuple[str, int]] = {
        (i.file or "", i.line_start)
        for i in issues
        if i.line_start is not None
    }

    for finding in static_results.findings:
        if (finding.file_path, finding.line) in llm_covered:
            continue

        # 静的解析の指摘をIssueとして追加
        from .models import IssueScores
        sev_map = {"Critical": "Critical", "High": "High", "Medium": "Medium", "Low": "Low"}
        severity = sev_map.get(finding.severity, "Medium")

        issue = Issue(
            title=f"[{finding.tool.upper()}] {finding.rule_id}: {finding.message[:80]}",
            severity=severity,  # type: ignore
            confidence="High",  # 静的解析の検出は確信度高
            category="Secret" if finding.tool == "gitleaks" else "Other",
            affected_area=f"{finding.file_path}:{finding.line}",
            why_this_matters=finding.message,
            evidence=finding.code_snippet[:200] if finding.code_snippet else "",
            source=finding.tool,  # type: ignore
            file=finding.file_path,
            line_start=finding.line,
            scores=IssueScores(
                impact=8.0 if finding.tool == "gitleaks" else 5.0,
                likelihood=7.0,
                exploitability=6.0,
                evidence=9.0,  # 静的解析は根拠が明確
                urgency=8.0 if finding.tool == "gitleaks" else 5.0,
            ),
        )
        issues.append(issue)

    return issues


def _dedup_issues(issues: list[Issue]) -> list[Issue]:
    """同一タイトル+affected_areaの重複を除去"""
    seen: set[str] = set()
    unique: list[Issue] = []
    for issue in issues:
        key = f"{issue.title[:50]}|{issue.affected_area[:50]}"
        if key not in seen:
            seen.add(key)
            unique.append(issue)
    return unique
