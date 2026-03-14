"""Layer 3: Adversarial Analyzer — Analysis Layer（中核モジュール）"""
from __future__ import annotations

import json

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


def analyze(
    normalized: NormalizedInput,
    surface: AttackSurfaceMap,
    static_results: StaticAnalysisResult,
    client: LLMClient,
    params: AuditParameters,
    mode: AuditMode = "deep",
) -> list[Issue]:
    """
    敵対的前提でコード・仕様書を分析し、指摘リストを返す。
    チャンクが複数ある場合は順次処理して結果をマージする。
    """
    system = build_system_prompt(params, mode=mode)
    attack_surface_json = surface.model_dump_json(indent=2)
    static_findings_text = format_static_for_prompt(static_results)
    inp = normalized.original_input

    all_issues: list[Issue] = []

    for i, chunk in enumerate(normalized.chunks):
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
        return [Issue.model_validate(item) for item in data if isinstance(item, dict)]
    except Exception:
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
    LLMが既に「source: semgrep/gitleaks/merged」として取り込んでいれば重複しない。
    """
    covered_rules = {
        (i.source, i.line_start)
        for i in issues
        if i.source in ("semgrep", "gitleaks", "merged")
    }

    for finding in static_results.findings:
        if (finding.tool, finding.line) in covered_rules:
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
