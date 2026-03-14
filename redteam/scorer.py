"""スコアリング・優先度計算"""
from __future__ import annotations

from .models import Issue, IssueScores

_FALSE_POSITIVE_PENALTY = {
    "low": 0.0,
    "medium": 1.0,
    "high": 2.5,
}

_SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Info": 1,
}


def calculate_priority(scores: IssueScores, false_positive_risk_text: str) -> float:
    """
    Priority = (
        Impact × 0.35 +
        Likelihood × 0.25 +
        Exploitability × 0.20 +
        Urgency × 0.20
    ) × (Evidence / 10) - FalsePositivePenalty

    ImpactとExploitabilityの相関を重み付けで緩和。
    Evidenceが低いと全体スコアが圧縮される。
    """
    base = (
        scores.impact * 0.35
        + scores.likelihood * 0.25
        + scores.exploitability * 0.20
        + scores.urgency * 0.20
    )
    evidence_multiplier = scores.evidence / 10.0

    fp_text = false_positive_risk_text.lower()
    if "高" in fp_text or "high" in fp_text:
        penalty = _FALSE_POSITIVE_PENALTY["high"]
    elif "中" in fp_text or "medium" in fp_text:
        penalty = _FALSE_POSITIVE_PENALTY["medium"]
    else:
        penalty = _FALSE_POSITIVE_PENALTY["low"]

    priority = base * evidence_multiplier - penalty
    return round(max(priority, 0.0), 2)


def assign_priority(issue: Issue) -> Issue:
    """Issueのpriorityを計算して返す（immutable）"""
    return issue.model_copy(
        update={"priority": calculate_priority(issue.scores, issue.false_positive_risk)}
    )


def sort_issues_by_priority(issues: list[Issue]) -> list[Issue]:
    """優先度の高い順にソート。同一priorityは severity で二次ソート"""
    return sorted(
        issues,
        key=lambda i: (
            -i.priority,
            -_SEVERITY_ORDER.get(i.severity, 0),
        ),
    )


def assign_issue_ids(issues: list[Issue], prefix: str = "RTE") -> list[Issue]:
    """連番のissue_idを付与する"""
    result = []
    for i, issue in enumerate(issues, start=1):
        fp = issue.model_copy(update={"issue_id": f"{prefix}-{i:03d}"})
        # fingerprintが未設定なら計算
        if not fp.fingerprint:
            fp = fp.model_copy(update={"fingerprint": fp.compute_fingerprint()})
        result.append(fp)
    return result
