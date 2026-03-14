"""scorer モジュールのユニットテスト"""
import pytest
from redteam.scorer import calculate_priority, assign_issue_ids, sort_issues_by_priority
from redteam.models import Issue, IssueScores


def _make_issue(**kwargs) -> Issue:
    defaults = dict(
        title="Test Issue",
        severity="High",
        confidence="Medium",
        category="Auth",
        scores=IssueScores(impact=7, likelihood=6, exploitability=5, evidence=8, urgency=6),
        false_positive_risk="low",
    )
    defaults.update(kwargs)
    return Issue(**defaults)


def test_priority_with_high_evidence():
    scores = IssueScores(impact=8, likelihood=7, exploitability=6, evidence=9, urgency=7)
    p = calculate_priority(scores, "low risk")
    # base = 8*0.35 + 7*0.25 + 6*0.20 + 7*0.20 = 2.8+1.75+1.2+1.4 = 7.15
    # priority = 7.15 * (9/10) - 0 = 6.435
    assert abs(p - 6.435) < 0.01


def test_priority_penalized_by_false_positive():
    scores = IssueScores(impact=8, likelihood=7, exploitability=6, evidence=9, urgency=7)
    p_low = calculate_priority(scores, "low risk")
    p_high = calculate_priority(scores, "high false positive risk")
    assert p_low > p_high


def test_priority_penalized_by_low_evidence():
    high_ev = IssueScores(impact=7, likelihood=6, exploitability=5, evidence=9, urgency=6)
    low_ev = IssueScores(impact=7, likelihood=6, exploitability=5, evidence=3, urgency=6)
    assert calculate_priority(high_ev, "low") > calculate_priority(low_ev, "low")


def test_priority_never_negative():
    scores = IssueScores(impact=1, likelihood=1, exploitability=1, evidence=1, urgency=1)
    p = calculate_priority(scores, "high false positive risk")
    assert p >= 0


def test_sort_by_priority():
    issues = [
        _make_issue(title="Low priority", severity="Low",
                    scores=IssueScores(impact=2, likelihood=2, exploitability=2, evidence=5, urgency=2)),
        _make_issue(title="High priority", severity="Critical",
                    scores=IssueScores(impact=9, likelihood=8, exploitability=8, evidence=9, urgency=9)),
        _make_issue(title="Med priority", severity="Medium",
                    scores=IssueScores(impact=5, likelihood=5, exploitability=5, evidence=7, urgency=5)),
    ]
    from redteam.scorer import assign_priority
    issues = [assign_priority(i) for i in issues]
    sorted_issues = sort_issues_by_priority(issues)
    assert sorted_issues[0].title == "High priority"
    assert sorted_issues[-1].title == "Low priority"


def test_assign_issue_ids():
    issues = [_make_issue(title=f"Issue {i}") for i in range(3)]
    result = assign_issue_ids(issues)
    assert result[0].issue_id == "RTE-001"
    assert result[1].issue_id == "RTE-002"
    assert result[2].issue_id == "RTE-003"


def test_fingerprint_assigned():
    issues = [_make_issue(title="Test", file="app.py", affected_area="L42")]
    result = assign_issue_ids(issues)
    assert len(result[0].fingerprint) == 16
