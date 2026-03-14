"""redteam/comparator.py のテスト（LLM非依存部分）"""
import pytest

from redteam.comparator import _to_compare_issue
from redteam.models import Issue


def make_issue(**kwargs) -> Issue:
    defaults = dict(title="SQLi", severity="Critical", confidence="High", category="SQLi")
    defaults.update(kwargs)
    return Issue(**defaults)


def test_to_compare_issue_basic() -> None:
    issue = make_issue(fingerprint="abc123")
    ci = _to_compare_issue(issue, ["claude"])
    assert ci.title == "SQLi"
    assert ci.severity == "Critical"
    assert ci.fingerprint == "abc123"
    assert ci.found_by == ["claude"]


def test_to_compare_issue_computes_fingerprint_if_missing() -> None:
    issue = make_issue(fingerprint="")
    ci = _to_compare_issue(issue, ["gemini"])
    assert len(ci.fingerprint) == 16  # SHA256 先頭16文字


def test_to_compare_issue_multiple_backends() -> None:
    issue = make_issue(fingerprint="fp1")
    ci = _to_compare_issue(issue, ["claude", "gemini"])
    assert "claude" in ci.found_by
    assert "gemini" in ci.found_by
