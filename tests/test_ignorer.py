"""redteam/ignorer.py のテスト"""
import textwrap
from pathlib import Path

import pytest

from redteam.ignorer import (
    IgnoreRules,
    filter_issues,
    load_ignore_rules,
    should_skip_file,
)
from redteam.models import Issue


# ─── load_ignore_rules ────────────────────────────────────────────────────────

def test_load_ignore_rules_empty_file(tmp_path: Path) -> None:
    f = tmp_path / ".redteam-ignore"
    f.write_text("")
    rules = load_ignore_rules(f)
    assert rules.is_empty


def test_load_ignore_rules_missing_file(tmp_path: Path) -> None:
    rules = load_ignore_rules(tmp_path / ".redteam-ignore")
    assert rules.is_empty


def test_load_ignore_rules_all_types(tmp_path: Path) -> None:
    f = tmp_path / ".redteam-ignore"
    f.write_text(textwrap.dedent("""\
        # コメント行
        tests/
        *.generated.py
        severity:Info
        category:CORS
        fingerprint:abc123
        rule:RTE-Auth-Low
    """))
    rules = load_ignore_rules(f)
    assert "tests/" in rules.dir_prefixes
    assert "*.generated.py" in rules.file_globs
    assert "Info" in rules.severities
    assert "CORS" in rules.categories
    assert "abc123" in rules.fingerprints
    assert "RTE-Auth-Low" in rules.rule_ids


def test_load_ignore_rules_comments_stripped(tmp_path: Path) -> None:
    f = tmp_path / ".redteam-ignore"
    f.write_text("severity:Info  # この行末コメントは無視される\n")
    rules = load_ignore_rules(f)
    assert "Info" in rules.severities


# ─── should_skip_file ────────────────────────────────────────────────────────

def make_rules(**kwargs) -> IgnoreRules:
    return IgnoreRules(**kwargs)


@pytest.mark.parametrize("path,expected", [
    ("tests/sample.py",  True),
    ("src/app.py",       False),
    ("tests",            True),
])
def test_skip_dir_prefix(path: str, expected: bool) -> None:
    rules = make_rules(dir_prefixes=["tests/"])
    base = Path("/project")
    assert should_skip_file(base / path, rules, base_dir=base) == expected


@pytest.mark.parametrize("name,expected", [
    ("api.generated.py", True),
    ("api.py",           False),
    ("main.generated.ts", False),  # .py のみマッチ
])
def test_skip_glob(name: str, expected: bool) -> None:
    rules = make_rules(file_globs=["*.generated.py"])
    assert should_skip_file(Path("/src") / name, rules) == expected


def test_empty_rules_never_skip() -> None:
    rules = IgnoreRules()
    assert not should_skip_file(Path("tests/secret.py"), rules)


# ─── filter_issues ───────────────────────────────────────────────────────────

def make_issue(**kwargs) -> Issue:
    defaults = dict(title="test", severity="Medium", confidence="Medium", category="Other")
    defaults.update(kwargs)
    return Issue(**defaults)


def test_filter_severity() -> None:
    rules = make_rules(severities={"Info"})
    issues = [make_issue(severity="Info"), make_issue(severity="High")]
    result = filter_issues(issues, rules)
    assert len(result) == 1
    assert result[0].severity == "High"


def test_filter_category() -> None:
    rules = make_rules(categories={"CORS"})
    issues = [make_issue(category="CORS"), make_issue(category="SQLi")]
    result = filter_issues(issues, rules)
    assert len(result) == 1
    assert result[0].category == "SQLi"


def test_filter_fingerprint() -> None:
    rules = make_rules(fingerprints={"deadbeef"})
    issues = [
        make_issue(title="known fp", fingerprint="deadbeef"),
        make_issue(title="real issue", fingerprint="abc123"),
    ]
    result = filter_issues(issues, rules)
    assert len(result) == 1
    assert result[0].title == "real issue"


def test_filter_rule_id() -> None:
    rules = make_rules(rule_ids={"RTE-CORS-Medium"})
    issues = [
        make_issue(category="CORS", severity="Medium"),
        make_issue(category="SQLi", severity="Critical"),
    ]
    result = filter_issues(issues, rules)
    assert len(result) == 1
    assert result[0].category == "SQLi"


def test_empty_rules_no_filter() -> None:
    rules = IgnoreRules()
    issues = [make_issue() for _ in range(5)]
    assert filter_issues(issues, rules) == issues
