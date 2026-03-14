"""redteam/custom_rules.py のテスト"""
from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest

from redteam.custom_rules import (
    CustomRule,
    find_rules_file,
    load_custom_rules,
    match_rules,
    matches_to_findings,
    run_custom_rules,
)


# ─── フィクスチャ ─────────────────────────────────────────────────────────────

def make_rule(
    rule_id: str = "CUS-001",
    pattern: str = "eval\\s*\\(",
    severity: str = "High",
    category: str = "Test",
    file_glob: str | None = None,
) -> CustomRule:
    return CustomRule(
        rule_id=rule_id,
        name="テストルール",
        pattern=re.compile(pattern),
        severity=severity,
        category=category,
        message="テストメッセージ",
        file_glob=file_glob,
    )


def write_rules_yaml(tmp_path: Path, content: str) -> Path:
    p = tmp_path / ".redteam-rules.yaml"
    p.write_text(content, encoding="utf-8")
    return p


# ─── load_custom_rules ───────────────────────────────────────────────────────

VALID_YAML = textwrap.dedent("""\
    rules:
      - id: CUS-001
        name: "eval 検出"
        pattern: "eval\\\\s*\\\\("
        severity: High
        category: "Code Injection"
        message: "eval は危険です"
        file_glob: "*.py"
        enabled: true
      - id: CUS-002
        name: "無効ルール"
        pattern: "foo"
        severity: Low
        category: "Test"
        message: "無効"
        enabled: false
""")


def test_load_valid_rules(tmp_path: Path) -> None:
    p = write_rules_yaml(tmp_path, VALID_YAML)
    rules, errors = load_custom_rules(p)
    assert len(rules) == 1  # CUS-002 は enabled:false でスキップ
    assert rules[0].rule_id == "CUS-001"
    assert rules[0].severity == "High"
    assert rules[0].file_glob == "*.py"
    assert not errors


def test_load_invalid_pattern(tmp_path: Path) -> None:
    yaml_text = "rules:\n  - id: BAD\n    name: 'bad'\n    pattern: '[invalid'\n    severity: High\n    category: Test\n    message: m\n"
    p = write_rules_yaml(tmp_path, yaml_text)
    rules, errors = load_custom_rules(p)
    assert len(rules) == 0
    assert any("無効な正規表現" in e for e in errors)


def test_load_missing_pattern(tmp_path: Path) -> None:
    yaml_text = "rules:\n  - id: NO-PAT\n    name: 'no pattern'\n    severity: High\n    category: Test\n    message: m\n"
    p = write_rules_yaml(tmp_path, yaml_text)
    rules, errors = load_custom_rules(p)
    assert len(rules) == 0
    assert any("pattern" in e for e in errors)


def test_load_invalid_severity_falls_back(tmp_path: Path) -> None:
    yaml_text = "rules:\n  - id: SEV-TEST\n    name: 'sev'\n    pattern: 'foo'\n    severity: INVALID\n    category: Test\n    message: m\n"
    p = write_rules_yaml(tmp_path, yaml_text)
    rules, errors = load_custom_rules(p)
    assert rules[0].severity == "Medium"  # フォールバック
    assert any("severity" in e for e in errors)


def test_load_missing_rules_key(tmp_path: Path) -> None:
    p = write_rules_yaml(tmp_path, "other_key: value\n")
    rules, errors = load_custom_rules(p)
    assert not rules
    assert errors


# ─── match_rules ──────────────────────────────────────────────────────────────

def test_match_basic() -> None:
    rule = make_rule(pattern="eval\\s*\\(")
    content = "result = eval(user_input)\n"
    matches = match_rules(content, "app.py", [rule])
    assert len(matches) == 1
    assert matches[0].line_number == 1
    assert "eval" in matches[0].line_content


def test_match_no_hit() -> None:
    rule = make_rule(pattern="eval\\s*\\(")
    content = "x = 1 + 2\n"
    matches = match_rules(content, "app.py", [rule])
    assert len(matches) == 0


def test_match_file_glob_filter() -> None:
    rule = make_rule(pattern="eval", file_glob="*.py")
    content = "eval(x)\n"
    # *.py に一致するファイル
    assert len(match_rules(content, "app.py", [rule])) == 1
    # *.js には一致しない
    assert len(match_rules(content, "app.js", [rule])) == 0


def test_match_max_five_hits() -> None:
    """1ルールにつき最大5件しか返さない"""
    rule = make_rule(pattern="dangerous")
    content = "\n".join(["dangerous()" for _ in range(10)])
    matches = match_rules(content, "app.py", [rule])
    assert len(matches) == 5


def test_match_multiple_rules() -> None:
    rules = [
        make_rule("CUS-001", "eval\\s*\\("),
        make_rule("CUS-002", "exec\\s*\\("),
    ]
    content = "eval(x)\nexec(y)\n"
    matches = match_rules(content, "app.py", rules)
    assert len(matches) == 2
    rule_ids = {m.rule.rule_id for m in matches}
    assert rule_ids == {"CUS-001", "CUS-002"}


# ─── matches_to_findings ──────────────────────────────────────────────────────

def test_matches_to_findings_fields() -> None:
    rule = make_rule(severity="Critical")
    content = "eval(user_input)\n"
    matches = match_rules(content, "vuln.py", [rule])
    findings = matches_to_findings(matches, "vuln.py")
    assert len(findings) == 1
    f = findings[0]
    assert f.tool == "custom"
    assert f.severity == "Critical"
    assert f.line == 1
    assert f.file_path == "vuln.py"


# ─── run_custom_rules ────────────────────────────────────────────────────────

def test_run_no_rules_file_auto(tmp_path: Path) -> None:
    """ルールファイルが自動検索でも見つからない場合 → 空リストを返す（エラーなし）"""
    # 存在しないディレクトリ内のファイルを指定 → find_rules_file が None を返す
    fake_target = tmp_path / "subdir" / "app.py"
    findings, warnings = run_custom_rules(
        "eval(x)\n", str(fake_target),
        rules_file=None,
    )
    assert findings == []
    assert warnings == []


def test_run_with_rules_file(tmp_path: Path) -> None:
    p = write_rules_yaml(tmp_path, VALID_YAML)
    content = "result = eval(user_input)\n"
    findings, warnings = run_custom_rules(content, "test.py", rules_file=p)
    assert len(findings) == 1
    assert findings[0].rule_id == "CUS-001"
    assert not warnings


# ─── find_rules_file ──────────────────────────────────────────────────────────

def test_find_rules_file_in_same_dir(tmp_path: Path) -> None:
    rules = tmp_path / ".redteam-rules.yaml"
    rules.write_text("rules: []\n")
    target = tmp_path / "app.py"
    target.write_text("x=1\n")
    found = find_rules_file(target)
    assert found == rules
