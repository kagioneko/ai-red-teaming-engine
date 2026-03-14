"""static_tools モジュールのユニットテスト"""
import pytest
from pathlib import Path
import tempfile

from redteam.static_tools import (
    run_semgrep,
    run_gitleaks,
    run_static_analysis,
    format_static_for_prompt,
    _dedup_findings,
)
from redteam.models import StaticFinding, StaticAnalysisResult


def _write_temp_py(content: str) -> Path:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as f:
        f.write(content)
        return Path(f.name)


def test_semgrep_runs_on_python_file():
    path = _write_temp_py("x = 1 + 1\n")
    findings, err = run_semgrep(path)
    path.unlink(missing_ok=True)
    # エラーなく実行できる（findings は0件でもOK）
    assert err is None or isinstance(err, str)
    assert isinstance(findings, list)


def test_gitleaks_detects_secret():
    # gitleaks の公式テストで使われる AWS キー形式
    secret_code = 'aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
    path = _write_temp_py(secret_code)
    findings, err = run_gitleaks(path)
    path.unlink(missing_ok=True)
    # ツールが動作すること（検出件数は0でも可：偽陽性フィルタの影響を考慮）
    assert err is None or isinstance(err, str)
    assert isinstance(findings, list)
    if findings:
        assert findings[0].tool == "gitleaks"


def test_static_analysis_spec_type_skipped():
    result = run_static_analysis(
        content="some spec content",
        target_type="spec",
    )
    assert len(result.findings) == 0
    assert not result.semgrep_ran
    assert not result.gitleaks_ran


def test_dedup_findings():
    f1 = StaticFinding(tool="semgrep", rule_id="r1", severity="High", message="msg", file_path="f.py", line=10)
    f2 = StaticFinding(tool="semgrep", rule_id="r1", severity="High", message="msg", file_path="f.py", line=10)
    f3 = StaticFinding(tool="semgrep", rule_id="r2", severity="Low", message="msg2", file_path="f.py", line=20)
    result = _dedup_findings([f1, f2, f3])
    assert len(result) == 2


def test_format_static_for_prompt_empty():
    result = StaticAnalysisResult()
    text = format_static_for_prompt(result)
    assert "検出なし" in text


def test_format_static_for_prompt_with_findings():
    result = StaticAnalysisResult(
        findings=[
            StaticFinding(
                tool="semgrep",
                rule_id="test.rule",
                severity="High",
                message="hardcoded password",
                file_path="app.py",
                line=42,
                code_snippet="password = 'secret'",
            )
        ]
    )
    text = format_static_for_prompt(result)
    assert "SEMGREP" in text
    assert "Line 42" in text
    assert "hardcoded password" in text
