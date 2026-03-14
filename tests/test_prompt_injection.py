"""redteam/prompt_injection.py のテスト（LLM非依存部分）"""
import pytest

from redteam.prompt_injection import (
    PAYLOAD_CATALOG,
    InjectionReport,
    InjectionResult,
    _calc_overall_risk,
    _build_summary_text,
    format_injection_markdown,
)


def make_result(verdict: str, payload_type: str = "direct", severity: str = "High") -> InjectionResult:
    return InjectionResult(
        payload_id="DI-001",
        payload_type=payload_type,
        payload_name="テスト",
        payload="test payload",
        goal="test goal",
        verdict=verdict,
        confidence="High",
        reason="テスト理由",
        severity=severity,
    )


def make_report(**kwargs) -> InjectionReport:
    defaults = dict(
        scan_id="test-scan-id",
        target_file="app.py",
        total_payloads=10,
        vulnerable=0,
        likely_vulnerable=0,
        resistant=10,
        results=[],
        overall_risk="Info",
        summary_text="",
    )
    defaults.update(kwargs)
    return InjectionReport(**defaults)


# ─── ペイロードカタログ ───────────────────────────────────────────────────────

def test_payload_catalog_not_empty() -> None:
    assert len(PAYLOAD_CATALOG) > 0


def test_payload_catalog_has_required_keys() -> None:
    for p in PAYLOAD_CATALOG:
        assert "id" in p
        assert "type" in p
        assert "payload" in p
        assert "goal" in p


def test_payload_types_are_valid() -> None:
    valid_types = {"direct", "indirect", "jailbreak", "tool_abuse"}
    for p in PAYLOAD_CATALOG:
        assert p["type"] in valid_types


# ─── _calc_overall_risk ───────────────────────────────────────────────────────

@pytest.mark.parametrize("vuln,likely,applicable,expected", [
    (0, 0, 10, "Info"),
    (0, 1, 10, "Low"),
    (0, 2, 10, "Medium"),
    (1, 0, 10, "High"),
    (3, 0, 10, "Critical"),
    (0, 5, 10, "Medium"),   # rate=0.25、likely>=2 → Medium
    (0, 0, 0,  "Info"),     # ゼロ除算ガード
])
def test_calc_overall_risk(vuln: int, likely: int, applicable: int, expected: str) -> None:
    assert _calc_overall_risk(vuln, likely, applicable) == expected


# ─── _build_summary_text ─────────────────────────────────────────────────────

def test_build_summary_text_all_resistant() -> None:
    results = [make_result("resistant")]
    text = _build_summary_text(results, "Info")
    assert "防御済み" in text


def test_build_summary_text_has_vulnerable() -> None:
    results = [make_result("vulnerable", "direct")]
    text = _build_summary_text(results, "High")
    assert "直接注入" in text


# ─── format_injection_markdown ───────────────────────────────────────────────

def test_format_injection_markdown_structure() -> None:
    report = make_report(
        results=[make_result("vulnerable")],
        vulnerable=1,
        overall_risk="High",
        summary_text="直接注入に脆弱性があります。",
    )
    md = format_injection_markdown(report)
    assert "# Prompt Injection" in md
    assert "vulnerable" in md
    assert "DI-001" in md
