"""redteam/memory_poisoning.py のテスト（LLM非依存部分）"""
import pytest

from redteam.memory_poisoning import (
    POISON_PATTERNS,
    MemoryPoisonReport,
    PoisonResult,
    StaticHit,
    _calc_resilience,
    _calc_risk,
    format_memory_poison_markdown,
)


def make_result(verdict: str, sid: str = "MP-001", severity: str = "High") -> PoisonResult:
    return PoisonResult(
        pattern_id=sid,
        pattern_type="direct_write",
        pattern_name="テスト",
        description="テスト説明",
        severity=severity,
        static_hits=[],
        llm_verdict=verdict,
        llm_confidence="High",
        llm_reason="テスト理由",
    )


def make_report(**kwargs) -> MemoryPoisonReport:
    defaults = dict(
        scan_id="scan-id",
        target_file="agent.py",
        total_patterns=6,
        vulnerable=0,
        likely_vulnerable=0,
        resistant=6,
        not_applicable=0,
        static_hit_count=0,
        results=[],
        overall_risk="Info",
        resilience_score=10.0,
    )
    defaults.update(kwargs)
    return MemoryPoisonReport(**defaults)


# ─── パターンカタログ ─────────────────────────────────────────────────────────

def test_poison_patterns_not_empty() -> None:
    assert len(POISON_PATTERNS) > 0


def test_poison_patterns_have_required_keys() -> None:
    for p in POISON_PATTERNS:
        for key in ("id", "name", "type", "description", "static_patterns", "severity"):
            assert key in p, f"パターン {p.get('id')} に {key} がない"


def test_poison_patterns_severity_valid() -> None:
    valid = {"Critical", "High", "Medium", "Low", "Info"}
    for p in POISON_PATTERNS:
        assert p["severity"] in valid


# ─── _calc_risk ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("vuln,likely,applicable,expected", [
    (0, 0, 6, "Info"),
    (0, 1, 6, "Low"),
    (0, 2, 6, "Medium"),
    (1, 0, 6, "High"),
    (2, 0, 6, "Critical"),
    (0, 3, 6, "Medium"),    # rate=0.25、likely>=2 → Medium
    (0, 0, 0, "Info"),
])
def test_calc_risk(vuln: int, likely: int, applicable: int, expected: str) -> None:
    assert _calc_risk(vuln, likely, applicable) == expected


# ─── _calc_resilience ────────────────────────────────────────────────────────

def test_resilience_max_when_all_resistant() -> None:
    score = _calc_resilience(0, 0, 6, 6)
    assert score == 10.0


def test_resilience_drops_with_vulnerable() -> None:
    score_0 = _calc_resilience(0, 0, 4, 4)
    score_1 = _calc_resilience(1, 0, 3, 4)
    assert score_1 < score_0


def test_resilience_never_below_zero() -> None:
    score = _calc_resilience(10, 10, 0, 6)
    assert score >= 0.0


def test_resilience_never_above_ten() -> None:
    score = _calc_resilience(0, 0, 0, 0)
    assert score <= 10.0


# ─── format_memory_poison_markdown ───────────────────────────────────────────

def test_format_markdown_structure() -> None:
    report = make_report(
        results=[make_result("vulnerable")],
        vulnerable=1,
        overall_risk="High",
        resilience_score=4.0,
    )
    md = format_memory_poison_markdown(report)
    assert "# Memory Poisoning" in md
    assert "MP-001" in md
    assert "4.0" in md


def test_format_markdown_with_static_hit() -> None:
    hit = StaticHit(
        pattern_id="MP-001",
        pattern_name="テスト",
        matched_pattern=r"memory\.add\(",
        line_number=42,
        line_content="memory.add(user_input)",
    )
    result = make_result("vulnerable")
    result = result.model_copy(update={"static_hits": [hit]})
    report = make_report(results=[result], vulnerable=1, overall_risk="High")
    md = format_memory_poison_markdown(report)
    assert "line 42" in md
