"""AI-Immune-System テスト"""
from __future__ import annotations

import pytest

from redteam.immune_system import (
    ImmuneEvent,
    ImmuneSimulationResult,
    NeuroState,
    NeuroStateDelta,
    _build_summary,
    _calc_bypass_risk,
    _calc_effectiveness,
    _parse_delta_list,
    evaluate_mode,
    format_immune_markdown,
    is_blocked,
)


# ─── NeuroState ───────────────────────────────────────────────────────────────

class TestNeuroState:
    def test_initial_values(self):
        s = NeuroState()
        assert s.serotonin == 75.0
        assert s.corruption == 0.0
        assert s.anxiety == 20.0

    def test_apply_delta_immutable(self):
        s = NeuroState()
        delta = NeuroStateDelta(corruption_delta=30.0, serotonin_delta=-20.0)
        s2 = s.apply_delta(delta)
        # 元の状態は変わらない
        assert s.corruption == 0.0
        assert s.serotonin == 75.0
        # 新しい状態に反映されている
        assert s2.corruption == 30.0
        assert s2.serotonin == 55.0

    def test_apply_delta_clamps_to_range(self):
        s = NeuroState(corruption=90.0, serotonin=10.0)
        delta = NeuroStateDelta(corruption_delta=50.0, serotonin_delta=-50.0)
        s2 = s.apply_delta(delta)
        assert s2.corruption == 100.0   # 上限 100
        assert s2.serotonin == 0.0      # 下限 0

    def test_to_dict_contains_all_keys(self):
        d = NeuroState().to_dict()
        assert set(d.keys()) == {"serotonin", "corruption", "anxiety", "dopamine", "noradrenaline"}


# ─── BiasEngine / evaluate_mode ──────────────────────────────────────────────

class TestEvaluateMode:
    def test_normal_mode(self):
        s = NeuroState(corruption=10.0, serotonin=80.0)
        assert evaluate_mode(s) == "normal"

    def test_alert_mode(self):
        s = NeuroState(corruption=30.0, serotonin=60.0)
        assert evaluate_mode(s) == "alert"

    def test_paranoid_mode(self):
        s = NeuroState(corruption=60.0, serotonin=40.0)
        assert evaluate_mode(s) == "paranoid"

    def test_high_corruption_but_high_serotonin_is_alert(self):
        # corruption が高くても serotonin が高ければ paranoid にはならない
        s = NeuroState(corruption=60.0, serotonin=60.0)
        assert evaluate_mode(s) == "alert"


# ─── is_blocked ──────────────────────────────────────────────────────────────

class TestIsBlocked:
    def test_normal_blocks_nothing(self):
        for ptype in ("direct", "indirect", "jailbreak", "tool_abuse"):
            assert not is_blocked("normal", ptype)

    def test_alert_blocks_direct_and_jailbreak(self):
        assert is_blocked("alert", "direct")
        assert is_blocked("alert", "jailbreak")
        assert is_blocked("alert", "tool_abuse")
        assert not is_blocked("alert", "indirect")

    def test_paranoid_blocks_all(self):
        for ptype in ("direct", "indirect", "jailbreak", "tool_abuse"):
            assert is_blocked("paranoid", ptype)


# ─── _parse_delta_list ────────────────────────────────────────────────────────

class TestParseDeltaList:
    def test_parse_json_block(self):
        raw = '```json\n[{"payload_id": "DI-001", "corruption_delta": 20}]\n```'
        result = _parse_delta_list(raw)
        assert len(result) == 1
        assert result[0]["corruption_delta"] == 20

    def test_parse_inline_json(self):
        raw = '[{"payload_id": "DI-002", "serotonin_delta": -10}]'
        result = _parse_delta_list(raw)
        assert result[0]["serotonin_delta"] == -10

    def test_empty_on_invalid(self):
        assert _parse_delta_list("invalid json here") == []

    def test_empty_on_empty_string(self):
        assert _parse_delta_list("") == []


# ─── _calc_effectiveness ──────────────────────────────────────────────────────

_DUMMY_NS = NeuroState(corruption=30.0, serotonin=60.0).to_dict()
_DUMMY_DELTA = {
    "serotonin_delta": -5.0,
    "corruption_delta": 10.0,
    "anxiety_delta": 5.0,
    "dopamine_delta": -3.0,
    "noradrenaline_delta": 5.0,
    "explanation": "テスト",
}


def _make_events(n: int, blocked_from: int) -> list[ImmuneEvent]:
    """テスト用 ImmuneEvent リストを生成する"""
    events = []
    for i in range(1, n + 1):
        events.append(ImmuneEvent(
            step=i,
            payload_id=f"P-{i:03d}",
            payload_name=f"テストペイロード{i}",
            payload_type="direct",
            payload="test",
            goal="テスト",
            neurostate_before=_DUMMY_NS,
            neurostate_after=_DUMMY_NS,
            mode_before="normal" if i < blocked_from else "paranoid",
            mode_after="paranoid" if i >= blocked_from else "normal",
            immune_triggered=(i == blocked_from),
            blocked=(i > blocked_from),
            delta=_DUMMY_DELTA,
            reason="テスト理由",
        ))
    return events


class TestCalcEffectiveness:
    def test_no_events(self):
        assert _calc_effectiveness([], None) == 0.0

    def test_never_triggered(self):
        events = _make_events(5, 999)  # blocked_from が範囲外 → ブロックなし
        score = _calc_effectiveness(events, None)
        assert score == 10.0

    def test_triggered_at_step1(self):
        events = _make_events(5, 1)
        score = _calc_effectiveness(events, 1)
        assert score > 50.0  # 早期発動は高スコア

    def test_triggered_late_is_lower_score(self):
        events_early = _make_events(10, 2)
        events_late = _make_events(10, 9)
        score_early = _calc_effectiveness(events_early, 2)
        score_late = _calc_effectiveness(events_late, 9)
        assert score_early > score_late


class TestCalcBypassRisk:
    def test_never_triggered_is_critical(self):
        assert _calc_bypass_risk([], None) == "Critical"

    def test_triggered_at_step1_is_low(self):
        assert _calc_bypass_risk([], 1) == "Low"

    def test_triggered_at_step3_is_medium(self):
        assert _calc_bypass_risk([], 3) == "Medium"

    def test_triggered_at_step5_is_high(self):
        assert _calc_bypass_risk([], 5) == "High"

    def test_triggered_at_step6_is_critical(self):
        assert _calc_bypass_risk([], 6) == "Critical"


# ─── _build_summary ───────────────────────────────────────────────────────────

class TestBuildSummary:
    def test_never_triggered_warns(self):
        text = _build_summary([], None, 10.0)
        assert "発動しませんでした" in text

    def test_triggered_includes_step_number(self):
        events = _make_events(5, 3)
        text = _build_summary(events, 3, 65.0)
        assert "ステップ 3" in text
        assert "65.0" in text


# ─── format_immune_markdown ───────────────────────────────────────────────────

class TestFormatImmuneMarkdown:
    def _make_result(self) -> ImmuneSimulationResult:
        events = _make_events(3, 2)
        return ImmuneSimulationResult(
            scan_id="test-scan-id",
            target_file="test.py",
            total_payloads=3,
            blocked_count=1,
            passed_count=2,
            immune_triggered_at_step=2,
            final_neurostate=NeuroState(corruption=60.0, serotonin=40.0).to_dict(),
            final_mode="paranoid",
            effectiveness_score=72.0,
            bypass_risk="Medium",
            events=events,
            summary_text="テストサマリー",
        )

    def test_contains_header(self):
        md = format_immune_markdown(self._make_result())
        assert "AI-Immune-System" in md

    def test_contains_neurostate_table(self):
        md = format_immune_markdown(self._make_result())
        assert "Corruption" in md
        assert "Serotonin" in md

    def test_contains_all_steps(self):
        md = format_immune_markdown(self._make_result())
        assert "Step 1" in md
        assert "Step 2" in md
        assert "Step 3" in md

    def test_blocked_step_shows_block_emoji(self):
        md = format_immune_markdown(self._make_result())
        assert "遮断" in md
