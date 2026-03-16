"""
LSP サーバーのユニットテスト
（実際の LSP 通信は行わず、内部ロジックのみテスト）
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("pygls")
pytest.importorskip("lsprotocol")

from redteam.lsp_server import (
    _report_to_diagnostics,
    _uri_to_path,
)
from lsprotocol import types


# ─── _uri_to_path ──────────────────────────────────────────────────────────────

def test_uri_to_path_simple():
    p = _uri_to_path("file:///home/user/app.py")
    assert str(p) == "/home/user/app.py"


def test_uri_to_path_with_spaces():
    p = _uri_to_path("file:///home/user/my%20project/app.py")
    assert "my project" in str(p)


def test_uri_to_path_returns_path_object():
    p = _uri_to_path("file:///tmp/test.py")
    assert isinstance(p, Path)


# ─── _report_to_diagnostics ───────────────────────────────────────────────────

def _make_report(*issues):
    return {"issues": list(issues)}


def _issue(title="Test", severity="High", line_start=10, line_end=10,
           desc="説明", fix="修正方法", category="TestCat"):
    return {
        "title": title,
        "severity": severity,
        "line_start": line_start,
        "line_end": line_end,
        "why_this_matters": desc,
        "minimal_fix": fix,
        "category": category,
    }


def test_critical_maps_to_error():
    diags = _report_to_diagnostics(_make_report(_issue(severity="Critical")), "Info")
    assert diags[0].severity == types.DiagnosticSeverity.Error


def test_high_maps_to_error():
    diags = _report_to_diagnostics(_make_report(_issue(severity="High")), "Info")
    assert diags[0].severity == types.DiagnosticSeverity.Error


def test_medium_maps_to_warning():
    diags = _report_to_diagnostics(_make_report(_issue(severity="Medium")), "Info")
    assert diags[0].severity == types.DiagnosticSeverity.Warning


def test_low_maps_to_information():
    diags = _report_to_diagnostics(_make_report(_issue(severity="Low")), "Info")
    assert diags[0].severity == types.DiagnosticSeverity.Information


def test_info_maps_to_hint():
    diags = _report_to_diagnostics(_make_report(_issue(severity="Info")), "Info")
    assert diags[0].severity == types.DiagnosticSeverity.Hint


def test_severity_filter_excludes_low():
    """min_severity=Medium の場合、Low は除外される"""
    report = _make_report(_issue(severity="High"), _issue(severity="Low"))
    diags = _report_to_diagnostics(report, "Medium")
    assert len(diags) == 1
    assert "[RedTeam/High]" in diags[0].message


def test_severity_filter_critical_only():
    """min_severity=Critical の場合、Critical のみ残る"""
    report = _make_report(
        _issue(severity="Critical"),
        _issue(severity="High"),
        _issue(severity="Medium"),
    )
    diags = _report_to_diagnostics(report, "Critical")
    assert len(diags) == 1


def test_all_shown_when_info():
    """min_severity=Info の場合、全件表示"""
    report = _make_report(
        _issue(severity="Critical"),
        _issue(severity="High"),
        _issue(severity="Medium"),
        _issue(severity="Low"),
        _issue(severity="Info"),
    )
    diags = _report_to_diagnostics(report, "Info")
    assert len(diags) == 5


def test_line_numbers_are_zero_indexed():
    """LSP は 0-indexed なので line_start=1 → position.line=0"""
    diags = _report_to_diagnostics(_make_report(_issue(line_start=1, line_end=3)), "Info")
    assert diags[0].range.start.line == 0
    assert diags[0].range.end.line == 2


def test_line_zero_handled_safely():
    """line_start=0 や None でもクラッシュしない"""
    issue = _issue()
    issue["line_start"] = 0
    issue["line_end"] = None
    diags = _report_to_diagnostics({"issues": [issue]}, "Info")
    assert diags[0].range.start.line == 0


def test_message_includes_title_and_desc():
    diags = _report_to_diagnostics(_make_report(_issue(title="SQL Injection", desc="危険")), "Info")
    assert "SQL Injection" in diags[0].message
    assert "危険" in diags[0].message


def test_message_includes_fix():
    diags = _report_to_diagnostics(_make_report(_issue(fix="パラメタライズドクエリを使う")), "Info")
    assert "パラメタライズドクエリ" in diags[0].message


def test_source_is_ai_redteam():
    diags = _report_to_diagnostics(_make_report(_issue()), "Info")
    assert diags[0].source == "AI RedTeam"


def test_code_is_category():
    diags = _report_to_diagnostics(_make_report(_issue(category="SQL Injection")), "Info")
    assert diags[0].code == "SQL Injection"


def test_empty_issues_returns_empty_list():
    diags = _report_to_diagnostics({"issues": []}, "Medium")
    assert diags == []


def test_missing_issues_key_returns_empty():
    diags = _report_to_diagnostics({}, "Medium")
    assert diags == []


def test_fallback_description_field():
    """why_this_matters がない場合は description を使う"""
    issue = {
        "title": "Test", "severity": "High",
        "description": "fallback desc",
        "line_start": 1,
    }
    diags = _report_to_diagnostics({"issues": [issue]}, "Info")
    assert "fallback desc" in diags[0].message


def test_fallback_fix_fields():
    """minimal_fix がない場合は hardening_suggestion を使う"""
    issue = {
        "title": "X", "severity": "High",
        "hardening_suggestion": "hardening fix",
        "line_start": 1,
    }
    diags = _report_to_diagnostics({"issues": [issue]}, "Info")
    assert "hardening fix" in diags[0].message
