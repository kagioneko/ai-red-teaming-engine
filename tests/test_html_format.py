"""format_html のユニットテスト"""
import pytest
from redteam.formatters import format_html, _esc
from redteam.models import (
    AuditReport, AuditSummary, AttackSurfaceMap, Issue,
    AuditParameters, StaticAnalysisResult,
)


def _make_report(**kwargs) -> AuditReport:
    defaults = dict(
        scan_id="test-scan-0001",
        engine_version="0.5.1",
        file_path="app.py",
        target_type="code",
        audit_mode="deep",
        tech_stack=["Python"],
        parameters=AuditParameters(),
        static_analysis=StaticAnalysisResult(),
        summary=AuditSummary(
            total_issues=0,
            by_severity={},
            needs_human_confirmation=0,
            llm_findings=0,
            static_findings=0,
            masked_secrets_count=0,
        ),
        attack_surface=AttackSurfaceMap(),
        issues=[],
    )
    defaults.update(kwargs)
    return AuditReport(**defaults)


def _make_issue(**kwargs) -> Issue:
    defaults = dict(
        issue_id="RTE-001",
        title="Test Issue",
        severity="High",
        confidence="High",
        category="Injection",
        source="llm",
        needs_human_confirmation=True,
        priority=80,
        fingerprint="abc12345",
    )
    defaults.update(kwargs)
    return Issue(**defaults)


class TestEscape:
    def test_escapes_lt_gt(self):
        assert _esc("<script>") == "&lt;script&gt;"

    def test_escapes_ampersand(self):
        assert _esc("a&b") == "a&amp;b"

    def test_escapes_quotes(self):
        assert _esc('"hello"') == "&quot;hello&quot;"

    def test_plain_string_unchanged(self):
        assert _esc("hello world") == "hello world"


class TestFormatHtml:
    def test_returns_string(self):
        report = _make_report()
        html = format_html(report)
        assert isinstance(html, str)

    def test_contains_doctype(self):
        html = format_html(_make_report())
        assert "<!DOCTYPE html>" in html

    def test_contains_scan_id(self):
        report = _make_report(scan_id="scan-xyz-9999")
        html = format_html(report)
        assert "scan-xyz-9999" in html

    def test_contains_file_path(self):
        report = _make_report(file_path="src/auth.py")
        html = format_html(report)
        assert "src/auth.py" in html

    def test_empty_issues_shows_no_issues_message(self):
        html = format_html(_make_report())
        assert "指摘なし" in html

    def test_critical_issue_appears(self):
        issue = _make_issue(
            severity="Critical",
            title="危険なSQL injection",
            evidence="query = user_input",
        )
        report = _make_report(
            issues=[issue],
            summary=AuditSummary(
                total_issues=1,
                by_severity={"Critical": 1},
                needs_human_confirmation=1,
                llm_findings=1,
                static_findings=0,
                masked_secrets_count=0,
            ),
        )
        html = format_html(report)
        assert "危険なSQL injection" in html
        assert "Critical" in html
        assert "RTE-001" in html

    def test_severity_color_critical(self):
        issue = _make_issue(severity="Critical")
        report = _make_report(issues=[issue])
        html = format_html(report)
        assert "#e53e3e" in html  # Critical color

    def test_evidence_in_pre_block(self):
        issue = _make_issue(evidence="SELECT * FROM users WHERE id=1")
        report = _make_report(issues=[issue])
        html = format_html(report)
        assert "<pre" in html
        assert "SELECT * FROM users" in html

    def test_attack_surface_rendered(self):
        report = _make_report(
            attack_surface=AttackSurfaceMap(
                external_inputs=["POST /api/query"],
                auth_boundaries=["JWT"],
                persistence_points=[],
                tool_calls=[],
            )
        )
        html = format_html(report)
        assert "POST /api/query" in html
        assert "JWT" in html

    def test_xss_in_title_escaped(self):
        issue = _make_issue(title='<img src=x onerror="alert(1)">')
        report = _make_report(issues=[issue])
        html = format_html(report)
        assert "<img" not in html
        assert "&lt;img" in html

    def test_multiple_issues(self):
        issues = [
            _make_issue(issue_id=f"RTE-{i:03d}", severity="High", fingerprint=f"fp{i}")
            for i in range(3)
        ]
        report = _make_report(issues=issues)
        html = format_html(report)
        assert html.count("RTE-") == 3

    def test_needs_human_confirmation_shown(self):
        issue = _make_issue(needs_human_confirmation=True)
        report = _make_report(issues=[issue])
        html = format_html(report)
        assert "⚠️" in html
