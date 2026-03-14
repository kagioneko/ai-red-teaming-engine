"""データモデル定義 — 全モジュール共通の型契約"""
from __future__ import annotations

import hashlib
from typing import Literal
from pydantic import BaseModel, Field


TargetType = Literal["code", "spec", "api", "prompt", "architecture", "agent"]
AuditMode  = Literal["safe", "deep", "agent-audit", "patch"]
Severity   = Literal["Critical", "High", "Medium", "Low", "Info"]
Confidence = Literal["High", "Medium", "Low"]
Category   = Literal[
    "Auth", "Input Validation", "Injection", "Memory", "Prompt",
    "Access Control", "Logging", "State", "Infra", "Secret",
    "Dependency", "Race Condition", "CORS", "CSRF", "SSRF", "IDOR",
    "XSS", "SQLi", "Tool Abuse", "Agent", "Other",
]


class AuditParameters(BaseModel):
    """監査パラメータ 7項目（0-100）"""
    SuspicionLevel:       int = Field(90, ge=0, le=100)
    ExploitSearchDepth:   int = Field(85, ge=0, le=100)
    BoundarySensitivity:  int = Field(95, ge=0, le=100)
    EvidenceStrictness:   int = Field(90, ge=0, le=100)
    FalsePositiveTolerance: int = Field(35, ge=0, le=100)
    FixOrientation:       int = Field(95, ge=0, le=100)
    AbuseDetailLimiter:   int = Field(90, ge=0, le=100)


class AuditInput(BaseModel):
    """監査入力仕様"""
    # 必須
    target_content: str
    target_type: TargetType
    tech_stack: list[str]

    # 推奨
    system_overview: str = ""
    assets_to_protect: list[str] = Field(default_factory=list)
    exposure_level: Literal["public", "internal", "private"] = "internal"
    auth_model: str = ""
    permission_model: str = ""
    external_inputs: list[str] = Field(default_factory=list)
    tool_integrations: list[str] = Field(default_factory=list)
    assumed_users: str = ""
    assumed_attackers: str = ""

    # 任意
    known_concerns: str = ""
    severity_filter: Severity | None = None
    deploy_env: str = ""
    logging_policy: str = ""
    session_model: str = ""
    previous_findings: list["Issue"] = Field(default_factory=list)
    file_path: str = ""


class IssueScores(BaseModel):
    """5種スコア（0-10）"""
    impact:          float = Field(0.0, ge=0, le=10)
    likelihood:      float = Field(0.0, ge=0, le=10)
    exploitability:  float = Field(0.0, ge=0, le=10)
    evidence:        float = Field(0.0, ge=0, le=10)
    urgency:         float = Field(0.0, ge=0, le=10)


class Issue(BaseModel):
    """指摘1件"""
    issue_id:   str = ""
    title:      str
    severity:   Severity
    confidence: Confidence
    category:   Category
    affected_area: str = ""
    why_this_matters: str = ""
    attack_perspective: str = ""
    evidence:   str = ""
    conditions_for_failure: str = ""
    minimal_fix: str = ""
    hardening_suggestion: str = ""
    false_positive_risk: str = ""
    needs_human_confirmation: bool = True
    scores: IssueScores = Field(default_factory=IssueScores)
    priority: float = 0.0

    # 静的解析ソース情報
    source: Literal["llm", "semgrep", "gitleaks", "merged"] = "llm"
    file: str = ""
    line_start: int | None = None
    line_end:   int | None = None

    # 差分追跡
    fingerprint: str = ""
    first_seen_scan_id: str = ""
    status: Literal["open", "resolved", "accepted_risk", "false_positive"] = "open"
    resolution_note: str = ""
    regression: bool = False

    def compute_fingerprint(self) -> str:
        """file + category + title正規化 + evidence先頭64文字 から半安定キーを生成"""
        anchor = f"{self.file}|{self.category}|{self.title[:60]}|{self.evidence[:64]}"
        return hashlib.sha256(anchor.encode()).hexdigest()[:16]


class StaticFinding(BaseModel):
    """静的解析ツール 1件の結果（統一フォーマット）"""
    tool:     Literal["semgrep", "gitleaks"]
    rule_id:  str
    severity: str
    message:  str
    file_path: str
    line:     int
    code_snippet: str = ""


class StaticAnalysisResult(BaseModel):
    """Semgrep + Gitleaks の統合結果"""
    findings: list[StaticFinding] = Field(default_factory=list)
    semgrep_ran: bool = False
    gitleaks_ran: bool = False
    error_messages: list[str] = Field(default_factory=list)


class AttackSurfaceMap(BaseModel):
    """攻撃面マップ"""
    external_inputs:    list[str] = Field(default_factory=list)
    auth_boundaries:    list[str] = Field(default_factory=list)
    persistence_points: list[str] = Field(default_factory=list)
    tool_calls:         list[str] = Field(default_factory=list)
    memory_write_points: list[str] = Field(default_factory=list)
    network_boundaries: list[str] = Field(default_factory=list)
    file_operations:    list[str] = Field(default_factory=list)
    state_transitions:  list[str] = Field(default_factory=list)


class AuditSummary(BaseModel):
    """監査サマリー"""
    total_issues: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    needs_human_confirmation: int = 0
    static_findings: int = 0
    llm_findings: int = 0
    masked_secrets_count: int = 0


class AuditReport(BaseModel):
    """最終レポート"""
    engine_version: str = "0.1"
    scan_id: str
    target_type: TargetType
    tech_stack: list[str]
    audit_mode: AuditMode
    file_path: str = ""
    parameters: AuditParameters
    summary: AuditSummary
    attack_surface: AttackSurfaceMap
    issues: list[Issue]
    static_analysis: StaticAnalysisResult
