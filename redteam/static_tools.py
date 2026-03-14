"""静的解析ツール連携 (Semgrep / Gitleaks) — Analysis Layer"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from .models import StaticFinding, StaticAnalysisResult


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def run_semgrep(file_path: Path) -> tuple[list[StaticFinding], str | None]:
    """Semgrepを実行し、結果をStaticFindingリストで返す"""
    if not _tool_available("semgrep"):
        return [], "semgrep not installed"

    try:
        result = subprocess.run(
            ["semgrep", "scan", "--config", "auto", "--json", "--quiet", str(file_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        raw = result.stdout.strip()
        if not raw:
            return [], None

        data = json.loads(raw)
        findings: list[StaticFinding] = []

        for r in data.get("results", []):
            severity_map = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}
            raw_sev = r.get("extra", {}).get("severity", "WARNING")
            findings.append(
                StaticFinding(
                    tool="semgrep",
                    rule_id=r.get("check_id", "unknown"),
                    severity=severity_map.get(raw_sev, "Medium"),
                    message=r.get("extra", {}).get("message", ""),
                    file_path=r.get("path", str(file_path)),
                    line=r.get("start", {}).get("line", 0),
                    code_snippet=r.get("extra", {}).get("lines", ""),
                )
            )
        return findings, None

    except subprocess.TimeoutExpired:
        return [], "semgrep timed out"
    except json.JSONDecodeError as e:
        return [], f"semgrep JSON parse error: {e}"
    except Exception as e:
        return [], f"semgrep error: {e}"


def run_gitleaks(file_path: Path) -> tuple[list[StaticFinding], str | None]:
    """
    Gitleaksでシークレット検出を実行する。
    単一ファイルの場合は一時ディレクトリにコピーして検査する。
    """
    if not _tool_available("gitleaks"):
        return [], "gitleaks not installed"

    try:
        # gitleaksはディレクトリまたはgitリポジトリを対象にするため、
        # 単一ファイルの場合は一時ディレクトリを作って検査
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir) / file_path.name
            tmp_path.write_text(file_path.read_text(errors="replace"), encoding="utf-8")

            result = subprocess.run(
                [
                    "gitleaks", "detect",
                    "--source", tmpdir,
                    "--no-git",
                    "--report-format", "json",
                    "--report-path", "/dev/stdout",
                    "--exit-code", "0",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            raw = result.stdout.strip()
            if not raw or raw == "null":
                return [], None

            data = json.loads(raw)
            if not isinstance(data, list):
                return [], None

            findings: list[StaticFinding] = []
            for r in data:
                findings.append(
                    StaticFinding(
                        tool="gitleaks",
                        rule_id=r.get("RuleID", "unknown"),
                        severity="High",  # gitleaksはシークレット検出のため常にHigh
                        message=r.get("Description", r.get("RuleID", "")),
                        file_path=r.get("File", str(file_path)),
                        line=r.get("StartLine", 0),
                        code_snippet=r.get("Match", ""),
                    )
                )
            return findings, None

    except subprocess.TimeoutExpired:
        return [], "gitleaks timed out"
    except json.JSONDecodeError as e:
        return [], f"gitleaks JSON parse error: {e}"
    except Exception as e:
        return [], f"gitleaks error: {e}"


def run_static_analysis(
    content: str,
    file_path: str = "",
    target_type: str = "code",
) -> StaticAnalysisResult:
    """
    コード文字列に対して静的解析を実行する。
    一時ファイルに書き出してツールを実行し、結果を統合する。
    """
    result = StaticAnalysisResult()

    # spec/prompt/architecture はコード解析ツールをスキップ
    if target_type not in ("code", "api"):
        return result

    suffix = _guess_suffix(file_path)

    with tempfile.NamedTemporaryFile(
        mode="w",
        suffix=suffix,
        delete=False,
        encoding="utf-8",
    ) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        # Semgrep（全言語対応）
        semgrep_findings, semgrep_err = run_semgrep(tmp_path)
        result.semgrep_ran = semgrep_err is None
        result.findings.extend(semgrep_findings)
        if semgrep_err:
            result.error_messages.append(f"[semgrep] {semgrep_err}")

        # Gitleaks（シークレット検出）
        gitleaks_findings, gitleaks_err = run_gitleaks(tmp_path)
        result.gitleaks_ran = gitleaks_err is None
        result.findings.extend(gitleaks_findings)
        if gitleaks_err:
            result.error_messages.append(f"[gitleaks] {gitleaks_err}")

    finally:
        tmp_path.unlink(missing_ok=True)

    # 重複排除（同一行・同一ルール）
    result.findings = _dedup_findings(result.findings)
    return result


def _guess_suffix(file_path: str) -> str:
    if file_path:
        return Path(file_path).suffix or ".txt"
    return ".py"  # デフォルトはPythonとして扱う


def _dedup_findings(findings: list[StaticFinding]) -> list[StaticFinding]:
    """同一tool・rule_id・lineの重複を除去"""
    seen: set[tuple] = set()
    unique: list[StaticFinding] = []
    for f in findings:
        key = (f.tool, f.rule_id, f.line)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def format_static_for_prompt(result: StaticAnalysisResult) -> str:
    """静的解析結果をLLMプロンプトに注入可能な形式にフォーマット"""
    if not result.findings:
        return "静的解析: 検出なし"

    lines = []
    for f in result.findings:
        lines.append(
            f"[{f.tool.upper()}] {f.rule_id} ({f.severity}) "
            f"Line {f.line}: {f.message}"
            + (f"\n  Code: {f.code_snippet[:120]}" if f.code_snippet else "")
        )
    return "\n".join(lines)
