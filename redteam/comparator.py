"""バックエンド比較実行 — 同一ファイルを複数LLMで監査し、検出差分を可視化する"""
from __future__ import annotations

import time
import uuid
from pathlib import Path

from .config import DEFAULT_MODEL
from .models import (
    AuditInput,
    AuditMode,
    BackendResult,
    CompareIssue,
    CompareReport,
    Issue,
    Severity,
)
from .pipeline import run_audit


def compare_backends(
    audit_input: AuditInput,
    mode: AuditMode = "deep",
    enable_static: bool = True,
    model: str = DEFAULT_MODEL,
    backends: list[str] | None = None,
    log_dir: Path | None = None,
) -> CompareReport:
    """
    同一ファイルを複数バックエンドで監査し、検出差分を比較する。

    backends を指定しない場合は利用可能なものから 2 つ自動選択。
    """
    from .llm_client import detect_available_backends

    selected = backends or detect_available_backends()[:2]
    if len(selected) < 2:
        raise ValueError(
            f"比較には2つ以上のバックエンドが必要です。利用可能: {selected}"
        )

    scan_id = str(uuid.uuid4())
    backend_results: list[BackendResult] = []

    for backend in selected:
        t0 = time.monotonic()
        try:
            report = run_audit(
                audit_input=audit_input,
                mode=mode,
                enable_static=enable_static,
                model=model,
                backend=backend,
                log_dir=None,
            )
            elapsed = time.monotonic() - t0
            backend_results.append(BackendResult(backend=backend, report=report, elapsed_sec=elapsed))
        except Exception as e:
            elapsed = time.monotonic() - t0
            # エラー時はダミーレポートで記録
            from .pipeline import _empty_report
            dummy = _empty_report(Path(audit_input.file_path or "unknown"), mode)
            backend_results.append(
                BackendResult(backend=backend, report=dummy, elapsed_sec=elapsed, error=str(e))
            )

    # 検出Issue の fingerprint ベース比較
    fp_sets: dict[str, set[str]] = {}
    fp_to_issue: dict[str, Issue] = {}

    for br in backend_results:
        fps: set[str] = set()
        for issue in br.report.issues:
            fp = issue.fingerprint or issue.compute_fingerprint()
            fps.add(fp)
            fp_to_issue.setdefault(fp, issue)
        fp_sets[br.backend] = fps

    all_fps = set().union(*fp_sets.values())
    both_fps = set.intersection(*fp_sets.values()) if fp_sets else set()

    issues_both = [
        _to_compare_issue(fp_to_issue[fp], list(fp_sets.keys()))
        for fp in both_fps
        if fp in fp_to_issue
    ]

    issues_only: dict[str, list[CompareIssue]] = {}
    for backend, fps in fp_sets.items():
        only = fps - both_fps
        issues_only[backend] = [
            _to_compare_issue(fp_to_issue[fp], [backend])
            for fp in only
            if fp in fp_to_issue
        ]

    total = len(all_fps)
    agreement_rate = (len(both_fps) / total * 100) if total else 100.0

    compare = CompareReport(
        scan_id=scan_id,
        file_path=audit_input.file_path or "",
        audit_mode=mode,
        backends=selected,
        backend_results=backend_results,
        issues_both=issues_both,
        issues_only=issues_only,
        agreement_rate=round(agreement_rate, 1),
    )

    if log_dir is not None:
        from datetime import datetime
        from .formatters import format_compare_markdown
        log_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        (log_dir / f"{ts}_{scan_id[:8]}_compare.md").write_text(
            format_compare_markdown(compare), encoding="utf-8"
        )
        (log_dir / f"{ts}_{scan_id[:8]}_compare.json").write_text(
            compare.model_dump_json(indent=2, exclude_none=True), encoding="utf-8"
        )

    return compare


def _to_compare_issue(issue: Issue, found_by: list[str]) -> CompareIssue:
    return CompareIssue(
        title=issue.title,
        severity=issue.severity,
        category=issue.category,
        fingerprint=issue.fingerprint or issue.compute_fingerprint(),
        found_by=found_by,
    )
