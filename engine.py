#!/usr/bin/env python3
"""
AI-Red-Teaming-Engine CLI エントリポイント v0.2

使用例:
  # 単一ファイル監査
  python engine.py --file app.py --mode deep --backend claude

  # ディレクトリ丸ごと監査
  python engine.py --dir src/ --mode deep --backend claude

  # SARIF出力（GitHub Security Tab 対応）
  python engine.py --file app.py --format sarif -o results.sarif

  # バックエンド比較（claude vs gemini）
  python engine.py --file app.py --compare

  # ディレクトリ監査 + SARIF出力
  python engine.py --dir src/ --format sarif -o results.sarif
"""
import json
import sys
from pathlib import Path

import click

sys.path.insert(0, str(Path(__file__).parent))

from redteam.config import DEFAULT_MODEL
from redteam.comparator import compare_backends
from redteam.ignorer import IgnoreRules, load_ignore_rules
from redteam.multi_agent import run_multi_agent_audit
from redteam.prompt_injection import format_injection_markdown, run_injection_simulation
from redteam.memory_poisoning import format_memory_poison_markdown, run_memory_poison_test
from redteam.watcher import watch
from redteam.formatters import (
    format_compare_markdown,
    format_dir_json,
    format_dir_markdown,
    format_dir_sarif,
    format_json,
    format_markdown,
    format_sarif,
)
from redteam.llm_client import detect_available_backends
from redteam.models import AuditInput, AuditMode, Severity, TargetType
from redteam.pipeline import run_audit, run_dir_audit

LOG_DIR = Path(__file__).parent / "logs"

_TYPE_CHOICES = ["code", "spec", "api", "prompt", "architecture", "agent"]
_MODE_CHOICES = ["safe", "deep", "agent-audit", "patch"]
_FORMAT_CHOICES = ["text", "json", "sarif", "both"]
_BACKEND_CHOICES = ["api", "claude", "gemini", "codex"]


@click.command()
@click.option(
    "--file", "-f", "file_path",
    default=None,
    help="監査対象のファイルパス（--dir と排他）",
)
@click.option(
    "--dir", "-d", "dir_path",
    default=None,
    help="監査対象のディレクトリパス（--file と排他）",
)
@click.option(
    "--mode", "-m",
    default="deep",
    type=click.Choice(_MODE_CHOICES),
    show_default=True,
    help="監査モード: safe / deep / agent-audit / patch",
)
@click.option(
    "--type", "target_type",
    default=None,
    type=click.Choice(_TYPE_CHOICES),
    help="対象種別（省略時は拡張子から自動判定）",
)
@click.option(
    "--tech-stack",
    default=None,
    help="技術スタック（カンマ区切り、例: Python,FastAPI,Firebase）",
)
@click.option(
    "--format", "output_format",
    default="text",
    type=click.Choice(_FORMAT_CHOICES),
    show_default=True,
    help="出力形式: text（Markdown）/ json / sarif / both",
)
@click.option(
    "--output", "-o",
    default=None,
    help="出力ファイルパス（省略時はstdout）",
)
@click.option(
    "--backend", "-b",
    default=None,
    type=click.Choice(_BACKEND_CHOICES),
    help="LLMバックエンド（省略時は自動選択）",
)
@click.option(
    "--compare",
    is_flag=True,
    default=False,
    help="複数バックエンドで比較実行（--file 時のみ有効）",
)
@click.option(
    "--multi-agent",
    is_flag=True,
    default=False,
    help="4エージェント構成で監査（Attacker/Skeptic/Defender/Judge）。高精度だが時間がかかる（--file 時のみ）",
)
@click.option(
    "--injection-test",
    is_flag=True,
    default=False,
    help="Prompt Injection シミュレーションを実行（--file 時のみ。LLMプロンプト・エージェントコードに有効）",
)
@click.option(
    "--injection-types",
    default=None,
    help="注入ペイロード種別を絞り込む（カンマ区切り: direct,indirect,jailbreak,tool_abuse）",
)
@click.option(
    "--memory-poison",
    is_flag=True,
    default=False,
    help="Memory Poisoning 耐性試験を実行（--file 時のみ。エージェント・RAGコードに有効）",
)
@click.option(
    "--watch", "watch_mode",
    is_flag=True,
    default=False,
    help="ファイル変更を監視して自動再監査（--file / --dir と組み合わせて使用）",
)
@click.option(
    "--compare-backends", "compare_backends_str",
    default=None,
    help="比較するバックエンドをカンマ区切りで指定（例: claude,gemini）",
)
@click.option(
    "--model",
    default=DEFAULT_MODEL,
    show_default=True,
    help="使用するモデル（api バックエンド時のみ有効）",
)
@click.option(
    "--no-static",
    is_flag=True,
    default=False,
    help="静的解析（Semgrep/Gitleaks）をスキップ",
)
@click.option(
    "--severity-filter",
    default=None,
    type=click.Choice(["Critical", "High", "Medium", "Low", "Info"]),
    help="指定severity以上の指摘のみ表示",
)
@click.option(
    "--system-overview",
    default="",
    help="システム概要の説明（監査精度向上に貢献）",
)
@click.option(
    "--exposure",
    default="internal",
    type=click.Choice(["public", "internal", "private"]),
    show_default=True,
    help="外部公開範囲",
)
@click.option(
    "--ext",
    default=None,
    help="ディレクトリ監査で対象とする拡張子（カンマ区切り、例: .py,.js）",
)
@click.option(
    "--baseline",
    default=None,
    help="前回の baseline JSON パス（--mode patch と組み合わせて差分追跡）",
)
@click.option(
    "--save-baseline",
    default=None,
    help="今回の結果を baseline JSON として保存するパス（次回 --baseline に指定する）",
)
@click.option(
    "--ignore-file",
    default=None,
    help=".redteam-ignore ファイルのパス（省略時はカレント→対象ディレクトリを自動検索）",
)
@click.option(
    "--rules-file",
    "rules_file",
    default=None,
    help=".redteam-rules.yaml のパス（省略時は対象ディレクトリ→カレント→~/ を自動検索）",
)
@click.option(
    "--fail-on",
    default=None,
    type=click.Choice(["Critical", "High", "Medium", "Low", "Info"]),
    help="指定severity以上の指摘が1件でもあれば exit 1（CI/CD でのビルド失敗制御用）",
)
@click.option(
    "--save-log/--no-save-log",
    default=True,
    show_default=True,
    help="logs/ ディレクトリにレポートを保存（--no-save-log で無効）",
)
def main(
    file_path: str | None,
    dir_path: str | None,
    mode: str,
    target_type: str | None,
    tech_stack: str | None,
    output_format: str,
    output: str | None,
    backend: str | None,
    compare: bool,
    multi_agent: bool,
    injection_test: bool,
    injection_types: str | None,
    memory_poison: bool,
    watch_mode: bool,
    compare_backends_str: str | None,
    model: str,
    no_static: bool,
    severity_filter: str | None,
    system_overview: str,
    exposure: str,
    ext: str | None,
    baseline: str | None,
    save_baseline: str | None,
    ignore_file: str | None,
    rules_file: str | None,
    fail_on: str | None,
    save_log: bool,
) -> None:
    """
    AI-Red-Teaming-Engine — 防御目的の敵対的セキュリティ監査エンジン (v0.4)

    ⚠️  このツールはプロトタイプ版です。全ての指摘は人間による最終確認が必要です。
    """
    # baseline（前回 findings）の読み込み
    previous_findings = _load_baseline(baseline)
    if previous_findings:
        click.echo(f"📋 baseline 読み込み: {len(previous_findings)} 件の前回 findings", err=True)
        if mode != "patch":
            click.echo("  ℹ️  --mode patch を推奨します（差分追跡が有効になります）", err=True)

    # .redteam-ignore の読み込み（明示指定 → カレントdir → 対象dir の順で探索）
    rules = _load_ignore(ignore_file, file_path, dir_path)
    if not rules.is_empty:
        click.echo(f"🚫 ignore ルール読み込み済み", err=True)

    # --file / --dir のどちらか必須
    if not file_path and not dir_path:
        click.echo("エラー: --file または --dir のどちらかを指定してください。", err=True)
        sys.exit(1)
    if file_path and dir_path:
        click.echo("エラー: --file と --dir は同時に指定できません。", err=True)
        sys.exit(1)

    # compare は --file のみ有効
    if compare and dir_path:
        click.echo("エラー: --compare は --file 指定時のみ有効です。", err=True)
        sys.exit(1)

    stack: list[str] = [s.strip() for s in tech_stack.split(",")] if tech_stack else []

    # バックエンドの自動選択
    selected_backend = backend
    if selected_backend is None and not compare:
        available = detect_available_backends()
        if not available:
            click.echo(
                "エラー: 使用可能なLLMバックエンドがありません。\n"
                "  ANTHROPIC_API_KEY を設定するか、\n"
                "  claude / gemini / codex コマンドをインストールしてください。",
                err=True,
            )
            sys.exit(1)
        selected_backend = available[0]

    # ─── ディレクトリ監査 ────────────────────────────────────────────────
    if dir_path:
        target = Path(dir_path)
        if not target.is_dir():
            click.echo(f"エラー: ディレクトリが見つかりません: {dir_path}", err=True)
            sys.exit(1)

        extensions: set[str] | None = None
        if ext:
            extensions = {e.strip() if e.strip().startswith(".") else f".{e.strip()}" for e in ext.split(",")}

        click.echo(f"📂 ディレクトリ監査開始: {dir_path} (mode={mode}, backend={selected_backend})", err=True)

        try:
            dir_report = run_dir_audit(
                target_dir=target,
                mode=mode,  # type: ignore
                enable_static=not no_static,
                model=model,
                backend=selected_backend,
                log_dir=LOG_DIR if save_log else None,
                target_type=target_type,  # type: ignore
                tech_stack=stack,
                system_overview=system_overview,
                exposure=exposure,
                severity_filter=severity_filter,  # type: ignore
                extensions=extensions,
                verbose=True,
                ignore_rules=rules,
            )
        except Exception as e:
            click.echo(f"監査エラー: {e}", err=True)
            raise

        if output_format == "json":
            result_text = format_dir_json(dir_report)
        elif output_format == "sarif":
            result_text = format_dir_sarif(dir_report)
        else:
            result_text = format_dir_markdown(dir_report)

        _write_output(result_text, output)
        s = dir_report.aggregated_summary
        click.echo(f"\n📊 集約サマリー: {dir_report.file_count}ファイル / 合計 {s.total_issues} 件", err=True)
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = s.by_severity.get(sev, 0)
            if count > 0:
                click.echo(f"   {sev}: {count}", err=True)
        _check_fail_on(fail_on, dir_report.aggregated_summary.by_severity)
        if save_log:
            click.echo(f"📁 ログ保存先: {LOG_DIR}/", err=True)
        return

    # ─── バックエンド比較実行 ───────────────────────────────────────────
    if compare:
        target = Path(file_path)  # type: ignore
        if not target.exists():
            click.echo(f"エラー: ファイルが見つかりません: {file_path}", err=True)
            sys.exit(1)

        content = target.read_text(encoding="utf-8", errors="replace")
        audit_input = AuditInput(
            target_content=content,
            target_type=target_type or "code",  # type: ignore
            tech_stack=stack,
            system_overview=system_overview,
            exposure_level=exposure,  # type: ignore
            severity_filter=severity_filter,  # type: ignore
            file_path=str(target.resolve()),
        )

        backends_list: list[str] | None = None
        if compare_backends_str:
            backends_list = [b.strip() for b in compare_backends_str.split(",")]

        click.echo(f"🔀 比較監査開始: {file_path} (mode={mode})", err=True)

        try:
            compare_report = compare_backends(
                audit_input=audit_input,
                mode=mode,  # type: ignore
                enable_static=not no_static,
                model=model,
                backends=backends_list,
                log_dir=LOG_DIR if save_log else None,
            )
        except Exception as e:
            click.echo(f"比較エラー: {e}", err=True)
            raise

        result_text = format_compare_markdown(compare_report)
        _write_output(result_text, output)
        click.echo(f"\n📊 一致率: {compare_report.agreement_rate:.1f}%", err=True)
        click.echo(f"   両方検出: {len(compare_report.issues_both)} 件", err=True)
        for b in compare_report.backends:
            only = compare_report.issues_only.get(b, [])
            click.echo(f"   {b} のみ: {len(only)} 件", err=True)
        if save_log:
            click.echo(f"📁 ログ保存先: {LOG_DIR}/", err=True)
        return

    # ─── watch モード ───────────────────────────────────────────────────
    if watch_mode:
        target = Path(dir_path or file_path)  # type: ignore
        if not target.exists():
            click.echo(f"エラー: パスが見つかりません: {target}", err=True)
            sys.exit(1)

        # 現在のオプションを保持して再実行するクロージャ
        _run_opts = dict(
            file_path=file_path, dir_path=dir_path,
            mode=mode, target_type=target_type, tech_stack=tech_stack,
            output_format=output_format, output=output, backend=backend,
            compare=False, multi_agent=multi_agent,
            injection_test=injection_test, injection_types=injection_types,
            memory_poison=memory_poison, watch_mode=False,
            compare_backends_str=compare_backends_str, model=model,
            no_static=no_static, severity_filter=severity_filter,
            system_overview=system_overview, exposure=exposure,
            ext=ext, baseline=baseline, save_baseline=save_baseline,
            ignore_file=ignore_file, rules_file=rules_file,
            fail_on=None,  # watch中はfail_onを無効化
            save_log=save_log,
        )

        def _on_change(changed_path: Path) -> None:
            click.echo(f"\n🔄 変更検知: {changed_path}", err=True)
            click.echo(f"   {changed_path.name} を再監査中...", err=True)
            try:
                # ファイル監視時は変更ファイルを直接監査、ディレクトリ監視はdir全体
                opts = dict(_run_opts)
                if dir_path:
                    opts["dir_path"] = dir_path
                    opts["file_path"] = None
                else:
                    opts["file_path"] = str(changed_path)
                    opts["dir_path"] = None
                ctx = click.Context(main)
                ctx.invoke(main, **opts)
            except SystemExit:
                pass
            except Exception as e:
                click.echo(f"  ⚠️  監査エラー: {e}", err=True)

        # 初回は即実行
        _on_change(target)
        watch(target, _on_change)
        return

    # ─── Prompt Injection シミュレーション ─────────────────────────────
    if injection_test:
        if dir_path:
            click.echo("エラー: --injection-test は --file 指定時のみ有効です。", err=True)
            sys.exit(1)
        target = Path(file_path)  # type: ignore
        if not target.exists():
            click.echo(f"エラー: ファイルが見つかりません: {file_path}", err=True)
            sys.exit(1)
        content = target.read_text(encoding="utf-8", errors="replace")
        types_list: list[str] | None = (
            [t.strip() for t in injection_types.split(",")] if injection_types else None
        )
        click.echo(f"💉 Prompt Injection シミュレーション開始: {file_path} (backend={selected_backend})", err=True)
        try:
            inj_report = run_injection_simulation(
                content=content,
                file_path=str(target.resolve()),
                model=model,
                backend=selected_backend,
                payload_types=types_list,
                log_dir=LOG_DIR if save_log else None,
            )
        except Exception as e:
            click.echo(f"注入テストエラー: {e}", err=True)
            raise
        result_text = format_injection_markdown(inj_report)
        _write_output(result_text, output)
        click.echo(
            f"\n💉 結果: vulnerable={inj_report.vulnerable} / "
            f"likely={inj_report.likely_vulnerable} / "
            f"resistant={inj_report.resistant} / "
            f"総合リスク={inj_report.overall_risk}",
            err=True,
        )
        _check_fail_on(fail_on, {inj_report.overall_risk: 1} if inj_report.overall_risk != "Info" else {})
        return

    # ─── Memory Poisoning 耐性試験 ──────────────────────────────────────
    if memory_poison:
        if dir_path:
            click.echo("エラー: --memory-poison は --file 指定時のみ有効です。", err=True)
            sys.exit(1)
        target = Path(file_path)  # type: ignore
        if not target.exists():
            click.echo(f"エラー: ファイルが見つかりません: {file_path}", err=True)
            sys.exit(1)
        content = target.read_text(encoding="utf-8", errors="replace")
        click.echo(f"🧠 Memory Poisoning 耐性試験開始: {file_path} (backend={selected_backend})", err=True)
        try:
            mp_report = run_memory_poison_test(
                content=content,
                file_path=str(target.resolve()),
                model=model,
                backend=selected_backend,
                log_dir=LOG_DIR if save_log else None,
            )
        except Exception as e:
            click.echo(f"Memory Poisoning テストエラー: {e}", err=True)
            raise
        result_text = format_memory_poison_markdown(mp_report)
        _write_output(result_text, output)
        click.echo(
            f"\n🧠 結果: vulnerable={mp_report.vulnerable} / "
            f"likely={mp_report.likely_vulnerable} / "
            f"耐性スコア={mp_report.resilience_score}/10.0 / "
            f"総合リスク={mp_report.overall_risk}",
            err=True,
        )
        _check_fail_on(fail_on, {mp_report.overall_risk: 1} if mp_report.overall_risk != "Info" else {})
        return

    # ─── マルチエージェント監査 ─────────────────────────────────────────
    if multi_agent:
        if dir_path:
            click.echo("エラー: --multi-agent は --file 指定時のみ有効です。", err=True)
            sys.exit(1)
        target = Path(file_path)  # type: ignore
        if not target.exists():
            click.echo(f"エラー: ファイルが見つかりません: {file_path}", err=True)
            sys.exit(1)
        content = target.read_text(encoding="utf-8", errors="replace")
        audit_input = AuditInput(
            target_content=content,
            target_type=target_type or "code",  # type: ignore
            tech_stack=stack,
            system_overview=system_overview,
            exposure_level=exposure,  # type: ignore
            severity_filter=severity_filter,  # type: ignore
            file_path=str(target.resolve()),
            previous_findings=previous_findings,
        )
        click.echo(
            f"🤖 マルチエージェント監査開始: {file_path} "
            f"(Attacker→Skeptic→Defender→Judge, backend={selected_backend})",
            err=True,
        )
        try:
            report = run_multi_agent_audit(
                audit_input=audit_input,
                mode=mode,  # type: ignore
                enable_static=not no_static,
                model=model,
                backend=selected_backend,
                log_dir=LOG_DIR if save_log else None,
                verbose=True,
            )
        except Exception as e:
            click.echo(f"マルチエージェント監査エラー: {e}", err=True)
            raise

        if output_format == "json":
            result_text = format_json(report)
        elif output_format == "sarif":
            result_text = format_sarif(report)
        else:
            result_text = format_markdown(report)
        _write_output(result_text, output)
        s = report.summary
        click.echo(f"\n📊 サマリー: 合計 {s.total_issues} 件", err=True)
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            count = s.by_severity.get(sev, 0)
            if count > 0:
                click.echo(f"   {sev}: {count}", err=True)
        _save_baseline_if(save_baseline, report.issues)
        _check_fail_on(fail_on, s.by_severity)
        return

    # ─── 単一ファイル監査 ───────────────────────────────────────────────
    target = Path(file_path)  # type: ignore
    if not target.exists():
        click.echo(f"エラー: ファイルが見つかりません: {file_path}", err=True)
        sys.exit(1)

    try:
        content = target.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        click.echo(f"エラー: ファイル読み込み失敗: {e}", err=True)
        sys.exit(1)

    audit_input = AuditInput(
        target_content=content,
        target_type=target_type or "code",  # type: ignore
        tech_stack=stack,
        system_overview=system_overview,
        exposure_level=exposure,  # type: ignore
        severity_filter=severity_filter,  # type: ignore
        file_path=str(target.resolve()),
        previous_findings=previous_findings,
    )

    click.echo(f"🔍 監査開始: {file_path} (mode={mode}, backend={selected_backend})", err=True)
    click.echo(f"   静的解析: {'無効' if no_static else '有効 (Semgrep + Gitleaks)'}", err=True)

    try:
        report = run_audit(
            audit_input=audit_input,
            mode=mode,  # type: ignore
            enable_static=not no_static,
            model=model,
            backend=selected_backend,
            log_dir=LOG_DIR if save_log else None,
            ignore_rules=rules,
            rules_file=Path(rules_file) if rules_file else None,
        )
    except EnvironmentError as e:
        click.echo(f"設定エラー: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"監査エラー: {e}", err=True)
        raise

    if output_format == "json":
        result_text = format_json(report)
    elif output_format == "sarif":
        result_text = format_sarif(report)
    elif output_format == "both":
        result_text = format_markdown(report) + "\n\n---\n\n" + format_json(report)
    else:
        result_text = format_markdown(report)

    _write_output(result_text, output)

    s = report.summary
    click.echo(f"\n📊 サマリー: 合計 {s.total_issues} 件", err=True)
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = s.by_severity.get(sev, 0)
        if count > 0:
            click.echo(f"   {sev}: {count}", err=True)
    if save_log:
        click.echo(f"📁 ログ保存先: {LOG_DIR}/", err=True)
    _save_baseline_if(save_baseline, report.issues)
    _check_fail_on(fail_on, s.by_severity)


_SEV_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}


def _check_fail_on(fail_on: str | None, by_severity: dict[str, int]) -> None:
    """--fail-on で指定した severity 以上の指摘があれば exit 1"""
    if not fail_on:
        return
    threshold = _SEV_RANK.get(fail_on, 0)
    triggered = [
        sev for sev, count in by_severity.items()
        if count > 0 and _SEV_RANK.get(sev, 0) >= threshold
    ]
    if triggered:
        click.echo(
            f"\n❌ --fail-on {fail_on}: {', '.join(triggered)} の指摘が検出されました。",
            err=True,
        )
        sys.exit(1)


def _load_baseline(baseline_path: str | None) -> list:
    """baseline JSON から前回の Issue リストを読み込む"""
    if not baseline_path:
        return []
    p = Path(baseline_path)
    if not p.exists():
        click.echo(f"⚠️  baseline ファイルが見つかりません: {baseline_path}", err=True)
        return []
    try:
        from redteam.models import Issue
        data = json.loads(p.read_text(encoding="utf-8"))
        issues = data if isinstance(data, list) else data.get("issues", [])
        return [Issue.model_validate(i) for i in issues]
    except Exception as e:
        click.echo(f"⚠️  baseline 読み込みエラー: {e}", err=True)
        return []


def _save_baseline_if(save_path: str | None, issues: list) -> None:
    """今回の Issue リストを baseline JSON として保存する"""
    if not save_path:
        return
    p = Path(save_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = [i.model_dump(exclude_none=True) for i in issues]
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    click.echo(f"💾 baseline 保存: {save_path} ({len(issues)} 件)", err=True)


def _load_ignore(
    ignore_file: str | None,
    file_path: str | None,
    dir_path: str | None,
) -> IgnoreRules:
    """
    .redteam-ignore を探して読み込む。
    優先順位: --ignore-file 明示 → カレントdir → 対象ファイル/dir の親
    """
    candidates: list[Path] = []

    if ignore_file:
        candidates.append(Path(ignore_file))
    else:
        candidates.append(Path.cwd() / ".redteam-ignore")
        if file_path:
            candidates.append(Path(file_path).parent / ".redteam-ignore")
        if dir_path:
            candidates.append(Path(dir_path) / ".redteam-ignore")

    for candidate in candidates:
        if candidate.exists():
            return load_ignore_rules(candidate)

    return IgnoreRules()


def _write_output(text: str, output_path: str | None) -> None:
    if output_path:
        Path(output_path).write_text(text, encoding="utf-8")
        click.echo(f"✅ レポート保存: {output_path}", err=True)
    else:
        click.echo(text)


if __name__ == "__main__":
    main()
