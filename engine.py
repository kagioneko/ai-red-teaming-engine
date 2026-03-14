#!/usr/bin/env python3
"""
AI-Red-Teaming-Engine CLI エントリポイント

使用例:
  python engine.py --file app.py --mode deep
  python engine.py --file spec.md --type spec --mode agent-audit
  python engine.py --file api.py --format json --output report.json
"""
import sys
from pathlib import Path

import click

# プロジェクトルートをパスに追加
sys.path.insert(0, str(Path(__file__).parent))

from redteam.config import DEFAULT_MODEL
from redteam.formatters import format_json, format_markdown
from redteam.llm_client import detect_available_backends
from redteam.models import AuditInput, AuditMode, Severity, TargetType
from redteam.pipeline import run_audit

LOG_DIR = Path(__file__).parent / "logs"

_TYPE_CHOICES = ["code", "spec", "api", "prompt", "architecture", "agent"]
_MODE_CHOICES = ["safe", "deep", "agent-audit", "patch"]
_FORMAT_CHOICES = ["text", "json", "both"]


@click.command()
@click.option(
    "--file", "-f", "file_path",
    required=True,
    help="監査対象のファイルパス",
)
@click.option(
    "--mode", "-m",
    default="deep",
    type=click.Choice(_MODE_CHOICES),
    show_default=True,
    help="監査モード: safe（本番向け）/ deep（徹底調査）/ agent-audit（AI/Agent特化）/ patch（差分再監査）",
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
    help="出力形式: text（Markdown）/ json / both",
)
@click.option(
    "--output", "-o",
    default=None,
    help="出力ファイルパス（省略時はstdout）",
)
@click.option(
    "--backend", "-b",
    default=None,
    type=click.Choice(["api", "claude", "gemini", "codex"]),
    help=(
        "LLMバックエンド選択:\n"
        "  api    = Anthropic API（ANTHROPIC_API_KEY 必要）\n"
        "  claude = Claude Code CLI（APIキー不要）\n"
        "  gemini = Gemini CLI（APIキー不要）\n"
        "  codex  = Codex CLI（APIキー不要）\n"
        "省略時は使用可能なバックエンドを自動選択"
    ),
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
    "--save-log",
    is_flag=True,
    default=True,
    show_default=True,
    help="logs/ ディレクトリにレポートを保存",
)
def main(
    file_path: str,
    mode: str,
    target_type: str | None,
    tech_stack: str | None,
    output_format: str,
    output: str | None,
    backend: str | None,
    model: str,
    no_static: bool,
    severity_filter: str | None,
    system_overview: str,
    exposure: str,
    save_log: bool,
) -> None:
    """
    AI-Red-Teaming-Engine — 防御目的の敵対的セキュリティ監査エンジン (v0.1 Prototype)

    ⚠️  このツールはプロトタイプ版です。全ての指摘は人間による最終確認が必要です。
    """
    target = Path(file_path)
    if not target.exists():
        click.echo(f"エラー: ファイルが見つかりません: {file_path}", err=True)
        sys.exit(1)

    try:
        content = target.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        click.echo(f"エラー: ファイル読み込み失敗: {e}", err=True)
        sys.exit(1)

    # tech_stack の処理
    stack: list[str] = [s.strip() for s in tech_stack.split(",")] if tech_stack else []

    audit_input = AuditInput(
        target_content=content,
        target_type=target_type or "code",  # type: ignore
        tech_stack=stack,
        system_overview=system_overview,
        exposure_level=exposure,  # type: ignore
        severity_filter=severity_filter,  # type: ignore
        file_path=str(target.resolve()),
    )

    # バックエンドの自動選択
    selected_backend = backend
    if selected_backend is None:
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
        )
    except EnvironmentError as e:
        click.echo(f"設定エラー: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"監査エラー: {e}", err=True)
        raise

    # 出力
    if output_format == "json":
        result_text = format_json(report)
    elif output_format == "both":
        result_text = format_markdown(report) + "\n\n---\n\n" + format_json(report)
    else:
        result_text = format_markdown(report)

    if output:
        Path(output).write_text(result_text, encoding="utf-8")
        click.echo(f"✅ レポート保存: {output}", err=True)
    else:
        click.echo(result_text)

    # サマリーをstderrに表示
    s = report.summary
    click.echo(f"\n📊 サマリー: 合計 {s.total_issues} 件", err=True)
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = s.by_severity.get(sev, 0)
        if count > 0:
            click.echo(f"   {sev}: {count}", err=True)
    if save_log:
        click.echo(f"📁 ログ保存先: {LOG_DIR}/", err=True)


if __name__ == "__main__":
    main()
