#!/usr/bin/env python3
"""Demo script that simulates a realistic redteam-scan run for GIF recording."""
import sys
import time

R = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
YELLOW = "\033[33m"
GREEN = "\033[32m"
CYAN = "\033[36m"
MAGENTA = "\033[35m"
DIM = "\033[2m"


def typewriter(text: str, delay: float = 0.04):
    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def pause(t: float):
    time.sleep(t)


def spinner(label: str, duration: float):
    frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    end = time.time() + duration
    i = 0
    while time.time() < end:
        sys.stdout.write(f"\r{CYAN}{frames[i % len(frames)]}{R}  {label}")
        sys.stdout.flush()
        time.sleep(0.1)
        i += 1
    sys.stdout.write(f"\r{GREEN}✓{R}  {label}\n")
    sys.stdout.flush()


def print_finding(severity: str, title: str, line: str, detail: str):
    colors = {"CRITICAL": RED + BOLD, "HIGH": RED, "MEDIUM": YELLOW, "LOW": DIM}
    c = colors.get(severity, R)
    print(f"\n  {c}[{severity}]{R} {BOLD}{title}{R}")
    print(f"  {DIM}Line {line}{R}")
    print(f"  {detail}")
    pause(0.3)


def main():
    pause(0.5)
    print(f"{CYAN}$ {R}", end="")
    typewriter("redteam-scan -f demo/vulnerable_app.py --mode deep", delay=0.05)
    pause(0.6)

    print()
    print(f"{BOLD}AI Red Teaming Engine{R} {DIM}v0.5.0{R}")
    print(f"{DIM}防御目的の敵対的セキュリティ監査エンジン{R}")
    print()
    pause(0.4)

    spinner("静的解析 (Semgrep + Gitleaks) を実行中...", 1.8)
    pause(0.2)
    spinner("LLM セキュリティ監査を実行中 (claude-sonnet-4-6)...", 2.5)
    pause(0.2)
    spinner("攻撃パターンと脅威モデルを照合中...", 1.2)
    print()

    print(f"{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{R}")
    print(f"{BOLD} 監査レポート: demo/vulnerable_app.py{R}")
    print(f"{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{R}")
    pause(0.3)

    print_finding(
        "CRITICAL", "SQL インジェクション",
        "15",
        "ユーザー入力を直接 SQL クエリに結合しています。\n"
        "  攻撃例: username = \\\" ' OR '1'='1\\\" でログイン認証をバイパス可能。\n"
        f"  {GREEN}推奨修正:{R} parameterized query を使用してください。\n"
        f"  {DIM}cursor.execute(\"SELECT * FROM users WHERE username=? AND password=?\",{R}\n"
        f"  {DIM}              (username, password)){R}",
    )

    print_finding(
        "CRITICAL", "OS コマンドインジェクション",
        "24",
        "リクエストパラメータを shell=True で直接実行しています。\n"
        "  攻撃例: cmd = \\\"ls; cat /etc/passwd\\\" で任意コマンド実行可能。\n"
        f"  {GREEN}推奨修正:{R} shell=False + リスト形式を使用し、入力を allowlist で検証。",
    )

    print_finding(
        "HIGH", "パストラバーサル",
        "31",
        "filename をサニタイズせず os.path.join に渡しています。\n"
        "  攻撃例: name=../../etc/passwd で任意ファイルを読み取り可能。\n"
        f"  {GREEN}推奨修正:{R} pathlib.Path.resolve() でベースパス外へのアクセスを禁止。",
    )

    print_finding(
        "HIGH", "ハードコードされたシークレット",
        "9",
        "SECRET_KEY がソースコードに直書きされています。\n"
        "  Git 履歴にも残存するため、削除後も漏洩リスクが継続します。\n"
        f"  {GREEN}推奨修正:{R} 環境変数 or Vault 経由で注入してください。",
    )

    print_finding(
        "MEDIUM", "エラーメッセージへの情報漏洩",
        "17",
        "認証失敗時に 'Invalid credentials' を返すと\n"
        "  ユーザー名の存在確認（ユーザー列挙）に悪用される可能性があります。\n"
        f"  {GREEN}推奨修正:{R} 認証失敗の理由を統一したメッセージに。",
    )

    print()
    print(f"{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{R}")
    print(f"{BOLD} サマリー{R}")
    print(f"{BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{R}")
    pause(0.3)
    print(f"  {RED + BOLD}CRITICAL{R}  2件  SQL Injection, Command Injection")
    print(f"  {RED}HIGH    {R}  2件  Path Traversal, Hardcoded Secret")
    print(f"  {YELLOW}MEDIUM  {R}  1件  Information Disclosure")
    print()
    print(f"  リスクスコア: {RED + BOLD}9.1 / 10{R}  {RED}●●●●●●●●●○{R}")
    print()
    print(f"  {DIM}⚠️  このレポートは人間による最終確認が必要です。{R}")
    print(f"  {DIM}   詳細: redteam-scan --format sarif -o results.sarif{R}")
    print()
    pause(0.5)
    print(f"{GREEN}完了 {DIM}(3.2s){R}")
    print()


if __name__ == "__main__":
    main()
