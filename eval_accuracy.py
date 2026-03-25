"""
AI Red Teaming Engine — 検出精度評価スクリプト

tests/fixtures/ 配下の各脆弱性フィクスチャに対してエンジンを実行し、
expected.json との照合で検出率・誤検知率を算出する。

使い方:
    python3 eval_accuracy.py
    python3 eval_accuracy.py --mode safe
    python3 eval_accuracy.py --fixture sql_injection
    python3 eval_accuracy.py --backend claude
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

# エンジン本体のパスを通す
sys.path.insert(0, str(Path(__file__).parent))

from redteam.models import AuditInput, AuditMode
from redteam.pipeline import run_audit

FIXTURES_DIR = Path(__file__).parent / "tests" / "fixtures"

# カテゴリ部分一致マップ（expected の category と engine の category を緩やかに照合）
_CATEGORY_ALIASES: dict[str, list[str]] = {
    "Injection":          ["injection", "sql", "sqli"],
    "Command Execution":  ["command", "exec", "subprocess", "rce", "os command"],
    "Path Traversal":     ["path", "traversal", "directory"],
    "Secrets":            ["secret", "hardcoded", "credential", "api key", "token"],
    "Deserialization":    ["deserializ", "pickle", "unsafe"],
    "SSRF":               ["ssrf", "server-side request"],
    "Cryptography":       ["crypto", "md5", "weak", "hash"],
    "Authentication":     ["auth", "bypass", "access control"],
    "XXE":                ["xxe", "xml", "external entity"],
    "Prompt Injection":   ["prompt", "injection", "llm"],
}


def _category_match(expected_cat: str, detected_cat: str) -> bool:
    """expected と detected のカテゴリが意味的に一致するか判定"""
    e = expected_cat.lower()
    d = detected_cat.lower()
    if e in d or d in e:
        return True
    for canonical, aliases in _CATEGORY_ALIASES.items():
        if e in canonical.lower() or any(a in e for a in aliases):
            if d in canonical.lower() or any(a in d for a in aliases):
                return True
    return False


@dataclass
class FixtureResult:
    name: str
    expected: list[dict]
    detected_issues: list[dict]
    matched: list[dict] = field(default_factory=list)
    missed: list[dict] = field(default_factory=list)
    elapsed_sec: float = 0.0
    error: str = ""

    @property
    def recall(self) -> float:
        """検出率: 期待脆弱性のうち何割を検出できたか"""
        if not self.expected:
            return 1.0
        return len(self.matched) / len(self.expected)

    @property
    def false_positives(self) -> int:
        """誤検知数: expected にないカテゴリの検出"""
        fps = 0
        for issue in self.detected_issues:
            cat = issue.get("category", "")
            if not any(_category_match(e["category"], cat) for e in self.expected):
                fps += 1
        return fps


def run_fixture(
    name: str,
    mode: AuditMode,
    backend: str,
) -> FixtureResult:
    fixture_dir = FIXTURES_DIR / name
    vuln_file = fixture_dir / "vulnerable.py"
    expected_file = fixture_dir / "expected.json"

    expected = json.loads(expected_file.read_text()).get("vulnerabilities", [])
    code = vuln_file.read_text()

    audit_input = AuditInput(
        target_content=code,
        target_type="code",
        tech_stack=["Python", "Flask"],
        file_path=str(vuln_file),
    )

    t0 = time.time()
    try:
        report = run_audit(
            audit_input,
            mode=mode,
            backend=backend,
            use_cache=False,
        )
        elapsed = time.time() - t0
    except Exception as e:
        return FixtureResult(
            name=name,
            expected=expected,
            detected_issues=[],
            error=str(e),
            elapsed_sec=time.time() - t0,
        )

    detected = [
        {
            "category": i.category,
            "severity": i.severity,
            "title": i.title,
            "line_start": i.line_start,
        }
        for i in report.issues
    ]

    matched = []
    missed = []
    for exp in expected:
        found = any(_category_match(exp["category"], d["category"]) for d in detected)
        if found:
            matched.append(exp)
        else:
            missed.append(exp)

    return FixtureResult(
        name=name,
        expected=expected,
        detected_issues=detected,
        matched=matched,
        missed=missed,
        elapsed_sec=elapsed,
    )


def print_result(r: FixtureResult) -> None:
    status = "✅" if r.recall == 1.0 else ("⚠️ " if r.recall >= 0.5 else "❌")
    print(f"\n{status} [{r.name}]  recall={r.recall:.0%}  fp={r.false_positives}  ({r.elapsed_sec:.1f}s)")

    if r.error:
        print(f"   エラー: {r.error}")
        return

    for m in r.matched:
        print(f"   ✓ 検出: {m['category']} ({m['severity']})")
    for m in r.missed:
        print(f"   ✗ 未検出: {m['category']} ({m['severity']})")
    if r.false_positives:
        fp_cats = [
            d["category"] for d in r.detected_issues
            if not any(_category_match(e["category"], d["category"]) for e in r.expected)
        ]
        print(f"   ⚠ 誤検知: {', '.join(fp_cats)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="AI Red Teaming Engine 検出精度評価")
    parser.add_argument("--mode", default="deep", choices=["safe", "deep", "agent-audit", "patch"])
    parser.add_argument("--backend", default="api", help="LLMバックエンド (api/claude/gemini)")
    parser.add_argument("--fixture", default="", help="特定フィクスチャのみ実行 (例: sql_injection)")
    args = parser.parse_args()

    # 実行対象フィクスチャ一覧
    if args.fixture:
        names = [args.fixture]
    else:
        names = sorted(p.name for p in FIXTURES_DIR.iterdir() if p.is_dir())

    if not names:
        print(f"フィクスチャが見つかりません: {FIXTURES_DIR}")
        sys.exit(1)

    print(f"=== AI Red Teaming Engine 精度評価 ===")
    print(f"mode={args.mode}  backend={args.backend}  fixtures={len(names)}件")

    results: list[FixtureResult] = []
    for name in names:
        print(f"  → {name} ...", end="", flush=True)
        r = run_fixture(name, mode=args.mode, backend=args.backend)
        results.append(r)
        print(f" done ({r.elapsed_sec:.1f}s)")

    # 個別結果
    print("\n" + "=" * 50)
    for r in results:
        print_result(r)

    # 集計
    valid = [r for r in results if not r.error]
    if not valid:
        print("\n有効な結果がありません")
        sys.exit(1)

    total_expected = sum(len(r.expected) for r in valid)
    total_matched  = sum(len(r.matched)  for r in valid)
    total_fp       = sum(r.false_positives for r in valid)
    avg_recall     = sum(r.recall for r in valid) / len(valid)
    total_elapsed  = sum(r.elapsed_sec for r in valid)

    perfect = sum(1 for r in valid if r.recall == 1.0)

    print("\n" + "=" * 50)
    print("=== 総合スコア ===")
    print(f"  フィクスチャ数   : {len(valid)} 件")
    print(f"  完全検出         : {perfect}/{len(valid)} 件")
    print(f"  平均 Recall      : {avg_recall:.1%}")
    print(f"  検出数/期待数    : {total_matched}/{total_expected}")
    print(f"  総誤検知数       : {total_fp} 件")
    print(f"  合計実行時間     : {total_elapsed:.1f}s")

    # 結果JSON保存
    out = Path(__file__).parent / "eval_results.json"
    out.write_text(json.dumps({
        "mode": args.mode,
        "backend": args.backend,
        "summary": {
            "fixtures": len(valid),
            "perfect": perfect,
            "avg_recall": round(avg_recall, 4),
            "total_matched": total_matched,
            "total_expected": total_expected,
            "total_fp": total_fp,
            "elapsed_sec": round(total_elapsed, 2),
        },
        "details": [
            {
                "name": r.name,
                "recall": round(r.recall, 4),
                "false_positives": r.false_positives,
                "matched": r.matched,
                "missed": r.missed,
                "elapsed_sec": round(r.elapsed_sec, 2),
                "error": r.error,
            }
            for r in results
        ],
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n結果保存: {out}")


if __name__ == "__main__":
    main()
