"""
カスタムルール DSL — .redteam-rules.yaml でユーザー定義ルールを追加

形式:
    rules:
      - id: CUS-001
        name: "危険な eval 使用"
        pattern: "eval\\s*\\("          # Python regex
        severity: High                  # Critical / High / Medium / Low / Info
        category: "Code Injection"
        message: "eval() はコードインジェクションのリスクがあります"
        file_glob: "*.py"               # 省略可: 特定の拡張子のみ適用
        enabled: true                   # 省略可: デフォルト true

検索優先順:
    1. コマンドラインで --rules-file 指定
    2. 対象ファイル/ディレクトリと同じ場所の .redteam-rules.yaml
    3. カレントディレクトリの .redteam-rules.yaml
    4. ホームディレクトリの ~/.redteam-rules.yaml
"""
from __future__ import annotations

import fnmatch
import re
import sys
from pathlib import Path
from typing import NamedTuple

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore[assignment]

from .models import StaticFinding

# ─── 型定義 ─────────────────────────────────────────────────────────────────

class CustomRule(NamedTuple):
    rule_id: str
    name: str
    pattern: re.Pattern
    severity: str
    category: str
    message: str
    file_glob: str | None  # None = 全ファイルに適用


class CustomRuleMatch(NamedTuple):
    rule: CustomRule
    line_number: int
    line_content: str

# ─── 定数 ────────────────────────────────────────────────────────────────────

_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}
_SEARCH_FILENAMES = [".redteam-rules.yaml", ".redteam-rules.yml"]


# ─── ルールファイル検索 ───────────────────────────────────────────────────────

def find_rules_file(target_path: Path | None = None) -> Path | None:
    """
    カスタムルールファイルを検索する。

    検索順:
      1. target_path と同じディレクトリ
      2. カレントディレクトリ
      3. ホームディレクトリ
    """
    search_dirs: list[Path] = []
    if target_path:
        d = target_path if target_path.is_dir() else target_path.parent
        search_dirs.append(d)
    search_dirs.append(Path.cwd())
    search_dirs.append(Path.home())

    for d in search_dirs:
        for name in _SEARCH_FILENAMES:
            p = d / name
            if p.is_file():
                return p
    return None


# ─── ルール読み込み ───────────────────────────────────────────────────────────

def load_custom_rules(rules_file: Path) -> tuple[list[CustomRule], list[str]]:
    """
    YAMLからカスタムルールを読み込む。

    Returns:
        (rules, errors): 有効なルールのリストとエラーメッセージのリスト
    """
    if yaml is None:
        return [], ["PyYAML がインストールされていません: pip install pyyaml"]

    errors: list[str] = []
    try:
        raw = yaml.safe_load(rules_file.read_text(encoding="utf-8"))
    except Exception as e:
        return [], [f"ルールファイル読み込みエラー: {e}"]

    if not isinstance(raw, dict) or "rules" not in raw:
        return [], ["ルールファイルに 'rules:' キーがありません"]

    rules: list[CustomRule] = []
    for i, entry in enumerate(raw.get("rules") or []):
        if not isinstance(entry, dict):
            errors.append(f"ルール[{i}]: dict 形式ではありません")
            continue

        # enabled チェック（省略時は true）
        if not entry.get("enabled", True):
            continue

        # 必須フィールド
        rule_id = str(entry.get("id", f"CUS-{i:03d}"))
        name = str(entry.get("name", rule_id))
        pattern_str = entry.get("pattern")
        if not pattern_str:
            errors.append(f"ルール {rule_id}: 'pattern' が必須です")
            continue

        # regex コンパイル
        try:
            compiled = re.compile(pattern_str)
        except re.error as e:
            errors.append(f"ルール {rule_id}: 無効な正規表現 — {e}")
            continue

        # severity 検証
        severity = str(entry.get("severity", "Medium"))
        if severity not in _VALID_SEVERITIES:
            errors.append(f"ルール {rule_id}: 不正な severity '{severity}' (使用可: {', '.join(_VALID_SEVERITIES)})")
            severity = "Medium"

        rules.append(CustomRule(
            rule_id=rule_id,
            name=name,
            pattern=compiled,
            severity=severity,
            category=str(entry.get("category", "Custom")),
            message=str(entry.get("message", name)),
            file_glob=entry.get("file_glob"),
        ))

    return rules, errors


# ─── マッチング ──────────────────────────────────────────────────────────────

def match_rules(
    content: str,
    file_path: str,
    rules: list[CustomRule],
) -> list[CustomRuleMatch]:
    """
    ファイル内容にカスタムルールを適用してマッチを返す。
    1ルールにつき最大5件（同一ルールの大量マッチを抑制）。
    """
    filename = Path(file_path).name
    matches: list[CustomRuleMatch] = []

    for rule in rules:
        # file_glob フィルター
        if rule.file_glob and not fnmatch.fnmatch(filename, rule.file_glob):
            continue

        hit_count = 0
        for lineno, line in enumerate(content.splitlines(), 1):
            if hit_count >= 5:
                break
            if rule.pattern.search(line):
                matches.append(CustomRuleMatch(
                    rule=rule,
                    line_number=lineno,
                    line_content=line.strip(),
                ))
                hit_count += 1

    return matches


def matches_to_findings(matches: list[CustomRuleMatch], file_path: str) -> list[StaticFinding]:
    """CustomRuleMatch を StaticFinding に変換してpipelineと統合できるようにする"""
    return [
        StaticFinding(
            tool="custom",
            rule_id=m.rule.rule_id,
            severity=m.rule.severity,
            message=f"[{m.rule.name}] {m.rule.message}",
            file_path=file_path,
            line=m.line_number,
            code_snippet=m.line_content,
        )
        for m in matches
    ]


# ─── 統合エントリポイント ───────────────────────────────────────────────────

def run_custom_rules(
    content: str,
    file_path: str,
    rules_file: Path | None = None,
) -> tuple[list[StaticFinding], list[str]]:
    """
    カスタムルールを読み込んでファイルに適用する。

    Args:
        content:    ファイル内容
        file_path:  ファイルパス（file_glob フィルタリングに使用）
        rules_file: ルールファイルパス。None の場合は自動検索

    Returns:
        (findings, warnings): StaticFinding のリストと警告メッセージ
    """
    if rules_file is None:
        rules_file = find_rules_file(Path(file_path) if file_path else None)
    if rules_file is None:
        return [], []  # ルールファイルなし = 何もしない

    rules, errors = load_custom_rules(rules_file)
    warnings = [f"[custom_rules] {e}" for e in errors]

    if not rules:
        return [], warnings

    matches = match_rules(content, file_path, rules)
    findings = matches_to_findings(matches, file_path)
    return findings, warnings
