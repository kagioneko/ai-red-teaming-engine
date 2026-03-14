"""
.redteam-ignore パーサー & フィルター

ルール記法:
  tests/                # ディレクトリ前方一致（末尾 / 必須）
  *.generated.py        # glob ファイルパターン
  severity:Info         # severity 除外
  category:CORS         # category 除外
  fingerprint:abc123de  # 既知の誤検知を fingerprint で固定除外
  rule:RTE-Secret-Low   # SARIF ruleId 形式で除外
  # コメント行 / 空行は無視
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from .models import Issue


@dataclass
class IgnoreRules:
    """パース済みの除外ルール集合"""
    dir_prefixes:  list[str] = field(default_factory=list)   # "tests/"
    file_globs:    list[str] = field(default_factory=list)   # "*.generated.py"
    severities:    set[str]  = field(default_factory=set)    # "Info"
    categories:    set[str]  = field(default_factory=set)    # "CORS"
    fingerprints:  set[str]  = field(default_factory=set)    # "abc123de"
    rule_ids:      set[str]  = field(default_factory=set)    # "RTE-Secret-Low"

    @property
    def is_empty(self) -> bool:
        return not any([
            self.dir_prefixes, self.file_globs,
            self.severities, self.categories,
            self.fingerprints, self.rule_ids,
        ])


def load_ignore_rules(ignore_file: Path) -> IgnoreRules:
    """
    .redteam-ignore ファイルを読み込んで IgnoreRules を返す。
    ファイルが存在しない場合は空の IgnoreRules を返す。
    """
    rules = IgnoreRules()
    if not ignore_file.exists():
        return rules

    for raw_line in ignore_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#")[0].strip()  # コメント除去
        if not line:
            continue

        if line.startswith("severity:"):
            rules.severities.add(line.split(":", 1)[1].strip())
        elif line.startswith("category:"):
            rules.categories.add(line.split(":", 1)[1].strip())
        elif line.startswith("fingerprint:"):
            rules.fingerprints.add(line.split(":", 1)[1].strip())
        elif line.startswith("rule:"):
            rules.rule_ids.add(line.split(":", 1)[1].strip())
        elif line.endswith("/"):
            rules.dir_prefixes.append(line)
        else:
            rules.file_globs.append(line)

    return rules


def should_skip_file(path: Path | str, rules: IgnoreRules, base_dir: Path | None = None) -> bool:
    """
    ファイルパスが除外対象かどうか判定する。

    base_dir を指定すると相対パスで照合する（ディレクトリ監査時に使用）。
    """
    if rules.is_empty:
        return False

    p = Path(path)
    rel = p.relative_to(base_dir) if base_dir and p.is_absolute() else p

    # ディレクトリ前方一致（例: "tests/"）
    for prefix in rules.dir_prefixes:
        prefix_clean = prefix.rstrip("/")
        parts = rel.parts
        if prefix_clean in parts:
            return True
        # 先頭からの前方一致も確認
        rel_str = str(rel).replace("\\", "/")
        if rel_str.startswith(prefix_clean + "/") or rel_str == prefix_clean:
            return True

    # glob パターン（例: "*.generated.py"）
    name = p.name
    rel_str = str(rel).replace("\\", "/")
    for pattern in rules.file_globs:
        if fnmatch.fnmatch(name, pattern):
            return True
        if fnmatch.fnmatch(rel_str, pattern):
            return True

    return False


def filter_issues(issues: Sequence[Issue], rules: IgnoreRules) -> list[Issue]:
    """
    IgnoreRules に基づいて Issue リストをフィルタリングする。
    除外された件数を把握したい場合は呼び出し元で len 比較すること。
    """
    if rules.is_empty:
        return list(issues)

    result: list[Issue] = []
    for issue in issues:
        if issue.severity in rules.severities:
            continue
        if issue.category in rules.categories:
            continue
        fp = issue.fingerprint or issue.compute_fingerprint()
        if fp in rules.fingerprints:
            continue
        # ruleId 照合: "RTE-{category}-{severity}" 形式
        rule_id = f"RTE-{issue.category.replace(' ', '-')}-{issue.severity}"
        if rule_id in rules.rule_ids:
            continue
        result.append(issue)

    return result
