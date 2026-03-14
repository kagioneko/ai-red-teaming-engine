# AI-Red-Teaming-Engine

**防御目的の敵対的セキュリティ監査エンジン**

[![CI](https://github.com/kagioneko/ai-red-teaming-engine/actions/workflows/security-audit.yml/badge.svg)](https://github.com/kagioneko/ai-red-teaming-engine/actions)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-orange)](https://sarifweb.azurewebsites.net/)

コード・仕様書・AIエージェント設計を「攻撃者の視点」で読み直す Python 製ツール。
**Semgrep / Gitleaks による静的解析** と **LLM（Claude / Gemini）による文脈解析** を組み合わせ、
単体ツールより高い検出精度を実現します。

> ⚠️ プロトタイプ版です。全ての指摘は人間による最終確認が必要です。

---

## 特徴

| 機能 | 説明 |
|------|------|
| 🔍 **ハイブリッド解析** | Semgrep + Gitleaks + LLM の3層で検出 |
| 📂 **ディレクトリ一括監査** | `--dir src/` で複数ファイルを再帰走査 |
| 📋 **SARIF 2.1.0 出力** | GitHub Security Tab / VS Code に直接表示 |
| 🤖 **4エージェント高精度監査** | Attacker → Skeptic → Defender → Judge で誤検知削減 |
| 💉 **Prompt Injection テスト** | 13種ペイロードで LLM システムの注入耐性を評価 |
| 🧠 **Memory Poisoning 耐性試験** | RAG・ベクトルDB汚染経路を静的+LLM で検出 |
| 🔀 **バックエンド比較** | Claude vs Gemini の検出差分を可視化 |
| 🚫 **除外ルール** | `.redteam-ignore` でノイズを管理 |
| 🔁 **差分追跡** | `--baseline` で前回との regression を検出 |
| ⚙️ **CI/CD 対応** | GitHub Actions ワークフロー同梱 |

---

## インストール

### 依存パッケージ

```bash
pip install click pydantic anthropic
```

### 静的解析ツール（推奨）

```bash
# Semgrep
pip install semgrep

# Gitleaks（Linux）
wget -qO- https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz | tar xz
sudo mv gitleaks /usr/local/bin/
```

### LLM バックエンド

APIキー不要で使える **Claude Code CLI** を推奨：

```bash
# Claude Code CLI がインストール済みなら追加設定不要
claude --version

# または Anthropic API キー
export ANTHROPIC_API_KEY="sk-ant-..."
```

---

## クイックスタート

```bash
git clone https://github.com/kagioneko/ai-red-teaming-engine.git
cd ai-red-teaming-engine

# 単一ファイルを監査
python engine.py --file app.py --backend claude

# ディレクトリ丸ごと監査
python engine.py --dir src/ --backend claude

# GitHub Security Tab 用 SARIF 出力
python engine.py --dir src/ --format sarif -o results.sarif
```

---

## 主なオプション

```
--file / --dir          監査対象（ファイル or ディレクトリ）
--mode                  safe / deep（default）/ agent-audit / patch
--backend               claude / gemini / codex / api
--format                text / json / sarif / both
--output / -o           出力ファイルパス
--fail-on               Critical/High/Medium 以上で exit 1（CI用）
--multi-agent           4エージェント高精度監査
--injection-test        Prompt Injection シミュレーション
--memory-poison         Memory Poisoning 耐性試験
--compare               複数バックエンド比較
--baseline              前回結果との差分追跡
--save-baseline         今回結果を次回比較用に保存
--no-static             Semgrep/Gitleaks をスキップ
```

詳細は [GUIDE.md](GUIDE.md) を参照してください。

---

## 使用例

```bash
# 通常の深度監査（デフォルト）
python engine.py --file api.py --backend claude

# 高精度監査（4エージェント、時間がかかる）
python engine.py --file api.py --multi-agent --backend claude

# AIエージェントのPrompt Injection テスト
python engine.py --file agent.py --injection-test --backend claude

# RAGシステムのMemory Poisoning 耐性試験
python engine.py --file rag_system.py --memory-poison --backend claude

# CI/CD: High以上で失敗・SARIF出力
python engine.py --dir src/ --format sarif -o results.sarif --fail-on High

# 2回目以降: 前回との差分のみ確認
python engine.py --dir src/ --baseline prev.json --save-baseline prev.json --mode patch
```

---

## GitHub Actions による自動監査

`.github/workflows/security-audit.yml` を参考にしてください。

1. `ANTHROPIC_API_KEY` を GitHub Secrets に登録
2. push / PR で自動的に監査が実行される
3. **Security タブ → Code scanning** に指摘が表示される

詳しくは [GUIDE.md#CI](GUIDE.md#cicd-への組み込み) を参照。

---

## 監査モード

| モード | 用途 |
|--------|------|
| `deep` | 徹底調査（デフォルト） |
| `safe` | 本番投入向け・誤検知少なめ |
| `agent-audit` | AI / LLM エージェント特化 |
| `patch` | 前回との差分のみ再監査 |

---

## 除外ルール（.redteam-ignore）

`.redteam-ignore.example` をコピーして `.redteam-ignore` に配置：

```bash
tests/              # ディレクトリ除外
*.generated.py      # glob パターン
severity:Info       # severity 単位除外
category:CORS       # カテゴリ単位除外
fingerprint:abc123  # 既知誤検知を固定除外
rule:RTE-Auth-Low   # SARIF ruleId 形式
```

---

## アーキテクチャ

```
engine.py (CLI)
└── redteam/
    ├── pipeline.py       # 4層パイプライン統合
    ├── multi_agent.py    # Attacker/Skeptic/Defender/Judge
    ├── prompt_injection.py # Prompt Injection シミュレータ
    ├── memory_poisoning.py # Memory Poisoning 耐性試験
    ├── comparator.py     # バックエンド比較
    ├── ignorer.py        # .redteam-ignore 解析
    ├── static_tools.py   # Semgrep + Gitleaks
    ├── analyzer.py       # LLM 敵対的分析
    ├── fixer.py          # 修正案生成
    ├── scorer.py         # 優先度スコアリング
    ├── formatters.py     # JSON / Markdown / SARIF 出力
    └── llm_client.py     # 統一 LLM クライアント
```

---

## ライセンス

MIT License — 防御・教育目的のみに使用してください。
自分が所有または許可を得たシステム以外への使用は禁止です。
