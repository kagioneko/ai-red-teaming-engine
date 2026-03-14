# AI-Red-Teaming-Engine 使い方ガイド

> 防御目的の敵対的セキュリティ監査エンジン — 初心者向けスタートガイド

---

## AI-Red-Teaming-Engine とは？

あなたのコードや仕様書を「攻撃者の視点」で読み直すツールです。

- **Semgrep / Gitleaks** による静的解析（パターンマッチ）
- **LLM（Claude / Gemini）** による文脈依存の設計欠陥検出
- 両方を組み合わせることで、単体ツールより高い検出精度を実現

⚠️ **プロトタイプ版です。全ての指摘は人間による最終確認が必要です。**

---

## 必要なもの

- Python 3.10 以上
- Claude Code CLI（`claude` コマンド）← APIキー不要でおすすめ
  - または Gemini CLI（`gemini` コマンド）
  - または Anthropic API キー（`ANTHROPIC_API_KEY`）

---

## インストール

### 1. リポジトリをクローン

```bash
git clone https://github.com/your-org/ai-red-teaming-engine.git
cd ai-red-teaming-engine
```

### 2. 依存パッケージをインストール

```bash
pip install click pydantic anthropic
```

### 3. 静的解析ツールをインストール（推奨）

**Semgrep**（コードパターン検出）:
```bash
pip install semgrep
# または
brew install semgrep
```

**Gitleaks**（シークレット漏洩検出）:
```bash
# macOS
brew install gitleaks

# Linux（バイナリ直接インストール）
wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz
tar -xzf gitleaks_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/
```

### 4. LLMバックエンドの設定

**推奨: Claude Code CLI（APIキー不要）**
```bash
# Claude Codeがインストール済みなら追加設定不要
claude --version  # 確認
```

**代替: Anthropic APIキー**
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

---

## 基本的な使い方

### 単一ファイルを監査する

```bash
python engine.py --file app.py
```

これだけで動きます。バックエンドは自動選択されます。

### 出力例

```
🔍 監査開始: app.py (mode=deep, backend=claude)
   静的解析: 有効 (Semgrep + Gitleaks)

# AI-Red-Teaming-Engine 監査レポート

## 指摘サマリー

**合計: 5 件**

| Severity | 件数 |
|----------|------|
| 🔴 Critical | 1 |
| 🟠 High | 2 |
| 🟡 Medium | 2 |
```

---

## よく使うコマンド集

### ファイル1つを監査（基本）

```bash
python engine.py --file app.py
```

### ディレクトリ丸ごと監査 ⭐ v0.2新機能

```bash
python engine.py --dir src/
```

Pythonファイル、JS/TS、Go、Yaml、Markdownなど、主要なファイルを自動で走査します。

### GitHub Security Tab 対応SARIF出力 ⭐ v0.2新機能

```bash
# 単一ファイル → SARIF
python engine.py --file app.py --format sarif -o results.sarif

# ディレクトリ → SARIF（CI/CD連携に最適）
python engine.py --dir src/ --format sarif -o results.sarif
```

### Claude vs Gemini で比較実行 ⭐ v0.2新機能

```bash
python engine.py --file app.py --compare
```

どちらのLLMが何を検出したか差分が見えます。

### バックエンドを明示指定

```bash
python engine.py --file app.py --backend claude   # Claude Code CLI
python engine.py --file app.py --backend gemini   # Gemini CLI
python engine.py --file app.py --backend api      # Anthropic API
```

### JSON出力（プログラムから使いたい場合）

```bash
python engine.py --file app.py --format json -o report.json
```

### Criticalだけ見たい

```bash
python engine.py --file app.py --severity-filter Critical
```

### 特定の拡張子だけディレクトリ監査

```bash
python engine.py --dir . --ext .py,.ts
```

---

## 監査モード

| モード | 用途 | 誤検知 |
|--------|------|--------|
| `deep`（デフォルト） | 徹底調査 | やや多め |
| `safe` | 本番投入向け | 少なめ |
| `agent-audit` | AI/LLMエージェント特化 | — |
| `patch` | 前回との差分のみ | — |

```bash
python engine.py --file api.py --mode safe
python engine.py --file agent.py --mode agent-audit
```

---

## 対象種別（--type）

省略すると拡張子から自動判定されます。

| 種別 | 対象 |
|------|------|
| `code`（デフォルト）| Python, JS, Go など |
| `spec` | 仕様書、Markdown |
| `api` | API定義（OpenAPI等）|
| `prompt` | LLMプロンプト |
| `architecture` | アーキテクチャ設計書 |
| `agent` | AIエージェント設計 |

```bash
python engine.py --file openapi.yaml --type api
python engine.py --file DESIGN.md --type architecture
```

---

## CI/CD への組み込み

### セットアップ手順

**1. ワークフローファイルをコピー**

`.github/workflows/security-audit.yml` がリポジトリに同梱されています。そのまま使えます。

**2. GitHub Secrets に API キーを登録**

GitHub リポジトリ → Settings → Secrets → Actions → New repository secret

| Secret 名 | 値 |
|-----------|---|
| `ANTHROPIC_API_KEY` | `sk-ant-...` |

**3. プッシュするだけで自動実行**

- `main` / `master` へのプッシュ時
- PRオープン時
- 毎朝9時（JST）の定期スキャン
- 手動実行（Actions タブから）

### 結果の確認場所

GitHub リポジトリ → **Security タブ → Code scanning** に指摘が自動表示されます。

### CI でのビルド失敗制御

```bash
# High以上の指摘があれば exit 1（デフォルト）
python engine.py --dir src/ --format sarif -o results.sarif --fail-on High

# Criticalのみ失敗扱い（厳しすぎる場合）
python engine.py --dir src/ --format sarif -o results.sarif --fail-on Critical

# 失敗させない（SARIFアップロードのみ）
python engine.py --dir src/ --format sarif -o results.sarif
```

### `.redteam-ignore` でCIの誤検知を除外

```bash
# リポジトリルートに .redteam-ignore を置くだけで自動適用される
echo "tests/" >> .redteam-ignore
echo "severity:Info" >> .redteam-ignore
git add .redteam-ignore && git commit -m "chore: redteam ignore rules"
```

→ `.redteam-ignore.example` をコピーして編集してください。

---

## 出力ファイルの場所

実行結果は `logs/` ディレクトリに自動保存されます。

```
logs/
├── 20260314_152300_abc12345_report.md    ← Markdown（読みやすい）
├── 20260314_152300_abc12345_report.json  ← JSON（プログラム処理用）
├── 20260314_152300_def67890_dir_report.md ← ディレクトリ監査
└── 20260314_152300_ghi11223_compare.md   ← 比較レポート
```

---

## トラブルシューティング

### 「使用可能なLLMバックエンドがありません」

```bash
# どれか一つを確認
claude --version    # Claude Code CLI
gemini --version    # Gemini CLI
echo $ANTHROPIC_API_KEY  # API キー
```

### Semgrep が動かない

```bash
pip install semgrep
semgrep --version
```

`--no-static` フラグでスキップして LLM のみで監査できます:
```bash
python engine.py --file app.py --no-static
```

### 大きなファイルがスキップされる

200KB 超のファイルは自動スキップされます。
`--file` で直接指定すれば監査できます。

---

## 指摘の読み方

各指摘には以下の情報が含まれます:

| フィールド | 説明 |
|-----------|------|
| **Severity** | Critical / High / Medium / Low / Info |
| **Confidence** | High / Medium / Low（LLMの確信度）|
| **Category** | 脆弱性カテゴリ（SQLi, XSS, Auth 等）|
| **なぜ問題か** | 攻撃シナリオの説明 |
| **根拠** | 問題箇所のコードスニペット |
| **最小修正案** | 修正コードの提案 |
| **人間確認が必要** | Yes の場合は必ず確認してください |

---

## セキュリティに関する注意

- このツールは**防御目的専用**です
- 自分が所有または許可を得たシステムのみに使用してください
- 出力されるレポートにはセキュリティ上の機微情報が含まれる場合があります
- ログファイル（`logs/`）の共有には注意してください
