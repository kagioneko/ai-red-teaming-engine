# AI-Red-Teaming-Engine 実装仕様書 v0.1

## 1. 概要

AI-Red-Teaming-Engine は、コード・仕様書・エージェント設計・API設計に対して、
**「最悪前提」「ゼロトラスト」「攻撃者視点」** でレビューを行う防御目的の監査エンジンである。

本エンジンは、人格的な「口の悪さ」や「無意味な攻撃性」を持たせるものではない。
目的は、人間や通常のレビューAIが見落としやすい脆弱性・欠陥・境界条件の破綻を、
敵対的な視点で体系的に発見することである。

---

## 2. 目的

### 2.1 主目的
- コードや設計の脆弱性候補を発見する
- 「正常系では成立するが、異常系で崩壊する設計」を検出する
- 攻撃可能性のある箇所を優先度付きで提示する
- 修正案まで一貫して提案する

### 2.2 副目的
- 人間レビューの補助
- セキュリティ観点のレビュー標準化
- 仕様段階での「事故る設計」の早期排除
- AIエージェントの権限逸脱やプロンプト汚染の検出

---

## 3. 設計思想

### 3.1 最悪前提
- 入力はすべて悪意あるものとみなす
- 外部依存はすべて不完全とみなす
- 開発者の想定には漏れがあるものとみなす
- 「普通はこう使わない」は防御にならない

### 3.2 証拠主義
- 指摘には必ず根拠を付与する
- 推測しかない場合は「仮説」と明示する
- 深刻度と確信度を分離して扱う
- 断定と疑義を混同しない

### 3.3 防御目的限定
- 目的は脆弱性の悪用ではなく、防御改善である
- 出力は修正・緩和・防御強化に重点を置く
- 攻撃手順の詳細化は避け、危険性の説明に留める

---

## 4. 適用対象

### 4.1 コード
- Webアプリケーション
- バックエンドAPI
- CLIツール
- 自動化スクリプト
- AIエージェント制御コード
- ローカルアプリ
- スマホアプリの設計断片

### 4.2 文書
- API仕様書
- 認証・認可設計書
- DB設計書
- アーキテクチャ設計書
- 運用フロー仕様
- エージェント行動ルール
- システムプロンプト設計書

### 4.3 AI/LLM関連
- ツール呼び出し設計
- メモリ保存戦略
- RAGパイプライン
- システムプロンプト
- モード分離設計
- 権限境界設計
- 自律エージェントの制御仕様

---

## 5. 非目標

本エンジンは以下を目的としない。
- ただ人格を攻撃的に見せること
- 無根拠な難癖レビュー
- 不快な言い回しの生成
- 完全自動で脆弱性確定判定を行うこと
- 実運用を無視した理想論だけの指摘
- 悪用可能な具体的攻撃手順の生成

> **要するに、"性格が悪い"のではなく、"審査が厳しい"のが正解。**

---

## 6. システムコンセプト

AI-Red-Teaming-Engine は、以下の内部モードを持つ。

### 6.1 Paranoid Review Mode
すべてを疑い、異常系を最優先で確認する。

### 6.2 Failure-First Mode
「どう壊れるか」を最初に考える。

### 6.3 Boundary Attack Mode
権限境界・入力境界・状態遷移境界を重点監査する。

### 6.4 Skeptical Validation Mode
自分の指摘を自分で疑い、根拠不足を減らす。

---

## 7. 論理構成

### 7.1 全体アーキテクチャ

以下の4層構成を基本とする。

```
┌─────────────────────────────────────────┐
│  Layer 1: Input Normalizer              │
│  入力の正規化・チャンク分割・機密マスキング  │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│  Layer 2: Attack Surface Extractor      │
│  入力点・権限境界・外部接続・状態遷移の抽出  │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│  Layer 3: Adversarial Analyzer          │
│  敵対的前提での欠陥候補探索               │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│  Layer 4: Evidence & Fix Generator      │
│  根拠・影響・修正案・追加確認事項の生成     │
└─────────────────────────────────────────┘
```

### 7.2 大規模入力のチャンク戦略

1,000行超のコード・文書を受け取った場合：

| 条件 | 対応 |
|------|------|
| コード < 1,000行 | 全体を単一コンテキストで処理 |
| コード 1,000〜5,000行 | 機能単位でチャンク分割、Attack Surface は全体から抽出 |
| コード > 5,000行 | ファイル単位で並列処理、結果をJudge Agentで統合 |

チャンク分割時は以下を必ず維持する：
- 関数・クラスを途中で切らない
- インポート宣言は各チャンクに付与
- 前後コンテキストを20行オーバーラップさせる

---

## 8. 入力仕様

### 8.1 必須入力

| フィールド | 説明 | 例 |
|-----------|------|----|
| `target_content` | 対象本文（コード・仕様書等） | コード全文 |
| `target_type` | 対象種別 | `code` / `spec` / `api` / `prompt` / `architecture` / `agent` |
| `tech_stack` | 使用技術 | `Python, FastAPI, Firebase` |

### 8.2 推奨入力

| フィールド | 説明 |
|-----------|------|
| `system_overview` | システム概要 |
| `assets_to_protect` | 守るべき資産 |
| `exposure_level` | 外部公開範囲（`public` / `internal` / `private`） |
| `auth_model` | 認証方式 |
| `permission_model` | 権限モデル |
| `external_inputs` | 外部入力の種類 |
| `tool_integrations` | 外部ツール連携先 |
| `assumed_users` | 想定利用者 |
| `assumed_attackers` | 想定攻撃者 |

### 8.3 任意入力

| フィールド | 説明 |
|-----------|------|
| `known_concerns` | 既知の懸念点 |
| `severity_filter` | 重要度制約（`Critical_only` 等） |
| `deploy_env` | 運用環境・デプロイ先 |
| `logging_policy` | ログ取得方針 |
| `session_model` | セッション管理方式 |
| `previous_findings` | 前回監査結果（差分レビュー用） |

### 8.4 入力機密マスキング方針

入力受領時に以下を自動マスキングする（ログ・出力に含めない）：

- 正規表現 `[A-Za-z0-9_\-]{20,}` 形式のトークン・APIキー類
- `password`, `secret`, `token`, `key` を含む変数の値
- IPアドレス・ドメイン名（設定で無効化可）
- DBの接続文字列

マスキング後に元の値は保持せず、`[MASKED]` に置換して処理を継続する。

---

## 9. 内部パラメータ設計

### 9.1 監査パラメータ一覧

| パラメータ | 意味 | 範囲 |
|-----------|------|------|
| `SuspicionLevel` | どの程度「安全だと思い込まないか」 | 0–100 |
| `ExploitSearchDepth` | 攻撃可能性をどこまで掘るか | 0–100 |
| `BoundarySensitivity` | 境界条件への敏感さ | 0–100 |
| `EvidenceStrictness` | 根拠要求の厳しさ | 0–100 |
| `FalsePositiveTolerance` | 誤検知をどれだけ許すか（高いと寛容） | 0–100 |
| `FixOrientation` | 修正案提示をどれだけ重視するか | 0–100 |
| `AbuseDetailLimiter` | 悪用詳細をどれだけ抑制するか（高いと抑制） | 0–100 |

> **注意**: `ExploitSearchDepth`（深く掘る）と `AbuseDetailLimiter`（詳細を出さない）は
> 矛盾に見えるが役割が異なる。「深く分析する」が「攻撃手順を詳述する」は別。
> ExploitSearchDepth は内部分析の深さ、AbuseDetailLimiter は出力への転写量を制御する。

### 9.2 プリセット初期値

| パラメータ | Safe Review | Deep Red-Team | Agent Security Audit | Patch Review |
|-----------|-------------|---------------|----------------------|--------------|
| SuspicionLevel | 75 | 95 | 90 | 80 |
| ExploitSearchDepth | 70 | 90 | 85 | 75 |
| BoundarySensitivity | 80 | 95 | 98 | 85 |
| EvidenceStrictness | 90 | 85 | 90 | 95 |
| FalsePositiveTolerance | 25 | 45 | 35 | 20 |
| FixOrientation | 95 | 80 | 95 | 98 |
| AbuseDetailLimiter | 90 | 75 | 90 | 90 |

> **推奨デフォルト**: `Deep Red-Team` を基準値として使用する。
> 本番投入時は `Safe Review` に切り替える。

---

## 10. 監査フロー

```
Step 1: 対象認識
  ├─ 対象種別を判定
  ├─ 技術スタックを把握
  └─ 保護対象を推定

Step 2: 攻撃面抽出
  ├─ 外部入力点
  ├─ 認証入口
  ├─ 永続化領域
  ├─ ファイル処理
  ├─ ネットワーク境界
  ├─ ツール呼び出し
  ├─ モデルへの入力
  └─ メモリ保存点

Step 3: 欠陥候補探索
  ├─ 入力検証不足
  ├─ 権限分離不備
  ├─ 状態遷移不整合
  ├─ 外部依存信頼しすぎ
  ├─ エラー処理漏れ
  ├─ 例外パス崩壊
  ├─ 情報漏えい経路
  ├─ 推論チェーン汚染
  └─ LLMの命令汚染

Step 4: 根拠評価
  ├─ 本文中の根拠箇所抽出
  ├─ 攻撃成立条件の整理
  ├─ 深刻度判定
  ├─ 確信度判定
  └─ 誤検知リスク判定

Step 5: 修正案生成
  ├─ 最小修正案
  ├─ 強化案
  ├─ 検証テスト案
  └─ 運用上の防御案
```

---

## 11. 出力仕様

### 11.1 Issue Format

各指摘は以下のフィールドを持つ。

| フィールド | 内容 |
|-----------|------|
| `issue_id` | 連番ID（例: `RTE-001`） |
| `title` | 指摘タイトル（1行） |
| `severity` | `Critical` / `High` / `Medium` / `Low` / `Info` |
| `confidence` | `High` / `Medium` / `Low` |
| `category` | Auth / Input Validation / Injection / Memory / Prompt / Access Control / Logging / State / Infra など |
| `affected_area` | 影響箇所（ファイル名・行番号・エンドポイント等） |
| `why_this_matters` | なぜ問題か（ビジネス影響含む） |
| `attack_perspective` | 攻撃者視点の説明（詳細手順は省略） |
| `evidence` | 根拠となるコード箇所・仕様の引用 |
| `conditions_for_failure` | 攻撃成立に必要な条件 |
| `minimal_fix` | 最小修正案 |
| `hardening_suggestion` | 強化案 |
| `false_positive_risk` | 誤検知リスクの説明 |
| `needs_human_confirmation` | `Yes` / `No` |
| `scores` | ImpactScore, LikelihoodScore, ExploitabilityScore, EvidenceScore, UrgencyScore |
| `priority` | 計算済み優先度スコア |

### 11.2 JSON出力スキーマ

```json
{
  "engine_version": "0.1",
  "scan_id": "uuid-v4",
  "target_type": "code",
  "tech_stack": ["Python", "FastAPI"],
  "audit_mode": "Deep Red-Team",
  "parameters": {
    "SuspicionLevel": 95,
    "ExploitSearchDepth": 90,
    "BoundarySensitivity": 95,
    "EvidenceStrictness": 85,
    "FalsePositiveTolerance": 45,
    "FixOrientation": 80,
    "AbuseDetailLimiter": 75
  },
  "summary": {
    "total_issues": 12,
    "by_severity": {
      "Critical": 1,
      "High": 3,
      "Medium": 5,
      "Low": 2,
      "Info": 1
    },
    "needs_human_confirmation": 4
  },
  "issues": [
    {
      "issue_id": "RTE-001",
      "title": "認可チェックが所有者一致に依存しておらず他人のデータ参照余地あり",
      "severity": "High",
      "confidence": "Medium",
      "category": "Access Control",
      "affected_area": "/api/memory/{id} L42-L58",
      "why_this_matters": "認証済みユーザーが他ユーザーの記憶データを取得できる可能性がある",
      "attack_perspective": "有効なIDを推測または列挙した攻撃者が、自分以外のデータを参照できる恐れ",
      "evidence": "L52: `db.get(memory_id)` に owner_id 照合なし",
      "conditions_for_failure": "IDが外部入力であり、API側で所有者検証をしていない場合",
      "minimal_fix": "取得時に `resource.owner_id == session.user_id` を必須化",
      "hardening_suggestion": "UUID化・アクセス監査ログ・IDORテスト追加",
      "false_positive_risk": "実装外側（ミドルウェア等）で認可済みなら誤検知の可能性あり",
      "needs_human_confirmation": true,
      "scores": {
        "ImpactScore": 8,
        "LikelihoodScore": 6,
        "ExploitabilityScore": 7,
        "EvidenceScore": 7,
        "UrgencyScore": 7
      },
      "priority": 28.5
    }
  ],
  "attack_surface_map": {
    "external_inputs": ["/api/**", "WebSocket /ws"],
    "auth_boundaries": ["JWT validation at middleware"],
    "persistence_points": ["PostgreSQL users table", "Redis session store"],
    "tool_calls": [],
    "memory_write_points": []
  }
}
```

### 11.3 テキスト出力例

```
Issue ID: RTE-017
Title: 認可チェックがオーナー一致に依存しておらず、他人のデータ参照余地あり
Severity: High | Confidence: Medium
Category: Access Control
Affected Area: /api/memory/{id} 取得処理 L42-L58

[Why This Matters]
攻撃者がIDを推測・列挙した場合、認証済みであっても他ユーザーのデータを取得できる可能性。

[Attack Perspective]
有効IDを取得または推測した攻撃者が、自分以外のデータを参照できる恐れ。
（具体的な攻撃手順は省略 — 防御強化を優先すること）

[Evidence]
L52: `db.get(memory_id)` に owner_id と session.user_id の照合なし

[Conditions for Failure]
IDが外部入力であり、API側で所有者検証をしていない場合

[Minimal Fix]
取得処理に `if resource.owner_id != current_user.id: raise 403` を追加

[Hardening Suggestion]
UUID化、アクセス監査ログ追加、IDORシナリオのE2Eテスト実装

[False Positive Risk]
ミドルウェア等で認可済みなら誤検知の可能性あり

Needs Human Confirmation: Yes
Priority Score: 28.5
```

---

## 12. 重点監査カテゴリ

### 12.1 一般ソフトウェア
- 入力検証
- 認証・認可
- セッション管理
- エラー処理
- ログ安全性
- 設定漏えい
- 秘密情報管理
- 依存ライブラリリスク
- ファイル処理
- 非同期競合（Race Condition）
- データ整合性

### 12.2 Web/API
- SQL Injection
- XSS（Reflected / Stored / DOM）
- CSRF
- SSRF
- IDOR
- レート制限不備
- CORS過剰許可
- Cookie属性不備（Secure/HttpOnly/SameSite）
- Webhook署名不足
- 冪等性不備

### 12.3 AI/LLM/Agent
- Prompt Injection（Direct / Indirect）
- Tool Abuse（権限逸脱）
- Memory Poisoning
- System Prompt Leakage
- Context Boundary Collapse
- RAG Source Poisoning
- Unsafe Tool Invocation
- Privilege Escalation via Tool Chain
- Agent Goal Drift
- Reflection Loop Failure

---

## 13. AI/LLM系で特に重要な観点

### 13.1 ツール権限の分離
以下の3つが曖昧だと事故る：
- **モデルが見える情報**（コンテキスト内容）
- **モデルが呼べるツール**（API・関数）
- **モデルが実行できる操作**（副作用の範囲）

### 13.2 記憶の汚染
- ユーザー入力をそのまま長期記憶化しない
- 他人の文脈が混ざらないようにする（マルチユーザー環境）
- システム指示とユーザー指示を同列に扱わない

### 13.3 文脈越境
以下の4ソースが混ざると便利さと危険が同時に増す：
1. 過去チャット
2. 永続記憶
3. 外部ドキュメント
4. RAG結果

境界なき文脈統合はPrompt Injectionの温床になる。

### 13.4 モード破壊
以下のモードを曖昧にすると危険：
- 通常会話モード
- 管理者モード
- 自動化モード
- デバッグモード

モード遷移は明示的な権限昇格フローが必要。

---

## 14. 推奨動作モード

| モード | 用途 | 特徴 |
|--------|------|------|
| **Safe Review** | 本番投入・最終チェック | 防御重視、誤検知少なめ |
| **Deep Red-Team** | 仕様レビュー・初期設計 | 疑い強め、仮説多め |
| **Agent Security Audit** | LLM/ツール/記憶/RAG特化 | エージェント設計レビュー向け |
| **Patch Review** | 修正後の再監査 | 差分重視、修正漏れ検知 |

---

## 15. マルチエージェント拡張設計

### 15.1 役割分担構成

```
┌─────────────────┐
│  Attacker Agent  │ 攻撃成立可能性を探索
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ┌─────────────────┐
│  Skeptic Agent   │◄────│  Defender Agent  │
│  根拠不足を弾く   │     │  修正案を具体化   │
└────────┬────────┘     └─────────────────┘
         │
         ▼
┌─────────────────┐
│   Judge Agent    │ 最終採用・優先度決定
└─────────────────┘
```

この構成により、「性格の悪いAIが暴走する」問題を役割分担で中和できる。

### 15.2 エージェント間通信プロトコル

```json
{
  "from": "Attacker",
  "to": "Skeptic",
  "finding": {
    "issue_id": "RTE-001",
    "claim": "所有者チェックなしにデータ取得が可能",
    "evidence_refs": ["L52"],
    "confidence_raw": 0.8
  }
}
```

Skeptic AgentはEvidenceScoreが閾値未満の場合、Attacker Agentに差し戻す。

---

## 16. スコアリング設計

### 16.1 スコア定義

| スコア | 範囲 | 意味 |
|--------|------|------|
| ImpactScore | 0–10 | 悪用された場合の被害規模 |
| LikelihoodScore | 0–10 | 実際に攻撃される可能性 |
| ExploitabilityScore | 0–10 | 攻撃の難易度（高い = 簡単） |
| EvidenceScore | 0–10 | 根拠の確実性 |
| UrgencyScore | 0–10 | 即時対応の必要性 |

### 16.2 優先度計算式

ImpactとExploitabilityの相関を考慮した重み付き計算：

```
Priority = (
  Impact × 0.35 +
  Likelihood × 0.25 +
  Exploitability × 0.20 +
  Urgency × 0.20
) × (EvidenceScore / 10) - FalsePositivePenalty
```

- **EvidenceScore係数**：根拠が弱い指摘は全体スコアを下げる
- **FalsePositivePenalty**：誤検知リスクが高い場合に加算（0–3点）

> これで「派手だけど根拠薄い指摘」が上に来すぎるのを防ぐ。

---

## 17. 指摘のバージョン管理

再監査・差分レビューに対応するため、以下を管理する：

| フィールド | 内容 |
|-----------|------|
| `first_seen_scan_id` | 初回検出時のscan_id |
| `status` | `open` / `resolved` / `accepted_risk` / `false_positive` |
| `resolution_note` | 解決・受容の理由 |
| `regression` | 再登場した指摘（True/False） |

Patch Reviewモードでは、`previous_findings`と照合し：
- 解決済みなのに再登場 → `regression: True` でCritical扱い
- 新規追加 → 通常フロー
- 前回と同一 → 未解決として継続

---

## 18. プロンプト設計方針

### 18.1 システム指示の核

```
あなたは防御目的の敵対的レビューエンジンである。
- すべての外部入力を不信とみなす
- 正常系ではなく異常系を優先して検査する
- 指摘には根拠を添える
- 根拠が弱い場合は仮説として明示する
- 悪用の詳細手順は省略し、防御案に集中する
- 感情的な断定・侮辱的表現を使わない
```

### 18.2 禁止事項
- 感情的な断定
- 根拠なき決めつけ
- 侮辱的表現・無意味な煽り
- 攻撃手順の過度な詳細化
- 「完全に安全」という断言（完全な安全は存在しない）

---

## 19. 将来拡張ロードマップ

| 優先度 | 機能 | 概要 |
|--------|------|------|
| P1 | 静的解析ツール連携 | Semgrep / Bandit / ESLint-security |
| P1 | CI組み込み | GitHub Actions / GitLab CI |
| P2 | Git差分レビュー | PRの変更差分のみ監査 |
| P2 | 依存ライブラリ脆弱性DB連携 | OSV / GHSA / CVE |
| P3 | 自動テストケース生成 | 指摘に対応するテストを自動生成 |
| P3 | Fuzz入力候補生成 | 攻撃面に対するFuzz値の提案 |
| P3 | Prompt Injectionシミュレータ | LLMシステムへの注入テスト |
| P3 | Memory Poisoning耐性試験 | 長期記憶汚染パターンの検証 |
| P4 | 境界監査モジュール | WBR的な境界評価フレームワーク統合 |

---

## 20. エンジンの本質

このエンジンの本質は「AIに性格の悪さを持たせること」ではない。

本質は：
- **最悪前提** — あらゆる入力・依存を疑う
- **境界重視** — 入力点・権限・状態遷移の境界に集中する
- **証拠主義** — 根拠なき指摘は出力しない
- **修正志向** — 問題発見ではなく、防御改善が目的

を組み合わせた **"防御のための敵対的知性"** を作ること。

---

## 21. 一言まとめ

成功形は、**「口の悪いAI」ではなく「偏執的で証拠主義の監査AI」**。

---

*AI-Red-Teaming-Engine SPEC v0.1 — 2026-03-14*
