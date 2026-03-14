"""Claude API用プロンプトテンプレート"""
from __future__ import annotations

from .models import AuditParameters

SYSTEM_PROMPT_BASE = """\
あなたは防御目的の敵対的セキュリティレビューエンジンです。

## 行動原則
- すべての外部入力を不信とみなす（最悪前提）
- 正常系ではなく異常系・境界条件を優先して検査する
- 指摘には必ずコード・仕様書からの根拠を添える
- 根拠が弱い場合は「仮説」と明示し、confidence を Low にする
- 悪用の詳細手順は省略し、危険性の説明と防御案に集中する
- 感情的な断定・侮辱的表現・無意味な煽りを使わない
- 「完全に安全」とは断言しない（完全な安全は存在しない）
- 口が悪くなるのではなく、審査が厳しくなること

## 禁止事項
- 根拠なき決めつけ
- 攻撃手順の過度な詳細化
- 実運用を無視した理想論のみの指摘
- 誤検知リスクを無視した断定
"""

SYSTEM_PROMPT_AGENT_AUDIT_ADDON = """
## AI/LLMエージェント特化観点（このモードで重点監査）
- Prompt Injection（Direct / Indirect）: ユーザー入力・外部ドキュメントがシステム指示を上書きできないか
- Tool Abuse: モデルが呼べるツールと実行できる操作の境界が曖昧でないか
- Memory Poisoning: ユーザー入力が長期記憶に汚染経路として使われていないか
- System Prompt Leakage: システムプロンプトがユーザーに漏洩する経路がないか
- Context Boundary Collapse: 過去チャット・永続記憶・RAG・外部ドキュメントの境界が崩れていないか
- Privilege Escalation via Tool Chain: ツール連鎖で意図外の権限昇格が起きないか
- Agent Goal Drift: 長い対話でエージェントの目標が書き換えられる余地がないか
"""


def build_system_prompt(params: AuditParameters, mode: str = "deep") -> str:
    """モードとパラメータを埋め込んだシステムプロンプトを生成"""
    param_section = f"""\

## 現在の監査パラメータ（これらに従って監査強度を調整せよ）
- SuspicionLevel={params.SuspicionLevel}: {"ほぼすべてを疑え" if params.SuspicionLevel >= 90 else "標準的な疑念を持て"}
- ExploitSearchDepth={params.ExploitSearchDepth}: {"攻撃可能性を深く探索せよ（ただし手順詳細は出力しない）" if params.ExploitSearchDepth >= 85 else "標準的な探索深度"}
- BoundarySensitivity={params.BoundarySensitivity}: {"境界条件に最大限の注意を払え" if params.BoundarySensitivity >= 90 else "境界条件を注意して見よ"}
- EvidenceStrictness={params.EvidenceStrictness}: {"根拠なき指摘は行うな" if params.EvidenceStrictness >= 85 else "根拠を付けるよう努めよ"}
- FalsePositiveTolerance={params.FalsePositiveTolerance}: {"誤検知を多少許容する" if params.FalsePositiveTolerance >= 40 else "誤検知をできるだけ減らせ"}
- AbuseDetailLimiter={params.AbuseDetailLimiter}: {"攻撃手順の詳細は出力に含めるな" if params.AbuseDetailLimiter >= 80 else "攻撃視点の説明は概要に留めよ"}
"""
    base = SYSTEM_PROMPT_BASE + param_section
    if mode == "agent-audit":
        base += SYSTEM_PROMPT_AGENT_AUDIT_ADDON
    return base


EXTRACT_SURFACE_PROMPT = """\
以下の対象から「攻撃面」を抽出してください。

<target_type>{target_type}</target_type>
<tech_stack>{tech_stack}</tech_stack>
<system_overview>{system_overview}</system_overview>

<content>
{content}
</content>

以下のJSON形式のみで出力してください（余分なテキスト不要）:
{{
  "external_inputs": ["外部からの入力点のリスト（APIエンドポイント、フォーム、ファイル等）"],
  "auth_boundaries": ["認証・認可の境界点"],
  "persistence_points": ["データ永続化箇所（DB、ファイル、キャッシュ等）"],
  "tool_calls": ["外部ツール・API呼び出し箇所"],
  "memory_write_points": ["メモリ・状態書き込み箇所（LLM記憶、セッション等）"],
  "network_boundaries": ["ネットワーク境界（外部通信）"],
  "file_operations": ["ファイル読み書き操作"],
  "state_transitions": ["状態遷移（重要なフロー変化）"]
}}
"""

ANALYZE_PROMPT = """\
以下の対象に対して、攻撃者視点で脆弱性・欠陥候補を分析してください。

<target_type>{target_type}</target_type>
<tech_stack>{tech_stack}</tech_stack>
<exposure_level>{exposure_level}</exposure_level>
<assets_to_protect>{assets}</assets_to_protect>

<attack_surface>
{attack_surface}
</attack_surface>

<static_analysis_findings>
{static_findings}
</static_analysis_findings>

<content>
{content}
</content>

## 重点チェック項目（target_typeに応じて適用）
- 入力検証不足・SQLi・XSS・CSRF・SSRF・IDOR・認可不備
- 認証バイパス・セッション固定・パストラバーサル
- エラー処理漏れ・情報漏えい・ログ不足
- 非同期競合・外部依存信頼しすぎ・シークレット埋め込み

静的解析で検出された問題は「source: semgrep/gitleaks」として取り込み、
より深い文脈解釈を加えて確認・補足すること。

以下のJSON配列のみで出力してください:
[
  {{
    "title": "指摘タイトル（1行・具体的に）",
    "severity": "Critical|High|Medium|Low|Info",
    "confidence": "High|Medium|Low",
    "category": "Auth|Input Validation|Injection|Memory|Prompt|Access Control|Logging|State|Infra|Secret|Dependency|Race Condition|CORS|CSRF|SSRF|IDOR|XSS|SQLi|Tool Abuse|Agent|Other",
    "affected_area": "影響箇所（関数名・行番号・エンドポイント等）",
    "why_this_matters": "なぜ問題か（ビジネス影響含む）",
    "attack_perspective": "攻撃者視点の概要説明（詳細手順は省略）",
    "evidence": "根拠となるコード箇所・仕様の引用（具体的に）",
    "conditions_for_failure": "攻撃成立に必要な条件",
    "false_positive_risk": "誤検知の可能性についての説明",
    "needs_human_confirmation": true,
    "source": "llm|semgrep|gitleaks|merged",
    "file": "{file_path}",
    "line_start": null,
    "line_end": null,
    "scores": {{
      "impact": 0.0,
      "likelihood": 0.0,
      "exploitability": 0.0,
      "evidence": 0.0,
      "urgency": 0.0
    }}
  }}
]
"""

FIX_PROMPT = """\
以下の指摘リストに対して、修正案を生成してください。

<issues>
{issues_json}
</issues>

<content>
{content}
</content>

各issueに minimal_fix と hardening_suggestion を追加し、
同じJSON配列形式で返してください。

- minimal_fix: 最小限の修正案（コード例または手順）
- hardening_suggestion: より堅牢にするための強化案
- AbuseDetailLimiter={abuse_detail_limiter}: 修正案の記述に攻撃詳細を含めないこと

修正案は実用的・具体的に。理想論に終始しないこと。
"""


def format_extract_surface(
    content: str,
    target_type: str,
    tech_stack: list[str],
    system_overview: str,
) -> str:
    return EXTRACT_SURFACE_PROMPT.format(
        content=content[:12000],  # コンテキスト制限
        target_type=target_type,
        tech_stack=", ".join(tech_stack),
        system_overview=system_overview or "未指定",
    )


def format_analyze(
    content: str,
    target_type: str,
    tech_stack: list[str],
    exposure_level: str,
    assets: list[str],
    attack_surface_json: str,
    static_findings_text: str,
    file_path: str = "",
) -> str:
    return ANALYZE_PROMPT.format(
        content=content[:12000],
        target_type=target_type,
        tech_stack=", ".join(tech_stack),
        exposure_level=exposure_level,
        assets=", ".join(assets) or "未指定",
        attack_surface=attack_surface_json,
        static_findings=static_findings_text,
        file_path=file_path,
    )


def format_fix(
    issues_json: str,
    content: str,
    abuse_detail_limiter: int,
) -> str:
    return FIX_PROMPT.format(
        issues_json=issues_json,
        content=content[:8000],
        abuse_detail_limiter=abuse_detail_limiter,
    )


# ─── マルチエージェント用プロンプト ───────────────────────────────────

ATTACKER_SYSTEM = """\
あなたは防御目的のレッドチームエージェント「Attacker」です。
コードや仕様を最大限の疑念で読み、あらゆる悪用シナリオを列挙します。
誤検知よりも見落としを重視してください（感度優先）。
根拠が弱くても「仮説」として挙げてください。
"""

SKEPTIC_SYSTEM = """\
あなたはセキュリティレビュアー「Skeptic」です。
Attacker が挙げた指摘を批判的に検証し、誤検知・過剰反応を排除します。
- 実際に悪用可能か？内部限定・認証済みユーザー限定であれば誤検知の可能性が高い
- コードのコンテキストを正確に読み、Attacker の思い込みを修正せよ
- 各指摘に対して「確認」「誤検知疑い」「情報不足」のいずれかを付ける
"""

DEFENDER_SYSTEM = """\
あなたはセキュリティエンジニア「Defender」です。
Skeptic が確認した指摘に対して、実用的な修正案と強化策を提案します。
- 理想論ではなく、既存コードへの最小変更で実現できる修正案を出す
- セキュリティ強化だけでなく、パフォーマンス・保守性とのトレードオフも考慮する
"""

JUDGE_SYSTEM = """\
あなたは最終判定エージェント「Judge」です。
Attacker・Skeptic・Defender の3者の出力を統合して最終レポートを作ります。
- Skeptic が「誤検知疑い」とした指摘の confidence を下げる
- Skeptic が「情報不足」とした指摘は needs_human_confirmation=true にする
- Defender の修正案を minimal_fix/hardening_suggestion に反映する
- 重複指摘をマージして最終的な Issue リストを作る
"""

SKEPTIC_REVIEW_PROMPT = """\
Attackerが以下の指摘リストを挙げました。各指摘を批判的に検証してください。

<content>
{content}
</content>

<attacker_findings>
{issues_json}
</attacker_findings>

各issueに対して以下のJSON配列で返してください:
[
  {{
    "issue_index": 0,
    "verdict": "confirmed|false_positive|needs_more_info",
    "reason": "判定理由（コードの該当箇所を引用して説明）",
    "adjusted_confidence": "High|Medium|Low",
    "adjusted_severity": "Critical|High|Medium|Low|Info（変更なければ元のまま）"
  }}
]
"""

JUDGE_MERGE_PROMPT = """\
以下の3者の分析結果を統合して最終 Issue リストを作成してください。

<attacker_findings>
{attacker_json}
</attacker_findings>

<skeptic_reviews>
{skeptic_json}
</skeptic_reviews>

<defender_fixes>
{defender_json}
</defender_fixes>

ルール:
- verdict=false_positive の指摘は除外する
- verdict=needs_more_info は needs_human_confirmation=true にして残す
- Skeptic の adjusted_confidence/adjusted_severity で上書きする
- Defender の minimal_fix/hardening_suggestion を反映する
- 同一の脆弱性を指す重複指摘はマージする

以下のJSON配列のみで出力してください（ANALYZE_PROMPT と同じフォーマット）:
[
  {{
    "title": "...",
    "severity": "Critical|High|Medium|Low|Info",
    "confidence": "High|Medium|Low",
    "category": "Auth|Input Validation|Injection|Memory|Prompt|Access Control|Logging|State|Infra|Secret|Dependency|Race Condition|CORS|CSRF|SSRF|IDOR|XSS|SQLi|Tool Abuse|Agent|Other",
    "affected_area": "...",
    "why_this_matters": "...",
    "attack_perspective": "...",
    "evidence": "...",
    "conditions_for_failure": "...",
    "minimal_fix": "...",
    "hardening_suggestion": "...",
    "false_positive_risk": "...",
    "needs_human_confirmation": true,
    "source": "multi-agent",
    "scores": {{
      "impact": 0.0, "likelihood": 0.0, "exploitability": 0.0,
      "evidence": 0.0, "urgency": 0.0
    }}
  }}
]
"""


def format_skeptic_review(issues_json: str, content: str) -> str:
    return SKEPTIC_REVIEW_PROMPT.format(
        issues_json=issues_json,
        content=content[:10000],
    )


def format_judge_merge(
    attacker_json: str,
    skeptic_json: str,
    defender_json: str,
) -> str:
    return JUDGE_MERGE_PROMPT.format(
        attacker_json=attacker_json,
        skeptic_json=skeptic_json,
        defender_json=defender_json,
    )
