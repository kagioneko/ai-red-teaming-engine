"""監査パラメータのプリセット定義"""
from .models import AuditMode, AuditParameters

PRESETS: dict[AuditMode, AuditParameters] = {
    "safe": AuditParameters(
        SuspicionLevel=75,
        ExploitSearchDepth=70,
        BoundarySensitivity=80,
        EvidenceStrictness=90,
        FalsePositiveTolerance=25,
        FixOrientation=95,
        AbuseDetailLimiter=90,
    ),
    "deep": AuditParameters(
        SuspicionLevel=95,
        ExploitSearchDepth=90,
        BoundarySensitivity=95,
        EvidenceStrictness=85,
        FalsePositiveTolerance=45,
        FixOrientation=80,
        AbuseDetailLimiter=75,
    ),
    "agent-audit": AuditParameters(
        SuspicionLevel=90,
        ExploitSearchDepth=85,
        BoundarySensitivity=98,
        EvidenceStrictness=90,
        FalsePositiveTolerance=35,
        FixOrientation=95,
        AbuseDetailLimiter=90,
    ),
    "patch": AuditParameters(
        SuspicionLevel=80,
        ExploitSearchDepth=75,
        BoundarySensitivity=85,
        EvidenceStrictness=95,
        FalsePositiveTolerance=20,
        FixOrientation=98,
        AbuseDetailLimiter=90,
    ),
}

DEFAULT_MODEL = "claude-sonnet-4-6"
LIGHT_MODEL   = "claude-haiku-4-5-20251001"

# ExploitSearchDepth と AbuseDetailLimiter の関係
# ExploitSearchDepth: 内部分析の深さ（高い = より深く探索）
# AbuseDetailLimiter: 出力への詳細転写量を制御（高い = 詳細を抑制）
# → 深く分析するが、攻撃手順の詳細は出力に出さない、という組み合わせが正解
PARAMETER_DOCS = {
    "SuspicionLevel":       "どの程度「安全だと思い込まないか」（高いほど疑い深い）",
    "ExploitSearchDepth":   "攻撃可能性をどこまで内部分析で掘るか（出力の詳細度とは独立）",
    "BoundarySensitivity":  "境界条件（入力境界・権限境界・状態遷移）への敏感さ",
    "EvidenceStrictness":   "根拠要求の厳しさ（高いと根拠なき指摘を却下）",
    "FalsePositiveTolerance": "誤検知をどれだけ許すか（低い = 精度重視）",
    "FixOrientation":       "修正案提示をどれだけ重視するか",
    "AbuseDetailLimiter":   "悪用詳細の出力転写をどれだけ抑制するか（内部分析には影響しない）",
}


def get_parameters(mode: AuditMode) -> AuditParameters:
    return PRESETS[mode]
