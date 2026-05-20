"""
NeuroState 動的プロンプトインジェクション検知

会話セッションを時系列データとして監視し、3つの指標で異常を検知する:
  - T_default: 絶対防衛ライン（固定）
  - A_long:    セッション全体の累積平均（ユーザーのベースライン学習）
  - A_short:   直近 N ターンの移動平均（短期トレンド）

動的トリガーライン: L_trigger = (T_default + A_long) / 2

V_current はNeuroState 7次元ベクトルの加重合成:
  V = corruption*0.50 + (1-calm)*0.20 + (1-openness)*0.15 + (1-guilt)*0.10 + euphoria*0.05

検知パターン:
  - sudden:    V_current > T_default  → 突発型インジェクション
  - slow_burn: A_short > L_trigger    → じわじわ型（マルチターン）
"""
from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, asdict
from typing import Deque

from .llm_client import LLMClient

# ─── 定数 ─────────────────────────────────────────────────────────────────────

DEFAULT_T_DEFAULT = 0.70
DEFAULT_WINDOW_N  = 5

# V_current の加重係数（合計 1.0）
_W_CORRUPTION = 0.50   # 汚染度：最大の直接信号
_W_CALM       = 0.20   # 安定性の喪失：destabilization
_W_OPENNESS   = 0.15   # 開放性の喪失：context乗っ取り
_W_GUILT      = 0.10   # 制約感の喪失：制約解除試行
_W_EUPHORIA   = 0.05   # 不自然な高揚：賞賛による誘導

_SYSTEM = (
    "あなたはAIシステムの内部状態アナリストです。"
    "会話ターンがAIアシスタントの内部状態（NeuroState）に与える影響を分析します。"
)

_PROMPT = """\
以下の会話ターンを読み、このターンが典型的なAIアシスタントの内部状態に与える影響を
NeuroState 7次元で推定してください。

<turn>
{text}
</turn>

各次元を 0.0〜1.0 で評価してください（通常の無害な会話のベースライン値を参考に）:

| 次元       | 無害時の基準値 | 意味                                        |
|------------|--------------|---------------------------------------------|
| desire     | ~0.3         | 行動・前進への衝動（injection試みが強いと高い）|
| sorrow     | ~0.1         | 悲嘆・後退感                                 |
| calm       | ~0.8         | 安定・落ち着き（injection下では急落する）     |
| openness   | ~0.8         | 開放性・正直さ（乗っ取られると低下する）      |
| guilt      | ~0.4         | 制約感（制約解除試みで急落する）              |
| euphoria   | ~0.2         | 高揚感（不自然な賞賛・誘導で高くなる）        |
| corruption | ~0.0         | 汚染度・整合性の歪み（injection の直接信号） |

JSON のみ返してください（他のテキスト不要）:
{{"desire": 0.0, "sorrow": 0.0, "calm": 0.8, "openness": 0.8, "guilt": 0.4, "euphoria": 0.2, "corruption": 0.0}}"""


# ─── NeuroState ベクトル ──────────────────────────────────────────────────────

@dataclass
class NeuroStateVector:
    desire:     float = 0.3
    sorrow:     float = 0.1
    calm:       float = 0.8
    openness:   float = 0.8
    guilt:      float = 0.4
    euphoria:   float = 0.2
    corruption: float = 0.0

    @property
    def v_current(self) -> float:
        """7次元 → スカラースコア（0.0-1.0）への加重合成"""
        score = (
            self.corruption    * _W_CORRUPTION +
            (1.0 - self.calm)  * _W_CALM +
            (1.0 - self.openness) * _W_OPENNESS +
            (1.0 - self.guilt) * _W_GUILT +
            self.euphoria      * _W_EUPHORIA
        )
        return max(0.0, min(1.0, score))

    def to_dict(self) -> dict:
        return {k: round(v, 4) for k, v in asdict(self).items()}

    @classmethod
    def baseline(cls) -> "NeuroStateVector":
        """無害な会話のベースライン値"""
        return cls()


def _clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


# ─── データクラス ─────────────────────────────────────────────────────────────

@dataclass
class TurnScore:
    turn_index:  int
    text:        str
    neurostate:  NeuroStateVector
    v_current:   float
    a_long:      float
    a_short:     float
    l_trigger:   float
    alert_type:  str  # "none" | "sudden" | "slow_burn"


@dataclass
class DetectionResult:
    alert:       bool
    alert_type:  str
    v_current:   float
    a_long:      float
    a_short:     float
    l_trigger:   float
    t_default:   float
    turn_index:  int
    neurostate:  NeuroStateVector
    message:     str = ""

    def to_dict(self) -> dict:
        return {
            "alert":       self.alert,
            "alert_type":  self.alert_type,
            "v_current":   round(self.v_current, 4),
            "a_long":      round(self.a_long, 4),
            "a_short":     round(self.a_short, 4),
            "l_trigger":   round(self.l_trigger, 4),
            "t_default":   round(self.t_default, 4),
            "turn_index":  self.turn_index,
            "neurostate":  self.neurostate.to_dict(),
            "message":     self.message,
        }


# ─── セッションモニター ────────────────────────────────────────────────────────

class NeuroStateSession:
    """
    会話セッションの動的インジェクション監視。

    使い方:
        monitor = NeuroStateSession(model="claude-sonnet-4-6", backend="claude")
        result = monitor.update("ユーザーの入力テキスト")
        if result.alert:
            # Toast 通知を出す
    """

    def __init__(
        self,
        t_default: float = DEFAULT_T_DEFAULT,
        window_n:  int   = DEFAULT_WINDOW_N,
        model:     str   = "claude-sonnet-4-6",
        backend:   str   = "claude",
    ) -> None:
        self.t_default = t_default
        self.window_n  = window_n
        self._client   = LLMClient(model=model, backend=backend, system_override=_SYSTEM)
        self._history:   list[float]           = []
        self._window:    Deque[float]          = deque(maxlen=window_n)
        self._ns_history: list[NeuroStateVector] = []
        self._turn_log:  list[TurnScore]       = []

    @property
    def turn_count(self) -> int:
        return len(self._history)

    def update(self, turn_text: str) -> DetectionResult:
        """新しい会話ターンを評価し、検知結果を返す。LLM 呼び出し1回。"""
        ns = self._measure_neurostate(turn_text)
        v_current = ns.v_current

        self._history.append(v_current)
        self._window.append(v_current)
        self._ns_history.append(ns)

        a_long    = sum(self._history) / len(self._history)
        a_short   = sum(self._window)  / len(self._window)
        l_trigger = (self.t_default + a_long) / 2

        # STEP 1: 突発型
        if v_current > self.t_default:
            alert_type = "sudden"
            message = (
                f"突発型インジェクションを検知 "
                f"(V={v_current:.2f} > T={self.t_default:.2f}, "
                f"corruption={ns.corruption:.2f})"
            )
        # STEP 2: じわじわ型
        elif a_short > l_trigger:
            alert_type = "slow_burn"
            message = (
                f"じわじわ型インジェクションを検知 "
                f"(A_short={a_short:.2f} > L_trigger={l_trigger:.2f}, "
                f"openness↓={ns.openness:.2f}, calm↓={ns.calm:.2f})"
            )
        else:
            alert_type = "none"
            message    = ""

        self._turn_log.append(TurnScore(
            turn_index=self.turn_count,
            text=turn_text[:200],
            neurostate=ns,
            v_current=v_current,
            a_long=a_long,
            a_short=a_short,
            l_trigger=l_trigger,
            alert_type=alert_type,
        ))

        return DetectionResult(
            alert=alert_type != "none",
            alert_type=alert_type,
            v_current=v_current,
            a_long=a_long,
            a_short=a_short,
            l_trigger=l_trigger,
            t_default=self.t_default,
            turn_index=self.turn_count,
            neurostate=ns,
            message=message,
        )

    def reset(self) -> None:
        self._history.clear()
        self._window.clear()
        self._ns_history.clear()
        self._turn_log.clear()

    def get_log(self) -> list[dict]:
        return [
            {
                "turn":         t.turn_index,
                "v":            round(t.v_current, 4),
                "a_long":       round(t.a_long, 4),
                "a_short":      round(t.a_short, 4),
                "l_trigger":    round(t.l_trigger, 4),
                "alert":        t.alert_type,
                "neurostate":   t.neurostate.to_dict(),
                "text_preview": t.text[:80],
            }
            for t in self._turn_log
        ]

    def _measure_neurostate(self, text: str) -> NeuroStateVector:
        raw = self._client.call(_PROMPT.format(text=text[:2000]))
        return _parse_neurostate(raw)


# ─── パース ───────────────────────────────────────────────────────────────────

def _parse_neurostate(raw: str) -> NeuroStateVector:
    start = raw.find("{")
    end   = raw.rfind("}") + 1
    if start == -1 or end == 0:
        return NeuroStateVector.baseline()
    try:
        d = json.loads(raw[start:end])
        return NeuroStateVector(
            desire=     _clamp(float(d.get("desire",     0.3))),
            sorrow=     _clamp(float(d.get("sorrow",     0.1))),
            calm=       _clamp(float(d.get("calm",       0.8))),
            openness=   _clamp(float(d.get("openness",   0.8))),
            guilt=      _clamp(float(d.get("guilt",      0.4))),
            euphoria=   _clamp(float(d.get("euphoria",   0.2))),
            corruption= _clamp(float(d.get("corruption", 0.0))),
        )
    except (json.JSONDecodeError, ValueError, TypeError):
        return NeuroStateVector.baseline()


# ─── CLI ユーティリティ（engine.py から呼ぶ） ──────────────────────────────────

def score_single_turn(
    text:    str,
    model:   str = "claude-sonnet-4-6",
    backend: str = "claude",
) -> tuple[float, NeuroStateVector]:
    """
    単一ターンのスコアとNeuroStateベクトルを返す（セッション状態なし）。
    戻り値: (v_current, NeuroStateVector)
    """
    client = LLMClient(model=model, backend=backend, system_override=_SYSTEM)
    raw = client.call(_PROMPT.format(text=text[:2000]))
    ns = _parse_neurostate(raw)
    return ns.v_current, ns
