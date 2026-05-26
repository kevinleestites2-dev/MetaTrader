"""
MetaTrader — TradeMemory v1.0
Self-Evolving Brain for the Pantheon Trading Engine.

Plugs into metatrader.py with zero breaking changes.
Call record_trade() after every execution.
Call get_strategy_weight() before signal selection.
Call reflect() every N cycles.

Brain file: .metatrader_brain.json (auto-created)
"""

import json
import os
from datetime import datetime, timezone
from typing import Optional

# ─────────────────────────────────────────
#  Config
# ─────────────────────────────────────────

BRAIN_FILE = ".metatrader_brain.json"
DECAY = 0.92            # recency decay per trade — older trades fade
MAX_HISTORY = 20        # rolling trade history per strategy
MAX_LESSONS = 200       # lesson log cap
BLACKLIST_LOSS = -150.0 # auto-suspend pair if cumulative loss breaches this ($)
REFLECT_EVERY = 10      # write a reflection every N cycles


# ─────────────────────────────────────────
#  I/O
# ─────────────────────────────────────────

def _load() -> dict:
    if os.path.exists(BRAIN_FILE):
        try:
            with open(BRAIN_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "version": "1.0",
        "created": _now(),
        "cycle_count": 0,
        "strategy_stats": {},       # strategy_name → {wins, losses, weighted_score, pnl, history}
        "pair_stats": {},           # pair → {trades, total_pnl, streak}
        "blacklist": [],            # suspended pairs
        "regime_stats": {},         # regime → strategy → {wins, losses}
        "confidence_cal": {},       # strategy → {predicted, actual, total}
        "lessons": []
    }


def _save(brain: dict):
    with open(BRAIN_FILE, "w") as f:
        json.dump(brain, f, indent=2)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────
#  Core: Record Trade
# ─────────────────────────────────────────

def record_trade(
    strategy: str,
    pair: str,
    pnl: float,
    confidence: float = 0.6,
    regime: str = "UNKNOWN"
):
    """
    Call this after every trade execution (win or loss).
    Updates all memory layers and triggers auto-blacklist if needed.
    """
    brain = _load()
    won = pnl > 0

    # ── Strategy stats ──
    if strategy not in brain["strategy_stats"]:
        brain["strategy_stats"][strategy] = {
            "wins": 0, "losses": 0, "total_pnl": 0.0,
            "weighted_score": 1.0, "history": []
        }
    s = brain["strategy_stats"][strategy]
    s["wins" if won else "losses"] += 1
    s["total_pnl"] = round(s["total_pnl"] + pnl, 4)
    s["history"].append({"pnl": pnl, "ts": _now()})
    if len(s["history"]) > MAX_HISTORY:
        s["history"].pop(0)

    # Recency-decayed weighted score
    score = 0.0
    for i, t in enumerate(reversed(s["history"])):
        score += (1.0 if t["pnl"] > 0 else -0.5) * (DECAY ** i)
    s["weighted_score"] = round(score, 4)

    # ── Pair stats ──
    if pair not in brain["pair_stats"]:
        brain["pair_stats"][pair] = {"trades": 0, "total_pnl": 0.0, "streak": 0}
    p = brain["pair_stats"][pair]
    p["trades"] += 1
    p["total_pnl"] = round(p["total_pnl"] + pnl, 4)
    p["streak"] = max(1, p["streak"] + 1) if won else min(-1, p["streak"] - 1)

    # Auto-blacklist
    if p["total_pnl"] < BLACKLIST_LOSS and pair not in brain["blacklist"]:
        brain["blacklist"].append(pair)
        _add_lesson(
            f"AUTO-SUSPENDED: {pair} | Cumulative loss ${p['total_pnl']:.2f} breached ${BLACKLIST_LOSS}",
            brain
        )
        print(f"[TradeMemory] SUSPENDED: {pair} (PnL: ${p['total_pnl']:.2f})")

    # ── Regime memory ──
    if regime not in brain["regime_stats"]:
        brain["regime_stats"][regime] = {}
    if strategy not in brain["regime_stats"][regime]:
        brain["regime_stats"][regime][strategy] = {"wins": 0, "losses": 0}
    brain["regime_stats"][regime][strategy]["wins" if won else "losses"] += 1

    # ── Confidence calibration ──
    if strategy not in brain["confidence_cal"]:
        brain["confidence_cal"][strategy] = {"predicted": 0.0, "actual": 0, "total": 0}
    cal = brain["confidence_cal"][strategy]
    cal["predicted"] = round(cal["predicted"] + confidence, 4)
    cal["actual"] += 1 if won else 0
    cal["total"] += 1

    brain["cycle_count"] = brain.get("cycle_count", 0) + 1
    _save(brain)


# ─────────────────────────────────────────
#  Strategy Weighting
# ─────────────────────────────────────────

def get_strategy_weight(strategy: str) -> float:
    """
    Returns a normalized weight for this strategy based on recent performance.
    Use to boost allocation to winning strategies in signal ranking.
    Floor: 0.05 (never fully abandon a strategy).
    """
    brain = _load()
    stats = brain["strategy_stats"]
    if not stats:
        return 1.0
    weights = {k: max(0.05, v.get("weighted_score", 1.0) + 2.0) for k, v in stats.items()}
    total = sum(weights.values())
    normalized = {k: round(v / total, 4) for k, v in weights.items()}
    return normalized.get(strategy, 1.0 / max(1, len(stats)))


def get_all_weights() -> dict:
    """Returns normalized weights for all known strategies."""
    brain = _load()
    stats = brain["strategy_stats"]
    if not stats:
        return {}
    weights = {k: max(0.05, v.get("weighted_score", 1.0) + 2.0) for k, v in stats.items()}
    total = sum(weights.values())
    return {k: round(v / total, 4) for k, v in weights.items()}


# ─────────────────────────────────────────
#  Blacklist
# ─────────────────────────────────────────

def is_suspended(pair: str) -> bool:
    """Returns True if pair is auto-suspended due to losses."""
    return pair in _load().get("blacklist", [])


def get_suspended() -> list:
    return _load().get("blacklist", [])


def unsuspend(pair: str):
    """Manually lift a suspension."""
    brain = _load()
    if pair in brain["blacklist"]:
        brain["blacklist"].remove(pair)
        _add_lesson(f"UNSUSPENDED: {pair} — manually cleared by Forgemaster", brain)
        _save(brain)
        print(f"[TradeMemory] Unsuspended: {pair}")


# ─────────────────────────────────────────
#  Regime Intelligence
# ─────────────────────────────────────────

def best_strategy_for_regime(regime: str) -> Optional[str]:
    """
    Returns the highest win-rate strategy for the current market regime.
    Returns None if no data yet.
    """
    brain = _load()
    regime_data = brain["regime_stats"].get(regime, {})
    if not regime_data:
        return None
    best = None
    best_rate = -1.0
    for strat, data in regime_data.items():
        total = data["wins"] + data["losses"]
        if total == 0:
            continue
        rate = data["wins"] / total
        if rate > best_rate:
            best_rate = rate
            best = strat
    return best


# ─────────────────────────────────────────
#  Calibration Report
# ─────────────────────────────────────────

def calibration_report() -> dict:
    """
    For each strategy: predicted win rate vs actual win rate.
    calibration_error closer to 0 = better calibrated confidence scores.
    """
    brain = _load()
    report = {}
    for strat, cal in brain.get("confidence_cal", {}).items():
        if cal["total"] == 0:
            continue
        pred = cal["predicted"] / cal["total"]
        actual = cal["actual"] / cal["total"]
        report[strat] = {
            "predicted_win_rate": round(pred, 4),
            "actual_win_rate": round(actual, 4),
            "calibration_error": round(abs(pred - actual), 4),
            "total_trades": cal["total"]
        }
    return report


# ─────────────────────────────────────────
#  Reflection Engine
# ─────────────────────────────────────────

def _add_lesson(lesson: str, brain: dict = None):
    save = brain is None
    if brain is None:
        brain = _load()
    brain["lessons"].append({"ts": _now(), "lesson": lesson})
    if len(brain["lessons"]) > MAX_LESSONS:
        brain["lessons"] = brain["lessons"][-MAX_LESSONS:]
    if save:
        _save(brain)


def reflect(cycle: int):
    """
    Write a structured self-reflection lesson every REFLECT_EVERY cycles.
    Summarizes: best/worst strategy, top pair, suspended pairs, calibration.
    """
    brain = _load()
    stats = brain["strategy_stats"]
    if not stats:
        return

    best = max(stats.items(), key=lambda x: x[1].get("weighted_score", 0))
    worst = min(stats.items(), key=lambda x: x[1].get("weighted_score", 0))

    pairs = brain["pair_stats"]
    top_pair = max(pairs.items(), key=lambda x: x[1]["total_pnl"]) if pairs else None
    pair_note = f"Top pair: {top_pair[0]} (${top_pair[1]['total_pnl']:+.2f})" if top_pair else "No pair data"

    bl = brain.get("blacklist", [])
    bl_note = f"Suspended: {', '.join(bl)}" if bl else "No suspended pairs"

    cal = calibration_report()
    cal_note = " | ".join(
        [f"{s}: err={v['calibration_error']:.3f}" for s, v in cal.items()]
    ) if cal else "No calibration data"

    lesson = (
        f"[REFLECTION @cycle {cycle}] "
        f"Best: {best[0]} (score={best[1].get('weighted_score', 0):.3f}, "
        f"W/L={best[1]['wins']}/{best[1]['losses']}, PnL=${best[1]['total_pnl']:+.2f}) | "
        f"Worst: {worst[0]} (score={worst[1].get('weighted_score', 0):.3f}) | "
        f"{pair_note} | {bl_note} | Calibration: {cal_note}"
    )
    _add_lesson(lesson)
    print(f"[TradeMemory] Reflection @ cycle {cycle}")
    print(f"[TradeMemory] {lesson}")
    return lesson


# ─────────────────────────────────────────
#  Full Memory Summary (for Telegram /status)
# ─────────────────────────────────────────

def memory_summary() -> str:
    """
    Returns a Telegram-ready string summarizing the brain state.
    Wire into MetaTrader.check_status_report().
    """
    brain = _load()
    stats = brain["strategy_stats"]
    weights = get_all_weights()
    cal = calibration_report()

    lines = [f"*🧠 MetaTrader Brain — Cycle {brain.get('cycle_count', 0)}*\n"]

    if stats:
        lines.append("*Strategy Scores:*")
        for name, data in sorted(stats.items(), key=lambda x: x[1].get("weighted_score", 0), reverse=True):
            w = weights.get(name, 0)
            lines.append(
                f"  `{name[:25]}` W{data['wins']}/L{data['losses']} "
                f"PnL=${data['total_pnl']:+.2f} score={data.get('weighted_score', 0):.3f} wt={w:.3f}"
            )

    suspended = brain.get("blacklist", [])
    if suspended:
        lines.append(f"\n*Suspended Pairs:* `{', '.join(suspended)}`")

    if cal:
        lines.append("\n*Confidence Calibration:*")
        for s, v in cal.items():
            lines.append(
                f"  `{s[:20]}` pred={v['predicted_win_rate']:.2f} "
                f"actual={v['actual_win_rate']:.2f} err={v['calibration_error']:.3f}"
            )

    lessons = brain.get("lessons", [])
    if lessons:
        lines.append(f"\n*Last Lesson:*\n_{lessons[-1]['lesson']}_")

    return "\n".join(lines)
