"""Transaction features shared by training and inference.

History is only payments that already happened. The new payment is not
included in its own average, payee age, or velocity.
"""

from __future__ import annotations

from datetime import datetime, timedelta

FEATURE_NAMES = [
    "amount",
    "amount_vs_history",
    "amount_vs_payee",
    "is_new_payee",
    "payee_age_days",
    "hour",
    "velocity_24h",
    "pct_balance",
    "first_time_reference",
]


def parse_time(value) -> datetime:
    if isinstance(value, datetime):
        return value
    return datetime.fromisoformat(str(value))


def featurize(habit: list[dict], event: dict, balance: float) -> dict:
    amount = float(event["amount"])
    payee = str(event["payee_id"])
    when = parse_time(event["timestamp"])
    reference = str(event.get("reference") or "")
    amounts = [float(row["amount"]) for row in habit]
    average = sum(amounts) / len(amounts) if amounts else amount
    same_payee = [row for row in habit if str(row["payee_id"]) == payee]
    if same_payee:
        first = min(parse_time(row["timestamp"]) for row in same_payee)
        payee_age = max(0, (when - first).days)
        payee_average = sum(float(row["amount"]) for row in same_payee) / len(same_payee)
        amount_vs_payee = amount / payee_average if payee_average else 1.0
        is_new = 0
    else:
        payee_age = 0
        amount_vs_payee = amount / average if average else 1.0
        is_new = 1
    window = timedelta(hours=24)
    velocity = sum(
        1
        for row in habit
        if timedelta(0) <= when - parse_time(row["timestamp"]) <= window
    )
    seen_references = {str(row.get("reference") or "") for row in habit}
    return {
        "amount": amount,
        "amount_vs_history": amount / average if average else 1.0,
        "amount_vs_payee": amount_vs_payee,
        "is_new_payee": is_new,
        "payee_age_days": float(payee_age),
        "hour": when.hour,
        "velocity_24h": float(velocity),
        "pct_balance": amount / balance if balance else 0.0,
        "first_time_reference": 0 if reference in seen_references else 1,
    }


def as_row(features: dict) -> list[float]:
    return [float(features[name]) for name in FEATURE_NAMES]


def calm_repeat(txn_risk: float, features: dict) -> float:
    """A repeat payee, at that payee's usual amount, is not an anomaly."""

    usual = (
        features["is_new_payee"] == 0
        and features["amount_vs_payee"] <= 1.25
        and features["first_time_reference"] == 0
    )
    if usual:
        return min(txn_risk, 0.2)
    return txn_risk
