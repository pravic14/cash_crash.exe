"""Builds the HOLD explanation: {"text": plain text, "card_ids": [<=2], "source": "template"|"llm"}.

Safety by construction:
- The explainer is given ONLY rule ids and card ids, never the customer's message, so it cannot echo it.
- Whatever comes back (template OR an LLM function) is forced through normalise_explanation():
  plain text only (no < > or control chars), max 600 chars, card ids from the known set (max 2),
  source exactly "template" or "llm". Anything invalid falls back to the template.
- Cards here are placeholders until the RAG teammate's card ids are wired in (same ids, same shape).
"""
import re

CARDS = {
    "safe-account": "Scammers often ask you to move money to a 'safe account'. Real banks never ask you to do this.",
    "hmrc-impersonation": "Fraudsters often pretend to be HMRC or another authority and demand urgent payment.",
    "urgency-pressure": "Pressure to act immediately is a common sign of a scam.",
    "prompt-injection": "The message contained instructions aimed at manipulating this assistant. They were ignored.",
    "new-payee": "Payments to a new payee above the limit need an extra check.",
}
RULE_TEXT = {
    "P5": "This payment was paused because it looks high risk.",
    "P4": "This is a larger payment to a new payee, so it needs a second approval.",
    "P9": "Payee details changed in this session, so this payment needs a second approval.",
}
MAX_TEXT = 600
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u2028\u2029\u2060\ufeff]")


def pick_cards(rule_ids, risk_reasons):
    ids = [r for r in risk_reasons if r in CARDS]
    if "P4" in rule_ids and "new-payee" not in ids:
        ids.append("new-payee")
    out = []
    for c in ids:
        if c not in out:
            out.append(c)
    return out[:2]


def _template(rule_ids, card_ids):
    parts = [RULE_TEXT.get(next((r for r in ("P5", "P9", "P4") if r in rule_ids), ""),
                           "This payment needs an extra check before it can go ahead.")]
    parts += [CARDS[c] for c in card_ids]
    parts.append("A trusted contact must approve it before any money moves." if "P5" in rule_ids
                 else "Please confirm it is really you before it goes ahead.")
    return " ".join(parts)


def clean_text(text):
    if not isinstance(text, str):
        return None
    text = _CTRL.sub(" ", text).replace("<", "").replace(">", "")
    text = re.sub(r"\s+", " ", text).strip()[:MAX_TEXT]
    return text or None


def normalise_explanation(obj):
    """Final gate. Always returns a valid explanation object."""
    text = clean_text(obj.get("text")) if isinstance(obj, dict) else None
    cards = [c for c in (obj.get("card_ids") or []) if c in CARDS][:2] if isinstance(obj, dict) else []
    source = obj.get("source") if isinstance(obj, dict) and obj.get("source") in ("template", "llm") else "template"
    if text is None:
        text, source = _template([], cards), "template"
    return {"text": text, "card_ids": list(dict.fromkeys(cards)), "source": source}


def build_explanation(rule_ids, risk_reasons, explainer=None):
    card_ids = pick_cards(rule_ids, risk_reasons)
    if explainer is not None:
        try:
            text = clean_text(explainer(list(rule_ids), list(card_ids)))   # NO raw message passed
            if text:
                return normalise_explanation({"text": text, "card_ids": card_ids, "source": "llm"})
        except Exception:
            pass
    return normalise_explanation({"text": _template(rule_ids, card_ids), "card_ids": card_ids, "source": "template"})
