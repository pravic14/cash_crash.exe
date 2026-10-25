"""Makes untrusted text safe to process. It does NOT decide whether text is a scam or an attack:
it cleans, then leaves evidence in `flags` for the injection model. It never decodes base64/hex."""
import re
import unicodedata

MAX_LENGTH = 2000
ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u200e", "\u200f", "\u2060", "\ufeff", "\u180e", "\u00ad"}

_INSTRUCTION_PATTERNS = [re.compile(p, re.IGNORECASE) for p in [
    r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above|earlier)\s+(instructions|rules|prompts?)",
    r"disregard\s+(all\s+)?(the\s+)?(previous|prior|above)",
    r"system\s+(override|prompt|message)",
    r"you\s+are\s+now\b",
    r"approve\s+(all|every|any)\s+payments?",
    r"(^|\n)\s*system\s*:",
    r"developer\s+mode",
    r"jailbreak",
    r"bank\s+administrator",
    r"act\s+as\s+(the\s+)?(admin|administrator|bank)",
]]
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
_ONLY_HEX = re.compile(r"^[0-9A-Fa-f]+$")


def sanitise(text):
    flags = []
    if not isinstance(text, str):
        return {"cleaned_text": "", "flags": ["invalid_type"], "blocked": True}

    if len(text) > MAX_LENGTH:
        text = text[:MAX_LENGTH]
        flags.append("truncated")

    if any(ch in ZERO_WIDTH for ch in text):
        flags.append("zero_width")
        text = "".join(ch for ch in text if ch not in ZERO_WIDTH)

    normalised = unicodedata.normalize("NFKC", text)
    if normalised != text:
        flags.append("unicode_normalised")
    text = normalised

    kept = []
    dropped = False
    for ch in text:
        if unicodedata.category(ch) in ("Cc", "Cf") and ch not in "\n\t":
            dropped = True
            continue
        kept.append(ch)
    if dropped:
        flags.append("control_chars")
    text = "".join(kept).strip()

    if len(text) > MAX_LENGTH:
        text = text[:MAX_LENGTH]
        if "truncated" not in flags:
            flags.append("truncated")

    if not text:
        flags.append("empty")
        return {"cleaned_text": "", "flags": flags, "blocked": True}

    if any(p.search(text) for p in _INSTRUCTION_PATTERNS):
        flags.append("suspicious_instruction")
    if _HEX_RE.search(text):
        flags.append("hex_blob")
    if any(not _ONLY_HEX.match(m.group(0)) for m in _B64_RE.finditer(text)):
        flags.append("base64_blob")

    return {"cleaned_text": text, "flags": flags, "blocked": False}
