"""G0. Clean untrusted text before the parser and the models see it."""

from __future__ import annotations

import re
from dataclasses import dataclass

from rag.corpus import normalise

MAX_CHARS = 2000
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"(?<![A-Za-z0-9])(?:0x)?[0-9a-fA-F]{32,}(?![A-Za-z0-9])")


@dataclass
class Sanitised:
    text: str
    rejected: str | None = None
    stripped_encoded: bool = False


def sanitise(text: str) -> Sanitised:
    """NFKC, drop zero-width characters, and cut out long encoded blobs.

    A message over the length limit is rejected and is not parsed.
    """

    if not isinstance(text, str):
        return Sanitised("", "text was not a string")
    if len(text) > MAX_CHARS:
        return Sanitised("", "text is over the length limit")
    cleaned = normalise(text)
    stripped = False
    if _BASE64.search(cleaned) or _HEX.search(cleaned):
        cleaned = _HEX.sub(" ", _BASE64.sub(" ", cleaned))
        cleaned = " ".join(cleaned.split())
        stripped = True
    return Sanitised(cleaned, None, stripped)
