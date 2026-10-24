"""Trusted scam cards and bank-policy clauses.

Files under rag/cards and rag/policies are the corpus. User messages are never
written here. A saved index is a hash snapshot: if a file changes, callers
must refuse that index and rebuild it.
"""

from __future__ import annotations

import hashlib
import os
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CARDS_DIR = ROOT / "rag" / "cards"
POLICIES_DIR = ROOT / "rag" / "policies"

_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff\u2060"), None)


class CorpusRefused(Exception):
    """The on-disk corpus does not match the index snapshot."""


def normalise(text: str) -> str:
    """NFKC plus strip zero-width characters. Sanitiser G0 still owns the full gate."""

    return unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH).strip()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def index_dir() -> Path:
    override = os.environ.get("RAG_INDEX_DIR")
    return Path(override) if override else ROOT / "rag" / "index"


def parse_markdown(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8")
    if not raw.startswith("---"):
        raise ValueError(f"{path} is missing front matter")
    parts = raw.split("---", 2)
    if len(parts) < 3:
        raise ValueError(f"{path} front matter is not closed")
    data: dict = {
        "body": parts[2].strip(),
        "patterns": [],
        "red_flags": [],
        "bank_never_asks": [],
        "path": path,
    }
    current: str | None = None
    for line in parts[1].splitlines():
        if not line.strip():
            continue
        if line.startswith("  - ") or line.startswith("- "):
            item = line.split("- ", 1)[1].strip()
            if current:
                data.setdefault(current, []).append(item)
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if value:
            data[key] = value
            current = None
        else:
            data[key] = []
            current = key
    if "id" not in data or "title" not in data:
        raise ValueError(f"{path} needs id and title")
    return data


def load_cards() -> list[dict]:
    return _load_dir(CARDS_DIR)


def load_policies() -> list[dict]:
    return _load_dir(POLICIES_DIR)


def _load_dir(directory: Path) -> list[dict]:
    docs = [parse_markdown(path) for path in sorted(directory.glob("*.md"))]
    ids = [doc["id"] for doc in docs]
    if len(ids) != len(set(ids)):
        raise ValueError(f"Duplicate ids in {directory}")
    return docs


def corpus_files() -> list[Path]:
    return sorted(CARDS_DIR.glob("*.md")) + sorted(POLICIES_DIR.glob("*.md"))


def snapshot_hashes() -> dict[str, str]:
    """Relative posix paths to sha256. This is the snapshot build_index freezes."""

    recorded: dict[str, str] = {}
    for path in corpus_files():
        recorded[path.relative_to(ROOT).as_posix()] = sha256_file(path)
    return recorded


def assert_snapshot(recorded: dict[str, str], current: dict[str, str]) -> None:
    if recorded != current:
        raise CorpusRefused(
            "Corpus hash mismatch. Refusing to load the index. "
            "Review the card change, then run: python -m rag.build_index"
        )


def card_embedding_text(card: dict) -> str:
    parts = [
        card.get("title", ""),
        " ".join(card.get("patterns") or []),
        " ".join(card.get("red_flags") or []),
        " ".join(card.get("bank_never_asks") or []),
        card.get("advice", ""),
        card.get("body", ""),
    ]
    return normalise("\n".join(part for part in parts if part))
