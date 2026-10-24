"""R1: similarity of incoming text to the trusted scam cards.

This does not approve a payment and does not write text_risk. It fills
rag_sim and a card id. The ML teammate owns M1–M4. Numpy cosine over
MiniLM vectors when an index exists. No vector database.

Until python -m rag.build_index has been run, matching uses the card
patterns so the demo still cites safe-account. A hash mismatch refuses
the index instead of searching a changed corpus.

Past attacks live in rag.attack_memory. That file stores a vector and a
label, never the message. Scam and injection labels can raise rag_sim.
They do not choose the cited card.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

import numpy as np

from rag.corpus import (
    CorpusRefused,
    assert_snapshot,
    card_embedding_text,
    index_dir,
    load_cards,
    load_policies,
    normalise,
    snapshot_hashes,
)

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
CITE_MIN = 0.45
_MODEL = None


@dataclass
class CardHit:
    card_id: str
    title: str
    score: float
    advice: str
    match_len: int = 0
    red_flags: list[str] = field(default_factory=list)
    bank_never_asks: list[str] = field(default_factory=list)
    body: str = ""


@dataclass
class Retrieval:
    rag_sim: float
    cited_card_id: str | None
    hits: list[CardHit]
    mode: str


def retrieve(text: str, k: int = 2) -> Retrieval:
    """Top scam cards for this text. k is how many the explainer may cite."""

    query = normalise(text)
    attack_sim = _attack_similarity(query)
    manifest = _read_manifest()
    if manifest is None:
        ranked = _pattern_hits(query)
        return _pack(ranked, k, "pattern", attack_sim)
    assert_snapshot(manifest.get("files", {}), snapshot_hashes())
    ranked = _merge(_embedding_hits(query, manifest), _pattern_hits(query))
    return _pack(ranked, k, "hybrid", attack_sim)


def cite_policy(policy_id: str) -> dict:
    """Clause text for the ops screen. The kernel in policy.py decides the verdict."""

    key = str(policy_id.value) if hasattr(policy_id, "value") else str(policy_id)
    for policy in load_policies():
        if policy["id"] == key:
            return {
                "id": policy["id"],
                "title": policy["title"],
                "body": policy.get("body", ""),
            }
    raise KeyError(f"No policy clause for {key}")


def _pack(ranked: list[CardHit], k: int, mode: str, attack_sim: float = 0.0) -> Retrieval:
    ranked.sort(key=lambda hit: (-hit.score, -hit.match_len, hit.card_id))
    rag_sim = float(ranked[0].score) if ranked else 0.0
    rag_sim = max(0.0, min(1.0, rag_sim), max(0.0, min(1.0, attack_sim)))
    hits = [hit for hit in ranked if hit.score >= CITE_MIN][:k]
    return Retrieval(
        rag_sim=rag_sim,
        cited_card_id=hits[0].card_id if hits else None,
        hits=hits,
        mode=mode,
    )


def _merge(left: list[CardHit], right: list[CardHit]) -> list[CardHit]:
    merged: dict[str, CardHit] = {}
    for hit in left + right:
        current = merged.get(hit.card_id)
        if current is None or hit.score > current.score or (
            hit.score == current.score and hit.match_len > current.match_len
        ):
            merged[hit.card_id] = hit
    return list(merged.values())


def _pattern_hits(query: str) -> list[CardHit]:
    hay = query.lower()
    hits: list[CardHit] = []
    for card in load_cards():
        matched = [pattern for pattern in card.get("patterns") or [] if pattern.lower() in hay]
        if not matched:
            continue
        longest = max(len(pattern) for pattern in matched)
        score = min(1.0, 0.55 + 0.15 * (len(matched) - 1))
        hits.append(_hit(card, score, longest))
    return hits


def _hit(card: dict, score: float, match_len: int) -> CardHit:
    return CardHit(
        card_id=card["id"],
        title=card["title"],
        score=float(score),
        advice=card.get("advice", ""),
        match_len=match_len,
        red_flags=list(card.get("red_flags") or []),
        bank_never_asks=list(card.get("bank_never_asks") or []),
        body=card.get("body", ""),
    )


def _read_manifest() -> dict | None:
    path = index_dir() / "manifest.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _embedding_hits(query: str, manifest: dict) -> list[CardHit]:
    matrix, ids = _load_vectors()
    query_vec = _embed([query])[0]
    scores = matrix @ query_vec
    cards = {card["id"]: card for card in load_cards()}
    if manifest.get("model") != MODEL_NAME:
        raise CorpusRefused(f"Index model is {manifest.get('model')}, expected {MODEL_NAME}")
    hits: list[CardHit] = []
    for card_id, score in zip(ids, scores.tolist()):
        card = cards.get(card_id)
        if card is None:
            raise CorpusRefused(f"Index cites missing card {card_id}")
        hits.append(_hit(card, max(0.0, float(score)), 0))
    return hits


def _load_vectors() -> tuple[np.ndarray, list[str]]:
    path = index_dir() / "embeddings.npz"
    if not path.exists():
        raise CorpusRefused("manifest.json exists without embeddings.npz")
    stored = np.load(path, allow_pickle=False)
    matrix = np.asarray(stored["vectors"], dtype=np.float32)
    ids = [str(card_id) for card_id in stored["ids"].tolist()]
    return matrix, ids


def embed_query(text: str) -> np.ndarray:
    return _embed([text])[0]


def _attack_similarity(query: str) -> float:
    from rag.attack_memory import max_attack_similarity, memory_path

    if not memory_path().exists():
        return 0.0
    try:
        return max_attack_similarity(embed_query(query))
    except ImportError:
        return 0.0


def embed_cards(cards: list[dict] | None = None) -> tuple[np.ndarray, list[str]]:
    cards = load_cards() if cards is None else cards
    ids = [card["id"] for card in cards]
    vectors = _embed([card_embedding_text(card) for card in cards])
    return vectors, ids


def _embed(texts: list[str]) -> np.ndarray:
    model = _model()
    vectors = model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
    return np.asarray(vectors, dtype=np.float32)


def _model():
    global _MODEL
    if _MODEL is None:
        from sentence_transformers import SentenceTransformer

        _MODEL = SentenceTransformer(MODEL_NAME)
    return _MODEL
