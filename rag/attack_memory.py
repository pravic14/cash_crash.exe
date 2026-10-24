"""Past attacks as vectors and labels. The raw message is not stored.

R1 can raise rag_sim from these, for labels scam and injection. A legit
example does not raise it. Card citations still come from the scam cards.
"""

from __future__ import annotations

import numpy as np

from rag.corpus import index_dir, normalise

LABELS = ("scam", "injection", "legit")
RISK_LABELS = ("scam", "injection")


def memory_path():
    return index_dir() / "attack_memory.npz"


def append_vector(vector: np.ndarray, label: str) -> None:
    if label not in LABELS:
        raise ValueError(f"label must be one of {LABELS}")
    row = np.asarray(vector, dtype=np.float32).reshape(-1)
    norm = float(np.linalg.norm(row))
    if norm == 0.0:
        raise ValueError("attack vector is empty")
    row = row / norm
    path = memory_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        stored = np.load(path, allow_pickle=False)
        vectors = np.vstack([np.asarray(stored["vectors"], dtype=np.float32), row])
        labels = np.concatenate([stored["labels"].astype(str), np.array([label])])
    else:
        vectors = row.reshape(1, -1)
        labels = np.array([label])
    np.savez_compressed(path, vectors=vectors.astype(np.float32), labels=labels)


def remember(text: str, label: str) -> None:
    """Embed text, store the vector and the label, then drop the text."""

    from rag.retriever import embed_query

    append_vector(embed_query(normalise(text)), label)


def max_attack_similarity(query_vector: np.ndarray) -> float:
    path = memory_path()
    if not path.exists():
        return 0.0
    stored = np.load(path, allow_pickle=False)
    labels = [str(label) for label in stored["labels"].tolist()]
    vectors = np.asarray(stored["vectors"], dtype=np.float32)
    query = np.asarray(query_vector, dtype=np.float32).reshape(-1)
    norm = float(np.linalg.norm(query))
    if norm == 0.0:
        return 0.0
    query = query / norm
    scores = vectors @ query
    best = 0.0
    for label, score in zip(labels, scores.tolist()):
        if label in RISK_LABELS:
            best = max(best, max(0.0, float(score)))
    return min(1.0, best)
