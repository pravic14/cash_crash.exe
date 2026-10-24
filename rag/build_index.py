"""Freeze the corpus: hash every card and policy, embed the scam cards.

Run from the repo root:

    python -m rag.build_index

Uses sentence-transformers/all-MiniLM-L6-v2 locally. Vectors are L2-normalised
so a dot product is cosine. Policies are hashed, not embedded: the dashboard
looks them up by id.
"""

from __future__ import annotations

import json

import numpy as np

from rag.corpus import index_dir, snapshot_hashes
from rag.retriever import MODEL_NAME, embed_cards


def build() -> dict:
    vectors, ids = embed_cards()
    folder = index_dir()
    folder.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        folder / "embeddings.npz",
        vectors=vectors,
        ids=np.array(ids),
    )
    manifest = {"model": MODEL_NAME, "files": snapshot_hashes()}
    (folder / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    manifest = build()
    print(f"Indexed {len(manifest['files'])} corpus files with {MODEL_NAME}")


if __name__ == "__main__":
    main()
