"""SHA-256 Merkle root over a set of artefact (path, sha256) leaves.

Used by RunRecord to commit to every artefact written in a single run.
The construction follows RFC-6962-style binary trees with two
deviations callers should know about:

1. **Domain-separated hashing.** Leaves prepend ``b"\\x00"``; internal
   nodes prepend ``b"\\x01"``. This prevents an attacker from passing a
   leaf hash as an internal hash and vice versa (a known issue in
   naive Merkle constructions).
2. **Duplicate-last on odd levels.** When a level has an odd number of
   nodes, the last node is duplicated rather than promoted unchanged.
   This is simpler than RFC-6962's promote-tail rule and adequate for
   in-repo verification; an external transparency-log integration
   (deferred per D-14) would need to revisit this.
"""

from __future__ import annotations

import hashlib
import re

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def leaf_hash(path: str, sha256_hex: str) -> str:
    """Return the SHA-256 leaf hash for one artefact (path, sha256) pair."""
    if not _SHA256_RE.match(sha256_hex):
        raise ValueError(f"sha256 hex digest must be 64 lowercase hex chars, got {sha256_hex!r}")
    payload = b"\x00" + path.encode("utf-8") + b":" + sha256_hex.encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def _internal(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256(b"\x01" + bytes.fromhex(left_hex) + bytes.fromhex(right_hex)).hexdigest()


def compute_artefact_merkle_root(artefact_hashes: dict[str, str]) -> str:
    """Return the Merkle root over sorted (path, sha256) leaves.

    Empty input returns the empty-string sentinel rather than a fixed
    hash, so downstream code can cheaply tell "no artefacts in this
    run" apart from "artefacts present, root computed".
    """
    if not artefact_hashes:
        return ""
    nodes = [leaf_hash(path, sha) for path, sha in sorted(artefact_hashes.items())]
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])  # duplicate-last
        nodes = [_internal(a, b) for a, b in zip(nodes[::2], nodes[1::2], strict=True)]
    return nodes[0]
