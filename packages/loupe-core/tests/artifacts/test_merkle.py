import hashlib

import pytest
from loupe_core.artifacts.merkle import compute_artefact_merkle_root, leaf_hash


def _h(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TestLeafHash:
    def test_leaf_uses_domain_separator_zero(self) -> None:
        path = "sbom.cdx.json"
        sha = "a" * 64
        expected = _h(b"\x00" + path.encode() + b":" + sha.encode())
        assert leaf_hash(path, sha) == expected


class TestComputeArtefactMerkleRoot:
    def test_empty_returns_empty_string_sentinel(self) -> None:
        assert compute_artefact_merkle_root({}) == ""

    def test_single_leaf_is_just_the_leaf_hash(self) -> None:
        hashes = {"sbom.cdx.json": "a" * 64}
        root = compute_artefact_merkle_root(hashes)
        assert root == leaf_hash("sbom.cdx.json", "a" * 64)

    def test_two_leaves_combine_with_internal_separator_one(self) -> None:
        hashes = {
            "sbom.cdx.json": "a" * 64,
            "threats.yaml": "b" * 64,
        }
        # Sorted by path: sbom.cdx.json < threats.yaml
        left = leaf_hash("sbom.cdx.json", "a" * 64)
        right = leaf_hash("threats.yaml", "b" * 64)
        expected = _h(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right))
        assert compute_artefact_merkle_root(hashes) == expected

    def test_three_leaves_duplicate_last_at_odd_level(self) -> None:
        hashes = {
            "a.json": "1" * 64,
            "b.json": "2" * 64,
            "c.json": "3" * 64,
        }
        la = leaf_hash("a.json", "1" * 64)
        lb = leaf_hash("b.json", "2" * 64)
        lc = leaf_hash("c.json", "3" * 64)
        # Level 0 (odd): [la, lb, lc] -> duplicate lc -> [la, lb, lc, lc]
        # Level 1: [H(la|lb), H(lc|lc)]
        # Level 2 (root): H(H(la|lb) | H(lc|lc))
        n_ab = _h(b"\x01" + bytes.fromhex(la) + bytes.fromhex(lb))
        n_cc = _h(b"\x01" + bytes.fromhex(lc) + bytes.fromhex(lc))
        expected = _h(b"\x01" + bytes.fromhex(n_ab) + bytes.fromhex(n_cc))
        assert compute_artefact_merkle_root(hashes) == expected

    def test_deterministic_across_insertion_orders(self) -> None:
        a = {"sbom.cdx.json": "a" * 64, "threats.yaml": "b" * 64}
        b = {"threats.yaml": "b" * 64, "sbom.cdx.json": "a" * 64}
        assert compute_artefact_merkle_root(a) == compute_artefact_merkle_root(b)

    def test_changing_one_leaf_changes_root(self) -> None:
        before = compute_artefact_merkle_root({"x.json": "0" * 64})
        after = compute_artefact_merkle_root({"x.json": "0" * 63 + "1"})
        assert before != after

    def test_changing_a_path_changes_root(self) -> None:
        same_hash = "a" * 64
        before = compute_artefact_merkle_root({"x.json": same_hash})
        after = compute_artefact_merkle_root({"y.json": same_hash})
        assert before != after

    @pytest.mark.parametrize(
        "bad_sha",
        ["", "abc", "g" * 64, "A" * 64, " " * 64],
    )
    def test_rejects_malformed_sha(self, bad_sha: str) -> None:
        with pytest.raises(ValueError, match="sha256"):
            compute_artefact_merkle_root({"x.json": bad_sha})
