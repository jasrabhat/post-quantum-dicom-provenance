#!/usr/bin/env python3
"""Standalone Paper 2 witness-certificate regression tests.

Requires cryptography >= 47 with ML-DSA-65 support (tested in the user's
Windows environment with cryptography 50.0.2). This script exercises the
certificate-verification policy defined here; it does not modify or claim to
exercise the DICOM integration harness until this verifier is wired into it.
"""
from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
except Exception as exc:
    raise SystemExit(
        "ML-DSA-65 is unavailable. Run with the project's Python environment "
        "(cryptography >= 47; the project run used cryptography 50.0.2). "
        f"Import error: {type(exc).__name__}: {exc}"
    )

CONTEXT = b"Paper2-DICOM-Witness-Vote-v1"
DOMAIN = "Paper2-DICOM-Witness-Vote-v1"


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

@dataclass(frozen=True)
class Vote:
    witness_id: int
    checkpoint: dict
    signature: bytes
    message: bytes


def make_vote(witness_id: int, checkpoint: dict, key) -> Vote:
    msg = canonical({
        "domain": DOMAIN,
        "witness_id": witness_id,
        "checkpoint": checkpoint,
        "checkpoint_signature_sha256": "test-checkpoint-signature-digest",
    })
    return Vote(witness_id, checkpoint, key.sign(msg, CONTEXT), msg)


def verify_certificate(votes, expected_checkpoint, witness_public, threshold=5, total_witnesses=7):
    """Accept only threshold distinct authorized witnesses voting for one checkpoint."""
    if not isinstance(votes, (list, tuple)) or not isinstance(expected_checkpoint, dict):
        return False, "malformed_certificate"
    expected_bytes = canonical(expected_checkpoint)
    seen = set()
    valid = 0
    for vote in votes:
        if not isinstance(vote, Vote):
            return False, "malformed_vote"
        wid = vote.witness_id
        if not isinstance(wid, int) or wid < 0 or wid >= total_witnesses or wid not in witness_public:
            return False, "unknown_witness"
        if wid in seen:
            return False, "duplicate_witness"
        if canonical(vote.checkpoint) != expected_bytes:
            return False, "conflicting_checkpoint"
        expected_msg = canonical({
            "domain": DOMAIN,
            "witness_id": wid,
            "checkpoint": expected_checkpoint,
            "checkpoint_signature_sha256": "test-checkpoint-signature-digest",
        })
        if vote.message != expected_msg:
            return False, "vote_message_mismatch"
        try:
            witness_public[wid].verify(vote.signature, vote.message, CONTEXT)
        except InvalidSignature:
            return False, "invalid_signature"
        seen.add(wid)
        valid += 1
    if valid < threshold:
        return False, "insufficient_quorum"
    return True, "accepted"


def witness_may_sign(checkpoint, locked_by_size):
    """Witness lock policy: never sign a different root at an already locked size."""
    size = checkpoint.get("tree_size")
    root = checkpoint.get("root_sha256")
    prior = locked_by_size.get(size)
    if prior is not None and prior != root:
        return False
    return True


def main():
    private = {i: MLDSA65PrivateKey.generate() for i in range(7)}
    public = {i: k.public_key() for i, k in private.items()}
    cp_a = {"protocol": "paper2-dicom-checkpoint-v1", "log_id": "test-log", "tree_size": 11, "root_sha256": "a" * 64}
    cp_b = {**cp_a, "root_sha256": "b" * 64}
    votes_a = [make_vote(i, cp_a, private[i]) for i in range(7)]
    tests = []

    def check(name, condition, detail):
        tests.append({"test": name, "passed": bool(condition), "detail": detail})

    ok, reason = verify_certificate(votes_a[:5], cp_a, public)
    check("valid_five_of_seven_accepted", ok, reason)

    ok, reason = verify_certificate(votes_a[:4], cp_a, public)
    check("four_of_seven_rejected", (not ok and reason == "insufficient_quorum"), reason)

    ok, reason = verify_certificate([votes_a[0]] * 5, cp_a, public)
    check("duplicate_witness_cannot_inflate_quorum", (not ok and reason == "duplicate_witness"), reason)

    mixed = votes_a[:4] + [make_vote(4, cp_b, private[4])]
    ok, reason = verify_certificate(mixed, cp_a, public)
    check("conflicting_checkpoint_votes_rejected", (not ok and reason == "conflicting_checkpoint"), reason)

    tampered = Vote(votes_a[0].witness_id, cp_a, votes_a[0].signature[:-1] + bytes([votes_a[0].signature[-1] ^ 1]), votes_a[0].message)
    ok, reason = verify_certificate([tampered] + votes_a[1:5], cp_a, public)
    check("tampered_vote_signature_rejected", (not ok and reason == "invalid_signature"), reason)

    unknown = make_vote(0, cp_a, private[0])
    unknown = Vote(7, cp_a, unknown.signature, unknown.message)
    ok, reason = verify_certificate([unknown] + votes_a[1:5], cp_a, public)
    check("unknown_witness_id_rejected", (not ok and reason == "unknown_witness"), reason)

    locked = {11: "a" * 64}
    check("witness_lock_allows_same_checkpoint", witness_may_sign(cp_a, locked), "same root at locked tree size")
    check("witness_lock_rejects_conflicting_root", not witness_may_sign(cp_b, locked), "different root at locked tree size")

    # Ensure a certificate is not accepted when all votes are valid but target a different checkpoint.
    ok, reason = verify_certificate(votes_a[:5], cp_b, public)
    check("certificate_for_wrong_expected_checkpoint_rejected", (not ok and reason == "conflicting_checkpoint"), reason)

    result = {
        "suite": "Paper 2 witness-certificate negative regression tests",
        "algorithm": "ML-DSA-65",
        "tests_passed": sum(t["passed"] for t in tests),
        "tests_total": len(tests),
        "all_tests_passed": all(t["passed"] for t in tests),
        "tests": tests,
        "limitations": [
            "Standalone policy test only; not yet wired into the DICOM integration harness.",
            "Synthetic checkpoints and ephemeral keys; no distributed witness network is exercised.",
            "This tests duplicate witness identities and conflicting checkpoint roots; it is not a formal proof of transparency-log security."
        ]
    }
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["all_tests_passed"] else 1)

if __name__ == "__main__":
    main()