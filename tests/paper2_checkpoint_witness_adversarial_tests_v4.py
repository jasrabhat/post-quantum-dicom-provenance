#!/usr/bin/env python3
"""Adversarial tests for the extracted checkpoint/witness functions in Phase A v4.

Run from the folder containing this script, the Phase A v4 harness, and
paper2_merkle_proofs_prototype_windows.py. These tests exercise the actual helper
functions imported from the v4 harness, not a separate policy adapter.
"""
from __future__ import annotations
import argparse, importlib.util, json, sys, hashlib
from pathlib import Path


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location("paper2_phaseA_v4", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load harness module: {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", default=str(Path(__file__).with_name("paper2_dicom_exchange_tests_phaseA_audited_corrected_v4.py")))
    ap.add_argument("--output-dir", default="checkpoint_witness_adversarial_results")
    args = ap.parse_args()
    harness = load_module(Path(args.module).resolve())
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey

    leaves = [f"manifest-{i}".encode() for i in range(4)]
    old_size, new_size = 2, 4
    old_root = harness.tree_hash(leaves[:old_size])
    new_root = harness.tree_hash(leaves)
    proof = harness.consistency_proof(leaves, old_size)
    authority = MLDSA65PrivateKey.generate()
    state = {"schema": 1, "log_id": "local-dicom-log", "size": old_size,
             "root": old_root.hex(), "locks": {str(old_size): old_root.hex()}}

    def make_checkpoint(**overrides):
        cp = {"protocol": "paper2-dicom-checkpoint-v1", "log_id": "local-dicom-log",
              "tree_size": new_size, "root_sha256": new_root.hex(), "authority_key_id": "test-key"}
        cp.update(overrides)
        b = harness.canonical(cp)
        return cp, b, authority.sign(b, harness.CHECKPOINT_CONTEXT)

    results = []
    def record(name, passed, detail):
        results.append({"test": name, "passed": bool(passed), "detail": detail})

    cp, cp_bytes, sig = make_checkpoint()
    accepted, updated = harness.evaluate_witness_checkpoint(state, cp, sig, cp_bytes, authority.public_key(), new_root, proof)
    record("valid_checkpoint_accepted", accepted and updated["size"] == new_size and updated["root"] == new_root.hex(), "Valid signed extension accepted and state advances")

    tampered_sig = bytes([sig[0] ^ 1]) + sig[1:]
    accepted, updated = harness.evaluate_witness_checkpoint(state, cp, tampered_sig, cp_bytes, authority.public_key(), new_root, proof)
    record("tampered_authority_signature_rejected", not accepted and updated == state, "Invalid signature rejected; state unchanged")

    bad_proof = list(proof)
    if bad_proof:
        bad_proof[0] = hashlib.sha256(b"tampered-proof-node").digest()
    else:
        bad_proof = [hashlib.sha256(b"tampered-proof-node").digest()]
    accepted, updated = harness.evaluate_witness_checkpoint(state, cp, sig, cp_bytes, authority.public_key(), new_root, bad_proof)
    record("tampered_consistency_proof_rejected", not accepted and updated == state, "Invalid extension proof rejected; state unchanged")

    stale_cp, stale_bytes, stale_sig = make_checkpoint(tree_size=1, root_sha256=harness.tree_hash(leaves[:1]).hex())
    accepted, updated = harness.evaluate_witness_checkpoint(state, stale_cp, stale_sig, stale_bytes, authority.public_key(), harness.tree_hash(leaves[:1]), [])
    record("stale_checkpoint_rejected", not accepted and updated == state, "Older tree size rejected; state unchanged")

    replay_cp, replay_bytes, replay_sig = make_checkpoint(tree_size=old_size, root_sha256=old_root.hex())
    accepted, updated = harness.evaluate_witness_checkpoint(state, replay_cp, replay_sig, replay_bytes, authority.public_key(), old_root, [])
    record("same_size_replay_rejected", not accepted and updated == state, "Equal-size replay rejected; state unchanged")

    wrong_log_cp, wrong_log_bytes, wrong_log_sig = make_checkpoint(log_id="different-log")
    accepted, updated = harness.evaluate_witness_checkpoint(state, wrong_log_cp, wrong_log_sig, wrong_log_bytes, authority.public_key(), new_root, proof)
    record("wrong_log_id_rejected", not accepted and updated == state, "Checkpoint for another log rejected; state unchanged")

    conflict_state = {**state, "locks": {**state["locks"], str(new_size): hashlib.sha256(b"conflicting-root").hexdigest()}}
    accepted, updated = harness.evaluate_witness_checkpoint(conflict_state, cp, sig, cp_bytes, authority.public_key(), new_root, proof)
    record("conflicting_same_size_root_rejected", not accepted and updated == conflict_state, "Previously locked conflicting root rejected; state unchanged")

    # Alter the signed checkpoint bytes while keeping the original signature.
    altered_bytes = cp_bytes + b" "
    record("checkpoint_byte_tampering_rejected", not harness.verify_checkpoint_signature(authority.public_key(), sig, altered_bytes), "Signature does not verify over altered checkpoint bytes")

    witness_keys = {i: MLDSA65PrivateKey.generate() for i in range(7)}
    witness_public = {i: k.public_key() for i, k in witness_keys.items()}
    votes = []
    for wid in range(5):
        msg = harness.canonical({"domain": "Paper2-DICOM-Witness-Vote-v1", "witness_id": wid, "checkpoint": cp})
        votes.append((wid, witness_keys[wid].sign(msg, harness.WITNESS_CONTEXT), msg))
    valid_unique = harness.count_valid_witness_votes(votes, witness_public)
    valid_with_duplicate = harness.count_valid_witness_votes(votes + [votes[0], votes[0]], witness_public)
    record("duplicate_votes_do_not_inflate_quorum", valid_unique == 5 and valid_with_duplicate == 5, f"Unique votes={valid_unique}; after duplicate entries={valid_with_duplicate}")

    outdir = Path(args.output_dir)
    outdir.mkdir(parents=True, exist_ok=True)
    summary = {"suite": "Phase A v4 actual checkpoint/witness helper tests", "test_count": len(results),
               "passed": sum(r["passed"] for r in results), "failed": sum(not r["passed"] for r in results),
               "all_tests_passed": all(r["passed"] for r in results), "results": results,
               "scope_note": "Tests import checkpoint/witness helper functions from the Phase A v4 harness and the actual Merkle verifier module. This does not establish durable multi-process witness storage, concurrency safety, production key management, formal verification, or full RFC 9162 conformance."}
    (outdir / "paper2_checkpoint_witness_adversarial_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    raise SystemExit(0 if summary["all_tests_passed"] else 1)

if __name__ == "__main__":
    main()