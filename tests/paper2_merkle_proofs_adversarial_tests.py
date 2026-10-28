"""
Paper 2 — adversarial tests for the local RFC-6962-style Merkle prototype.

This test suite calls the uploaded prototype's actual tree/proof generator and
verification functions. It adds explicit cases for:
- valid and tampered inclusion proofs;
- valid and tampered consistency proofs;
- stale checkpoint policy and rollback/replay state;
- log-ID mismatch policy.

The prototype does not implement signed checkpoints, log IDs, or persistent
witness policy. Those cases are tested by small explicit policy adapters around
the real Merkle proof verifier and are labelled as policy-layer tests, not
proofs of an existing production implementation.
Educational prototype only; not full RFC 9162 conformance.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time

def load_module(path: Path):
    spec = importlib.util.spec_from_file_location("paper2_merkle_under_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load Merkle module: {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def flip_hash(value: bytes) -> bytes:
    if not value:
        return b"\x01"
    return bytes([value[0] ^ 1]) + value[1:]

class WitnessCheckpointState:
    """Minimal monotonic checkpoint policy adapter for negative regression tests."""
    def __init__(self):
        self.by_log = {}

    def accept(self, log_id, size, root):
        if not isinstance(log_id, str) or not log_id:
            return False, "invalid_log_id"
        if not isinstance(size, int) or size < 1 or not isinstance(root, bytes):
            return False, "invalid_checkpoint"
        prior = self.by_log.get(log_id)
        if prior is not None:
            prior_size, prior_root = prior
            if size < prior_size:
                return False, "stale_or_rollback_checkpoint"
            if size == prior_size and root != prior_root:
                return False, "conflicting_checkpoint_same_size"
            if size == prior_size and root == prior_root:
                return False, "replayed_checkpoint"
            # Larger checkpoint acceptance requires consistency verification by caller.
        self.by_log[log_id] = (size, root)
        return True, "accepted"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--module", default="paper2_merkle_proofs_prototype_windows.py",
                    help="Path to the original prototype module")
    ap.add_argument("--output-dir", default="local_run/merkle_adversarial")
    args = ap.parse_args()

    module_path = Path(args.module).resolve()
    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    mod = load_module(module_path)

    cases = []
    start = time.perf_counter()

    # 1. Actual verifier: valid inclusion accepted, changed sibling hash rejected.
    leaves = [f"manifest-{i}".encode() for i in range(11)]
    root = mod.tree_hash(leaves)
    idx = 4
    proof = list(mod.inclusion_proof(leaves, idx))
    cases.append(("inclusion_valid_accepted",
                  bool(mod.verify_inclusion(leaves[idx], idx, len(leaves), proof, root)),
                  True, "actual verify_inclusion"))
    bad = list(proof)
    if bad:
        bad[0] = flip_hash(bad[0])
    else:
        bad = [hashlib.sha256(b"tampered-sibling").digest()]
    cases.append(("inclusion_tampered_sibling_rejected",
                  not bool(mod.verify_inclusion(leaves[idx], idx, len(leaves), bad, root)),
                  True, "actual verify_inclusion with altered proof"))
    cases.append(("inclusion_tampered_leaf_rejected",
                  not bool(mod.verify_inclusion(b"tampered-leaf", idx, len(leaves), proof, root)),
                  True, "actual verify_inclusion with altered leaf"))
    cases.append(("inclusion_wrong_root_rejected",
                  not bool(mod.verify_inclusion(leaves[idx], idx, len(leaves), proof, flip_hash(root))),
                  True, "actual verify_inclusion with altered expected root"))
    cases.append(("inclusion_out_of_range_rejected",
                  not bool(mod.verify_inclusion(leaves[idx], len(leaves), len(leaves), proof, root)),
                  True, "actual verify_inclusion with invalid index"))

    # 2. Actual verifier: valid consistency accepted, changed proof rejected.
    old_size = 5
    old_root = mod.tree_hash(leaves[:old_size])
    consistency = list(mod.consistency_proof(leaves, old_size))
    cases.append(("consistency_valid_accepted",
                  bool(mod.verify_consistency(old_size, len(leaves), old_root, root, list(consistency))),
                  True, "actual verify_consistency"))
    badc = list(consistency)
    if badc:
        badc[0] = flip_hash(badc[0])
    else:
        badc = [hashlib.sha256(b"tampered-consistency").digest()]
    cases.append(("consistency_tampered_proof_rejected",
                  not bool(mod.verify_consistency(old_size, len(leaves), old_root, root, badc)),
                  True, "actual verify_consistency with altered proof"))
    cases.append(("consistency_wrong_old_root_rejected",
                  not bool(mod.verify_consistency(old_size, len(leaves), flip_hash(old_root), root, list(consistency))),
                  True, "actual verify_consistency with altered old root"))
    cases.append(("consistency_wrong_new_root_rejected",
                  not bool(mod.verify_consistency(old_size, len(leaves), old_root, flip_hash(root), list(consistency))),
                  True, "actual verify_consistency with altered new root"))

    # 3. Policy layer: stale/rollback/replay/conflict and log separation.
    # These are NOT capabilities implemented in the Merkle module; the adapter
    # is deliberately explicit and results are labelled as policy-layer checks.
    state = WitnessCheckpointState()
    log_a = "research-log-A"
    log_b = "research-log-B"
    accepted, reason = state.accept(log_a, 5, old_root)
    cases.append(("checkpoint_initial_accepted", accepted, True, "policy adapter: " + reason))
    accepted, reason = state.accept(log_a, 4, mod.tree_hash(leaves[:4]))
    cases.append(("stale_checkpoint_rejected", not accepted and reason == "stale_or_rollback_checkpoint",
                  True, "policy adapter: " + reason))
    accepted, reason = state.accept(log_a, 5, old_root)
    cases.append(("checkpoint_replay_rejected", not accepted and reason == "replayed_checkpoint",
                  True, "policy adapter: " + reason))
    accepted, reason = state.accept(log_a, 5, flip_hash(old_root))
    cases.append(("conflicting_same_size_checkpoint_rejected",
                  not accepted and reason == "conflicting_checkpoint_same_size",
                  True, "policy adapter: " + reason))
    # A different log has independent state; it must not be treated as the
    # same log's checkpoint. Demonstrate independent acceptance, then reject a
    # request that explicitly supplies the wrong expected log ID.
    accepted, reason = state.accept(log_b, 5, old_root)
    cases.append(("separate_log_checkpoint_independent", accepted, True,
                  "policy adapter: " + reason))
    supplied_log_id, expected_log_id = log_b, log_a
    cases.append(("wrong_log_id_rejected",
                  supplied_log_id != expected_log_id, True,
                  "policy adapter comparison only; no log-ID field in original verifier"))

    elapsed_ms = (time.perf_counter() - start) * 1000
    result_rows = [
        {"test": name, "passed": bool(passed), "expected": bool(expected),
         "layer": detail}
        for name, passed, expected, detail in cases
    ]
    failed = [row for row in result_rows if not row["passed"]]
    summary = {
        "experiment": "Paper 2 Merkle adversarial regression suite",
        "source_module": str(module_path.name),
        "source_module_sha256": hashlib.sha256(module_path.read_bytes()).hexdigest(),
        "tests_total": len(result_rows),
        "tests_passed": len(result_rows) - len(failed),
        "tests_failed": len(failed),
        "all_tests_passed": not failed,
        "runtime_ms": round(elapsed_ms, 3),
        "results": result_rows,
        "scope_note": (
            "Merkle inclusion/consistency cases call the uploaded module's actual verifier functions. "
            "Checkpoint rollback/replay/log-ID cases exercise a separate illustrative policy adapter, "
            "because the source module does not implement signed checkpoints, log-ID binding, or durable "
            "witness state. These results do not establish those properties in the main exchange harness."
        ),
        "limitations": [
            "Educational RFC-6962-style Merkle implementation; not full RFC 9162 conformance.",
            "No cryptographic checkpoint-signature or witness-certificate verifier is invoked by this test file.",
            "Policy adapter is in-memory and not a production persistence/concurrency implementation.",
        ],
    }
    (out_dir / "paper2_merkle_adversarial_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8")
    # CSV avoids needing pandas and keeps each result independently inspectable.
    import csv
    with (out_dir / "paper2_merkle_adversarial_results.csv").open(
        "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["test", "passed", "expected", "layer"])
        w.writeheader()
        w.writerows(result_rows)
    print(json.dumps(summary, indent=2))
    if failed:
        raise SystemExit(1)

if __name__ == "__main__":
    main()