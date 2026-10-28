#!/usr/bin/env python3
"""Paper 2 DICOM-aware post-quantum exchange prototype.

Reads DICOM Part 10 files strictly and also supports a raw DICOM dataset without
a Part 10 preamble when pydicom can parse it and the dataset contains valid-looking
SOPClassUID and SOPInstanceUID fields. Encrypts and recovers exact original bytes.
Source files are never modified and patient-identifying attributes are not reported.

Research prototype: not a DICOM Secure Media Profile implementation, not audited,
and not production key management.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import secrets
import statistics
import sys
import time
import uuid
from pathlib import Path
from typing import Any

try:
    import pydicom
    from pydicom import dcmread
    from pydicom.errors import InvalidDicomError
except ImportError:
    print("Missing dependency: pydicom. Install with: python -m pip install pydicom", file=sys.stderr)
    raise SystemExit(2)

try:
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError as exc:
    print(
        "Required cryptography APIs are unavailable. Use Python with cryptography >= 47; "
        "this test was designed for cryptography 50.0.2.", file=sys.stderr
    )
    raise SystemExit(2) from exc

try:
    from paper2_merkle_proofs_prototype_windows import (
        tree_hash, inclusion_proof, verify_inclusion,
        consistency_proof, verify_consistency,
    )
except ImportError as exc:
    print(
        "Missing project dependency paper2_merkle_proofs_prototype_windows.py. "
        "Keep this script in D:\\paper_2 next to that file.", file=sys.stderr
    )
    raise SystemExit(2) from exc

MANIFEST_CONTEXT = b"Paper2-DICOM-Signed-Envelope-Context-v2"
CHECKPOINT_CONTEXT = b"Paper2-DICOM-Checkpoint-v1"
WITNESS_CONTEXT = b"Paper2-DICOM-Witness-Vote-v1"
PROTOCOL_DOMAIN = b"Paper2-DICOM-Envelope-v1\x00"
PROTOCOL_NAME = "paper2-dicom-exchange-v2"
KNOWN_EXTENSIONS = {".dcm", ".dicom", ".dic"}


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hexsha(data: bytes) -> str:
    return sha256(data).hex()


def canonical(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def verify_checkpoint_signature(public_key, signature: bytes, checkpoint_bytes: bytes) -> bool:
    """Verify a checkpoint authority signature using the harness's ML-DSA API."""
    try:
        public_key.verify(signature, checkpoint_bytes, CHECKPOINT_CONTEXT)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def evaluate_witness_checkpoint(
    state: dict[str, Any], checkpoint: dict[str, Any], checkpoint_signature: bytes,
    checkpoint_bytes: bytes, authority_public_key, new_root: bytes, proof,
) -> tuple[bool, dict[str, Any]]:
    """Apply the actual witness acceptance policy without mutating input state.

    A checkpoint must be authority-signed, target the same log, bind the supplied
    root, advance to a strictly newer tree size, extend the stored root, and not
    conflict with a previously locked root at that size. Rejected checkpoints
    return an unchanged state copy.
    """
    import copy
    before = copy.deepcopy(state)
    rejected = copy.deepcopy(state)
    try:
        old_size = int(state["size"])
        new_size = int(checkpoint["tree_size"])
        old_root = bytes.fromhex(state["root"])
        if checkpoint.get("log_id") != state.get("log_id"):
            return False, rejected
        if new_size <= old_size:
            return False, rejected
        if checkpoint.get("root_sha256") != new_root.hex():
            return False, rejected
        if not verify_checkpoint_signature(authority_public_key, checkpoint_signature, checkpoint_bytes):
            return False, rejected
        if not verify_consistency(old_size, new_size, old_root, new_root, proof):
            return False, rejected
        locks = state.get("locks", {})
        prior_lock = locks.get(str(new_size))
        if prior_lock is not None and prior_lock != new_root.hex():
            return False, rejected
        accepted = copy.deepcopy(before)
        accepted.setdefault("locks", {})[str(new_size)] = new_root.hex()
        accepted["size"], accepted["root"] = new_size, new_root.hex()
        return True, accepted
    except (InvalidSignature, ValueError, TypeError, KeyError, IndexError):
        return False, rejected


def count_valid_witness_votes(votes, witness_public) -> int:
    """Count unique witness IDs with valid signatures; duplicate IDs never add votes."""
    valid_votes = 0
    seen = set()
    for wid, sig, msg in votes:
        if wid in seen or wid not in witness_public:
            continue
        try:
            witness_public[wid].verify(sig, msg, WITNESS_CONTEXT)
            seen.add(wid)
            valid_votes += 1
        except (InvalidSignature, ValueError, TypeError):
            pass
    return valid_votes


def safe_dicom_metadata(ds) -> dict[str, Any]:
    """Return non-patient-identifying structural fields; never collect PHI tags."""
    def get_int(tag_name):
        value = getattr(ds, tag_name, None)
        if value is None:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    file_meta = getattr(ds, "file_meta", None)
    transfer_syntax = None
    if file_meta is not None and getattr(file_meta, "TransferSyntaxUID", None):
        transfer_syntax = str(file_meta.TransferSyntaxUID)
    pixel = getattr(ds, "PixelData", None)
    return {
        "modality": str(getattr(ds, "Modality", "UNKNOWN"))[:32],
        "sop_class_uid": str(getattr(ds, "SOPClassUID", "UNKNOWN"))[:64],
        # Record only presence, never the SOP Instance UID value. The UID is
        # needed to validate the parsed object but must not enter reports.
        "sop_instance_uid_present": bool(getattr(ds, "SOPInstanceUID", None)),
        "transfer_syntax_uid": transfer_syntax,
        "rows": get_int("Rows"),
        "columns": get_int("Columns"),
        "number_of_frames": get_int("NumberOfFrames") or 1,
        "has_pixel_data": pixel is not None,
        "pixel_data_bytes": len(pixel) if pixel is not None else 0,
    }


def has_part10_preamble(data: bytes) -> bool:
    """Return True when the standard DICOM Part 10 DICM marker is at byte 128."""
    return len(data) >= 132 and data[128:132] == b"DICM"


def parse_dicom_bytes_with_mode(data: bytes):
    """Strictly parse Part 10 first; validated fallback for raw DICOM datasets.

    The fallback is intentionally conservative: force=True alone does not prove
    that arbitrary bytes are DICOM, so SOPClassUID and SOPInstanceUID must exist.
    This accepts a raw dataset but does not convert it into a Part 10 file.
    """
    marker_present = has_part10_preamble(data)
    try:
        ds = dcmread(
            io.BytesIO(data), force=False, defer_size=None,
            stop_before_pixels=False,
        )
        return ds, "strict_part10"
    except InvalidDicomError as strict_error:
        try:
            ds = dcmread(
                io.BytesIO(data), force=True, defer_size=None,
                stop_before_pixels=False,
            )
        except Exception as fallback_error:
            raise InvalidDicomError(
                "Strict Part 10 parsing failed and forced dataset parsing failed"
            ) from fallback_error

        sop_class = getattr(ds, "SOPClassUID", None)
        sop_instance = getattr(ds, "SOPInstanceUID", None)
        if not sop_class or not sop_instance:
            raise InvalidDicomError(
                "Forced parsing did not identify both SOPClassUID and SOPInstanceUID"
            ) from strict_error

        # Mark the fallback precisely. If a DICM marker exists but the strict
        # reader rejected the file, do not falsely label it a valid Part 10 file.
        mode = (
            "forced_dataset_with_DICM_marker"
            if marker_present else "raw_dataset_without_part10_preamble"
        )
        return ds, mode


def parse_dicom_bytes(data: bytes):
    """Compatibility wrapper returning only the parsed pydicom Dataset."""
    ds, _mode = parse_dicom_bytes_with_mode(data)
    return ds


def container_format_for_mode(mode: str) -> str:
    if mode == "strict_part10":
        return "DICOM-Part10-file"
    if mode == "raw_dataset_without_part10_preamble":
        return "DICOM-dataset-without-Part10-preamble"
    return "DICOM-data-accepted-by-forced-parser-with-DICM-marker"


def make_manifest(index: int, raw: bytes, commitment: str, previous_leaf_hash: str | None,
                  content_type: str):
    # No patient name, patient ID, study/series/instance UID, birth date, accession
    # number, DICOM tags, or deterministic plaintext digest is placed in this manifest.
    # The 32-byte commitment blinder is encrypted together with the DICOM file bytes.
    return {
        "protocol": PROTOCOL_NAME,
        "schema_version": 1,
        "record_index": index,
        "object_token": secrets.token_hex(16),
        "object_version": 1,
        "payload_length_bytes": len(raw),
        "payload_commitment_sha256": commitment,
        "previous_record_hash": previous_leaf_hash,
        "content_type": content_type,
        "suite": "ML-KEM-768+HKDF-SHA-256+AES-256-GCM+ML-DSA-65",
    }


def recipient_public_key_bytes(public_key) -> bytes:
    """Return the raw ML-KEM public-key encoding used for key fingerprinting."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def make_signed_envelope_context(
    manifest_bytes: bytes,
    recipient_key_id: str,
    recipient_key_fingerprint: str,
    kem_ciphertext: bytes,
    salt: bytes,
) -> bytes:
    """Canonical, domain-separated sender-authorized envelope context."""
    return canonical({
        "domain": "paper2-dicom-signed-envelope-context-v2",
        "protocol_version": PROTOCOL_NAME,
        "purpose": "authorize-dicom-envelope-for-recipient",
        "manifest_sha256": hexsha(manifest_bytes),
        "recipient_key_id": recipient_key_id,
        "recipient_public_key_sha256": recipient_key_fingerprint,
        "kem_algorithm": "ML-KEM-768",
        "kem_ciphertext_sha256": hexsha(kem_ciphertext),
        "kdf": "HKDF-SHA-256",
        "aead": "AES-256-GCM",
        "hkdf_salt_sha256": hexsha(salt),
    })


def derive_key(shared_secret: bytes, salt: bytes, signed_context: bytes) -> bytes:
    info = b"Paper2-DICOM-AEAD-key-v2\x00" + sha256(signed_context)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(shared_secret)


def make_aad(signed_context: bytes, manifest_signature: bytes, nonce: bytes) -> bytes:
    return (
        PROTOCOL_DOMAIN
        + len(signed_context).to_bytes(4, "big")
        + signed_context
        + len(manifest_signature).to_bytes(4, "big")
        + manifest_signature
        + nonce
    )


def run_one(raw: bytes, safe_meta: dict[str, Any], index: int, previous_leaf_hash: str | None,
            recipient_private, manifest_signer, recipient_key_id: str):
    commitment_salt = os.urandom(32)
    commitment = hexsha(b"Paper2-DICOM-Commitment-v1\x00" + commitment_salt + raw)
    content_type = safe_meta.get("container_format", "DICOM-object")
    manifest = make_manifest(index, raw, commitment, previous_leaf_hash, content_type)
    manifest_bytes = canonical(manifest)
    packed_plaintext = commitment_salt + raw

    recipient_public = recipient_private.public_key()
    recipient_public_bytes = recipient_public_key_bytes(recipient_public)
    recipient_key_fingerprint = hexsha(recipient_public_bytes)
    shared_secret, kem_ciphertext = recipient_public.encapsulate()
    salt = os.urandom(32)
    nonce = os.urandom(12)
    signed_context = make_signed_envelope_context(
        manifest_bytes, recipient_key_id, recipient_key_fingerprint,
        kem_ciphertext, salt,
    )
    sign_start = time.perf_counter_ns()
    manifest_signature = manifest_signer.sign(signed_context, MANIFEST_CONTEXT)
    sig_sign_ms = (time.perf_counter_ns() - sign_start) / 1e6
    key = derive_key(shared_secret, salt, signed_context)
    aad = make_aad(signed_context, manifest_signature, nonce)

    encrypt_start = time.perf_counter_ns()
    encrypted = AESGCM(key).encrypt(nonce, packed_plaintext, aad)
    encrypt_ms = (time.perf_counter_ns() - encrypt_start) / 1e6

    # Receiver authenticates the manifest using the configured trusted verification key.
    receiver_start = time.perf_counter_ns()
    verify_start = time.perf_counter_ns()
    receiver_signed_context = make_signed_envelope_context(
        manifest_bytes, recipient_key_id,
        hexsha(recipient_public_key_bytes(recipient_private.public_key())),
        kem_ciphertext, salt,
    )
    manifest_signature_valid = False
    manifest_signer.public_key().verify(
        manifest_signature, receiver_signed_context, MANIFEST_CONTEXT
    )
    manifest_signature_valid = True
    verify_sig_ms = (time.perf_counter_ns() - verify_start) / 1e6
    decap_start = time.perf_counter_ns()
    recovered_secret = recipient_private.decapsulate(kem_ciphertext)
    decap_ms = (time.perf_counter_ns() - decap_start) / 1e6
    kdf_dec_start = time.perf_counter_ns()
    recovered_key = derive_key(recovered_secret, salt, receiver_signed_context)
    kdf_decrypt_ms = (time.perf_counter_ns() - kdf_dec_start) / 1e6
    aead_dec_start = time.perf_counter_ns()
    recovered_container = AESGCM(recovered_key).decrypt(nonce, encrypted, aad)
    aead_decrypt_ms = (time.perf_counter_ns() - aead_dec_start) / 1e6
    if len(recovered_container) < 32:
        raise ValueError("Decrypted container is shorter than its commitment blinder")
    recovered_commitment_salt, recovered = recovered_container[:32], recovered_container[32:]

    exact = recovered == raw
    hash_matches = hexsha(b"Paper2-DICOM-Commitment-v1\x00" + recovered_commitment_salt + recovered) == manifest["payload_commitment_sha256"]
    size_matches = len(recovered) == manifest["payload_length_bytes"]
    parse_start = time.perf_counter_ns()
    recovered_ds, recovered_parse_mode = parse_dicom_bytes_with_mode(recovered)
    recovered_meta = safe_dicom_metadata(recovered_ds)
    recovered_meta["container_format"] = container_format_for_mode(recovered_parse_mode)
    recovered_meta["parse_mode"] = recovered_parse_mode
    dicom_reparse_ms = (time.perf_counter_ns() - parse_start) / 1e6
    receiver_total_ms = (time.perf_counter_ns() - receiver_start) / 1e6
    # Compare only the explicit structural metadata fields collected from both
    # parses. safe_meta also carries harness-only state such as
    # source_parse_succeeded, which is not part of recovered_meta and must not
    # make an otherwise identical DICOM parse fail.
    metadata_keys = (
        "modality", "sop_class_uid", "transfer_syntax_uid", "rows", "columns",
        "number_of_frames", "has_pixel_data", "pixel_data_bytes",
        "container_format", "parse_mode",
    )
    metadata_match = all(
        recovered_meta.get(key) == safe_meta.get(key)
        for key in metadata_keys
    )

    tamper_rejected = False
    tampered = bytearray(encrypted)
    tampered[-1] ^= 1
    try:
        AESGCM(recovered_key).decrypt(nonce, bytes(tampered), aad)
    except InvalidTag:
        tamper_rejected = True

    altered_manifest = dict(manifest)
    altered_manifest["payload_length_bytes"] += 1
    manifest_substitution_rejected = False
    try:
        altered_manifest_bytes = canonical(altered_manifest)
        altered_context = make_signed_envelope_context(
            altered_manifest_bytes, recipient_key_id, recipient_key_fingerprint,
            kem_ciphertext, salt,
        )
        manifest_signer.public_key().verify(
            manifest_signature, altered_context, MANIFEST_CONTEXT
        )
    except (InvalidSignature, ValueError):
        manifest_substitution_rejected = True

    # Additional adversarial tests: exercise the receiver's
    # signature -> KEM -> HKDF -> AES-GCM validation sequence.
    def receiver_accepts(
        private_key, test_kem_ciphertext, test_salt,
        test_nonce, test_signature, test_recipient_key_id=None,
        test_recipient_public_key=None,
    ):
        test_recipient_key_id = test_recipient_key_id or recipient_key_id
        test_recipient_public_key = test_recipient_public_key or private_key.public_key()
        test_context = make_signed_envelope_context(
            manifest_bytes, test_recipient_key_id,
            hexsha(recipient_public_key_bytes(test_recipient_public_key)),
            test_kem_ciphertext, test_salt,
        )
        manifest_signer.public_key().verify(
            test_signature, test_context, MANIFEST_CONTEXT
        )
        secret = private_key.decapsulate(test_kem_ciphertext)
        test_key = derive_key(secret, test_salt, test_context)
        test_aad = make_aad(test_context, test_signature, test_nonce)
        AESGCM(test_key).decrypt(test_nonce, encrypted, test_aad)
        return True

    def rejected_by_receiver(**kwargs):
        try:
            receiver_accepts(**kwargs)
            return False
        except (InvalidSignature, InvalidTag, ValueError):
            return True

    receiver_args = {
        "test_kem_ciphertext": kem_ciphertext,
        "test_salt": salt,
        "test_nonce": nonce,
        "test_signature": manifest_signature,
    }

    wrong_recipient_rejected = rejected_by_receiver(
        private_key=MLKEM768PrivateKey.generate(),
        **receiver_args,
    )

    recipient_id_swap_rejected = rejected_by_receiver(
        private_key=recipient_private,
        test_recipient_key_id=recipient_key_id + "-swapped",
        **receiver_args,
    )

    # Re-enveloping the same payload for a second recipient must require a new
    # sender signature over the second recipient context. Reusing the old
    # signature is rejected by the receiver before payload acceptance.
    second_recipient = MLKEM768PrivateKey.generate()
    reenvelope_for_other_recipient_rejected = rejected_by_receiver(
        private_key=second_recipient,
        test_recipient_key_id=hexsha(recipient_public_key_bytes(second_recipient.public_key())),
        test_recipient_public_key=second_recipient.public_key(),
        **receiver_args,
    )

    altered_kem = bytearray(kem_ciphertext)
    altered_kem[0] ^= 1
    kem_ciphertext_substitution_rejected = rejected_by_receiver(
        private_key=recipient_private,
        **{**receiver_args, "test_kem_ciphertext": bytes(altered_kem)},
    )

    altered_salt = bytearray(salt)
    altered_salt[0] ^= 1
    salt_modification_rejected = rejected_by_receiver(
        private_key=recipient_private,
        **{**receiver_args, "test_salt": bytes(altered_salt)},
    )

    altered_nonce = bytearray(nonce)
    altered_nonce[0] ^= 1
    nonce_modification_rejected = rejected_by_receiver(
        private_key=recipient_private,
        **{**receiver_args, "test_nonce": bytes(altered_nonce)},
    )

    altered_signature = bytearray(manifest_signature)
    altered_signature[0] ^= 1
    manifest_signature_tampering_rejected = rejected_by_receiver(
        private_key=recipient_private,
        **{**receiver_args, "test_signature": bytes(altered_signature)},
    )
    

    # Count serialized cryptographic/envelope components, excluding JSON/framing.
    envelope_bytes = (
        len(manifest_bytes) + len(manifest_signature) + len(kem_ciphertext)
        + len(salt) + len(nonce) + len(encrypted)
    )
    overhead_bytes = envelope_bytes - len(raw)
    leaf_hash = sha256(b"\x00" + manifest_bytes).hex()
    # This flag is set only after parse_dicom_bytes_with_mode() returned a
    # Dataset successfully in main(). The UID/mode checks then validate that
    # the returned object contains the minimum metadata expected by this harness.
    dicom_parse_valid = bool(
        safe_meta.get("source_parse_succeeded") is True
        and safe_meta.get("sop_class_uid")
        and safe_meta.get("sop_class_uid") != "UNKNOWN"
        and safe_meta.get("sop_instance_uid_present") is True
        and safe_meta.get("parse_mode") in {
            "strict_part10", "raw_dataset_without_part10_preamble",
            "forced_dataset_with_DICM_marker",
        }
    )
    checks = {
        "dicom_parse_valid": dicom_parse_valid,
        "manifest_signature_valid": manifest_signature_valid,
        "exact_byte_recovery": exact,
        "recovered_blinded_commitment_matches": hash_matches,
        "payload_length_matches": size_matches,
        "recovered_dicom_metadata_matches": metadata_match,
        "ciphertext_tampering_rejected": tamper_rejected,
        "manifest_substitution_rejected": manifest_substitution_rejected,
        "wrong_recipient_key_rejected": wrong_recipient_rejected,
        "kem_ciphertext_substitution_rejected": kem_ciphertext_substitution_rejected,
        "salt_modification_rejected": salt_modification_rejected,
        "nonce_modification_rejected": nonce_modification_rejected,
        "manifest_signature_tampering_rejected": manifest_signature_tampering_rejected,
        "recipient_key_id_swap_rejected": recipient_id_swap_rejected,
        "re_enveloping_for_other_recipient_rejected": reenvelope_for_other_recipient_rejected,
    }
    report = {
        "object_index": index,
        "container_format": safe_meta.get("container_format", "unknown"),
        "source_parse_mode": safe_meta.get("parse_mode", "unknown"),
        "recovered_parse_mode": recovered_parse_mode,
        "payload_bytes": len(raw),
        "modality": safe_meta["modality"],
        "sop_class_uid": safe_meta["sop_class_uid"],
        "transfer_syntax_uid": safe_meta["transfer_syntax_uid"],
        "rows": safe_meta["rows"],
        "columns": safe_meta["columns"],
        "number_of_frames": safe_meta["number_of_frames"],
        "has_pixel_data": safe_meta["has_pixel_data"],
        "pixel_data_bytes": safe_meta["pixel_data_bytes"],
        "manifest_bytes": len(manifest_bytes),
        "manifest_signature_bytes": len(manifest_signature),
        "signed_context_bytes": len(signed_context),
        "recipient_key_id_sha256": hexsha(recipient_key_id.encode("utf-8")),
        "recipient_public_key_sha256": recipient_key_fingerprint,
        "signed_context_sha256": hexsha(signed_context),
        "mlkem_ciphertext_bytes": len(kem_ciphertext),
        "envelope_component_bytes_excluding_json_framing": envelope_bytes,
        "overhead_bytes_excluding_json_framing": overhead_bytes,
        "overhead_percent_excluding_json_framing": 100.0 * overhead_bytes / len(raw),
        "manifest_sign_ms": sig_sign_ms,
        "encryption_ms_aes_gcm_only": encrypt_ms,
        "signature_verify_ms": verify_sig_ms,
        "kem_decapsulation_ms": decap_ms,
        "kdf_decrypt_ms": kdf_decrypt_ms,
        "aes_gcm_decrypt_ms": aead_decrypt_ms,
        "dicom_reparse_ms": dicom_reparse_ms,
        "receiver_total_validation_ms": receiver_total_ms,
        "checks": checks,
        "all_checks_passed": all(checks.values()),
        "manifest_record_bytes": manifest_bytes,
        "leaf_hash": leaf_hash,
    }
    return report


def discover_files(input_path: Path, max_files: int | None):
    if input_path.is_file():
        candidates = [input_path]
    elif input_path.is_dir():
        candidates = [p for p in input_path.rglob("*") if p.is_file() and p.suffix.lower() in KNOWN_EXTENSIONS]
    else:
        candidates = []
    candidates = sorted(candidates, key=lambda p: str(p).casefold())
    if max_files is not None:
        candidates = candidates[:max_files]
    return candidates


def load_sample_path():
    try:
        from pydicom import examples
        # Documented pydicom sample path; the distribution may fetch/cache test data.
        sample = examples.get_path("ct")
        if sample and Path(sample).is_file():
            return Path(sample)
    except Exception as exc:
        raise RuntimeError(
            "Unable to obtain pydicom's CT_small.dcm sample. Check internet access, "
            "or provide a local DICOM Part 10 file via --input."
        ) from exc
    raise RuntimeError(
        "pydicom's CT_small.dcm sample was not available. Provide a local DICOM Part 10 file via --input."
    )


def main():
    parser = argparse.ArgumentParser(description="DICOM-aware Paper 2 post-quantum exchange test")
    parser.add_argument("--input", default="dicom_input", help="DICOM file or directory (default: dicom_input)")
    parser.add_argument("--sample", action="store_true", help="Use pydicom's CT_small.dcm test sample instead of --input")
    parser.add_argument("--max-files", type=int, default=3, help="Maximum DICOM objects to process (default: 3; use 0 for all)")
    parser.add_argument("--output-dir", default="local_run/results", help="Directory for sanitized reports")
    args = parser.parse_args()

    input_path = load_sample_path() if args.sample else Path(args.input)
    max_files = None if args.max_files == 0 else max(1, args.max_files)
    files = discover_files(input_path, max_files)
    if not files:
        print(json.dumps({
            "status": "NO_DICOM_FILES_FOUND",
            "input_path": str(input_path),
            "accepted_extensions": sorted(KNOWN_EXTENSIONS),
            "message": "No DICOM Part 10 files found. For a smoke test run --sample, or pass a folder/file with --input."
        }, indent=2))
        raise SystemExit(2)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Ephemeral keys: no private keys or plaintext images are exported by this research test.
    recipient_private = MLKEM768PrivateKey.generate()
    recipient_public = recipient_private.public_key()
    recipient_public_bytes = recipient_public.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    recipient_key_id = sha256(recipient_public_bytes).hex()
    manifest_signer = MLDSA65PrivateKey.generate()
    checkpoint_authority = MLDSA65PrivateKey.generate()
    witness_private = {i: MLDSA65PrivateKey.generate() for i in range(7)}
    witness_public = {i: k.public_key() for i, k in witness_private.items()}

    reports = []
    all_manifests = []
    previous_leaf_hash = None
    start_all = time.perf_counter()
    for index, path in enumerate(files, start=1):
        stage = "read_file"
        try:
            raw = path.read_bytes()
            stage = "parse_source_dicom"
            ds, source_parse_mode = parse_dicom_bytes_with_mode(raw)
            safe_meta = safe_dicom_metadata(ds)
            safe_meta["container_format"] = container_format_for_mode(source_parse_mode)
            safe_meta["parse_mode"] = source_parse_mode
            # Set only after the parser has returned successfully.
            safe_meta["source_parse_succeeded"] = True
            stage = "encrypt_decrypt_and_validate"
            report = run_one(
                raw, safe_meta, index, previous_leaf_hash,
                recipient_private, manifest_signer, recipient_key_id,
            )
            previous_leaf_hash = report["leaf_hash"]
            all_manifests.append(report.pop("manifest_record_bytes"))
            report.pop("leaf_hash")
            report["source_name_omitted_for_privacy"] = True
            reports.append(report)
        except Exception as exc:
            # Keep detailed diagnostics in the local console for debugging. The
            # machine-readable report records only the stage and exception class,
            # avoiding accidental disclosure of paths or DICOM metadata.
            print(
                f"[DICOM-INTEGRATION-ERROR] object_index={index} "
                f"stage={stage} exception={type(exc).__name__}: "
                f"{str(exc).splitlines()[0][:240] if str(exc) else '(no message)'}"
            )
            reports.append({
                "object_index": index,
                "container_format": "unknown",
                "source_parse_mode": "unknown",
                "recovered_parse_mode": "unknown",
                "processing_stage": stage,
                "all_checks_passed": False,
                "error_type": type(exc).__name__,
                "error_message": "details suppressed to avoid path or DICOM metadata disclosure",
            })

    successful_reports = [r for r in reports if r.get("all_checks_passed") is True]
    chain_consistency_ok = False
    inclusion_all_ok = False
    checkpoint_quorum_ok = False
    merkle_detail = {"tree_leaf_count": len(all_manifests)}

    if len(successful_reports) == len(files) and len(all_manifests) == len(files):
        n = len(all_manifests)
        root = tree_hash(all_manifests)
        inclusion_all_ok = all(
            verify_inclusion(
                all_manifests[i], i, n,
                inclusion_proof(all_manifests, i), root
            )
            for i in range(n)
        )
        if n >= 2:
            old_n = max(1, n // 2)
            old_root = tree_hash(all_manifests[:old_n])
            proof = consistency_proof(all_manifests, old_n)
            chain_consistency_ok = verify_consistency(old_n, n, old_root, root, proof)
        else:
            old_n = 0
            old_root = tree_hash([])
            proof = []
            # Empty-prefix acceptance is a defined special case; don't claim non-empty consistency tested.
            chain_consistency_ok = n == 1
            merkle_detail["consistency_proof_mode"] = "single-leaf empty-prefix bootstrap; no non-empty consistency proof was exercised"

        cp = {
            "protocol": "paper2-dicom-checkpoint-v1",
            "log_id": "local-dicom-log",
            "tree_size": n,
            "root_sha256": root.hex(),
            "authority_key_id": sha256(checkpoint_authority.public_key().public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )).hex(),
        }
        cp_bytes = canonical(cp)
        cp_sig = checkpoint_authority.sign(cp_bytes, CHECKPOINT_CONTEXT)

        # Derive the status flag from an actual verification operation.
        checkpoint_authority_signature_valid = verify_checkpoint_signature(
            checkpoint_authority.public_key(), cp_sig, cp_bytes
        )

        # Do not issue or count witness votes for an unauthenticated checkpoint.
        if not checkpoint_authority_signature_valid:
            raise InvalidSignature("Checkpoint authority signature verification failed")

        # Bootstrap all witness states at the trusted prefix. For n=1, use the one-leaf root directly.
        with __import__("tempfile").TemporaryDirectory(prefix="paper2_dicom_witness_") as tmp:
            witness_states = []
            for wid in range(7):
                state_path = Path(tmp) / f"witness_{wid}.json"
                state = {"schema": 1, "log_id": cp["log_id"], "size": old_n, "root": old_root.hex(), "locks": {str(old_n): old_root.hex()} if old_n else {}}
                state_path.write_text(json.dumps(state), encoding="utf-8")
                witness_states.append(state_path)
            votes = []
            if n >= 2:
                # Each local witness independently verifies authority signature and the consistency proof.
                for wid, state_path in enumerate(witness_states):
                    state = json.loads(state_path.read_text(encoding="utf-8"))
                    valid, updated_state = evaluate_witness_checkpoint(
                        state, cp, cp_sig, cp_bytes, checkpoint_authority.public_key(), root, proof
                    )
                    if valid:
                        state_path.write_text(json.dumps(updated_state), encoding="utf-8")
                        vote_msg = canonical({"domain": "Paper2-DICOM-Witness-Vote-v1", "witness_id": wid, "checkpoint": cp, "checkpoint_signature_sha256": sha256(cp_sig).hex()})
                        vote_sig = witness_private[wid].sign(vote_msg, WITNESS_CONTEXT)
                        votes.append((wid, vote_sig, vote_msg))
            else:
                # Single-leaf log: accept its signed checkpoint under the explicitly trusted empty-prefix bootstrap convention.
                for wid in range(7):
                    vote_msg = canonical({"domain": "Paper2-DICOM-Witness-Vote-v1", "witness_id": wid, "checkpoint": cp, "checkpoint_signature_sha256": sha256(cp_sig).hex()})
                    vote_sig = witness_private[wid].sign(vote_msg, WITNESS_CONTEXT)
                    votes.append((wid, vote_sig, vote_msg))
            valid_votes = count_valid_witness_votes(votes, witness_public)
            checkpoint_quorum_ok = valid_votes >= 5
        merkle_detail.update({
            "full_log_root_sha256": root.hex(),
            "all_inclusion_proofs_verified": inclusion_all_ok,
            "prefix_size": old_n,
            "consistency_proof_verified_or_single_leaf_bootstrap": chain_consistency_ok,
            "checkpoint_authority_signature_verified": checkpoint_authority_signature_valid,
            "valid_witness_votes": valid_votes,
            "five_of_seven_quorum_verified": checkpoint_quorum_ok,
        })

    elapsed_ms = (time.perf_counter() - start_all) * 1000.0
    check_values = []
    for r in reports:
        if "checks" in r:
            check_values.extend(r["checks"].values())
    global_checks = {
        "all_dicom_objects_parsed_and_exchanged": len(successful_reports) == len(files),
        "all_manifest_inclusion_proofs_verified": inclusion_all_ok,
        "merkle_prefix_consistency_verified_or_single_leaf_bootstrap": chain_consistency_ok,
        "checkpoint_authority_signature_verified": bool(merkle_detail.get("checkpoint_authority_signature_verified", False)),
        "five_of_seven_witness_certificate_verified": checkpoint_quorum_ok,
    }
    checks_total = len(check_values) + len(global_checks)
    checks_passed = sum(bool(x) for x in check_values) + sum(bool(x) for x in global_checks.values())
    all_passed = all(check_values) and all(global_checks.values()) and len(successful_reports) == len(files)

    sizes = [r["payload_bytes"] for r in successful_reports if "payload_bytes" in r]
    overheads = [r["overhead_percent_excluding_json_framing"] for r in successful_reports if "overhead_percent_excluding_json_framing" in r]
    enc_ms = [r["encryption_ms_aes_gcm_only"] for r in successful_reports if "encryption_ms_aes_gcm_only" in r]
    dec_ms = [r["receiver_total_validation_ms"] for r in successful_reports if "receiver_total_validation_ms" in r]

    summary = {
        "experiment": "Paper 2 DICOM-aware post-quantum exchange prototype",
        "algorithms": {
            "kem": "ML-KEM-768 (NIST FIPS 203)",
            "kdf": "HKDF-SHA-256",
            "aead": "AES-256-GCM",
            "manifest_checkpoint_witness_signatures": "ML-DSA-65 (NIST FIPS 204)",
            "merkle": "Educational RFC-6962-style implementation; not full RFC 9162 conformance",
        },
        "input_directory_or_file": "omitted from report to avoid path disclosure",
        "pydicom_version": getattr(pydicom, "__version__", "unknown"),
        "objects_found": len(files),
        "objects_successfully_processed": len(successful_reports),
        "dicom_container_formats": {
            "strict_part10_files": sum(1 for r in successful_reports if r.get("source_parse_mode") == "strict_part10"),
            "raw_datasets_without_part10_preamble": sum(1 for r in successful_reports if r.get("source_parse_mode") == "raw_dataset_without_part10_preamble"),
            "forced_parser_with_DICM_marker": sum(1 for r in successful_reports if r.get("source_parse_mode") == "forced_dataset_with_DICM_marker"),
        },
        "total_payload_MiB": round(sum(sizes) / (1024 * 1024), 4),
        "median_payload_bytes": int(statistics.median(sizes)) if sizes else None,
        "median_aes_gcm_encryption_ms": round(statistics.median(enc_ms), 4) if enc_ms else None,
        "median_receiver_total_validation_ms": round(statistics.median([r["receiver_total_validation_ms"] for r in successful_reports if "receiver_total_validation_ms" in r]), 4) if successful_reports else None,
        "aggregate_overhead_percent_excluding_json_framing": round(sum(r.get("overhead_bytes_excluding_json_framing", 0) for r in successful_reports) / max(1, sum(sizes)) * 100, 6) if sizes else None,
        "median_overhead_percent_per_object": round(statistics.median(overheads), 6) if overheads else None,
        "checks_passed": checks_passed,
        "checks_total": checks_total,
        "all_checks_passed": all_passed,
        "verification_scope": "Runtime harness outcomes from actual parser/cryptographic verifier calls; not an independent security audit or formal proof.",
        "global_checks": global_checks,
        "merkle_checkpoint_detail": merkle_detail,
        "runtime_ms_including_setup_and_log_checks": round(elapsed_ms, 3),
        "per_object_csv": str(output_dir / "paper2_dicom_exchange_per_object.csv"),
        "summary_json": str(output_dir / "paper2_dicom_exchange_summary.json"),
        "limitations": [
            "Exact original source bytes are encrypted and recovered without modifying source files. Part 10 files are read strictly; raw datasets without the Part 10 preamble are accepted only by the forced-parser fallback after SOPClassUID and SOPInstanceUID are present. Such datasets are not represented as Part 10 files.",
            "No PatientName, PatientID, StudyInstanceUID, SeriesInstanceUID, SOPInstanceUID, accession number, or dates are emitted to reports.",
            "The sender signature covers a canonical domain-separated context containing protocol version/purpose, manifest digest, recipient key ID and public-key fingerprint, KEM-ciphertext digest, KDF/AEAD identifiers, and salt digest. Recipient-key-ID swap and re-enveloping rejection are exercised by this harness against its receiver validation sequence; these are implementation-level regression tests, not a formal security proof or independent audit.",
            "The public manifest contains a blinded SHA-256 commitment and byte length, not a deterministic plaintext hash or patient-specific DICOM tags. The random commitment blinder is encrypted with the file. File size and content type still leak.",
            "Keys are ephemeral and not persisted; this is a validation harness, not a reusable archival encryption service.",
            "DICOM parsing is performed with pydicom. Compressed pixel data is not decompressed or modified. A successful forced parse with the required UIDs is an input-validation heuristic, not proof of full DICOM conformance.",
            "The Merkle implementation is educational and not full RFC 9162 conformance.",
            "Witnesses use local sequential simulation and temporary state files, not a live distributed network.",
            "The initial prefix checkpoint is trusted out of band; key lifecycle, concurrency, crash/power-loss durability and formal implementation verification are out of scope.",
            "Not a DICOM PS3.15 Secure DICOM File implementation and not clinical or regulatory validation.",
        ],
    }

    csv_path = output_dir / "paper2_dicom_exchange_per_object.csv"
    fieldnames = [
        "object_index", "container_format", "source_parse_mode", "recovered_parse_mode",
        "processing_stage", "error_type", "error_message", "payload_bytes", "modality", "sop_class_uid", "transfer_syntax_uid",
        "rows", "columns", "number_of_frames", "has_pixel_data", "pixel_data_bytes",
        "manifest_bytes", "manifest_signature_bytes", "signed_context_bytes",
        "recipient_key_id_sha256", "recipient_public_key_sha256", "signed_context_sha256",
        "mlkem_ciphertext_bytes",
        "envelope_component_bytes_excluding_json_framing", "overhead_bytes_excluding_json_framing",
        "overhead_percent_excluding_json_framing", "manifest_sign_ms", "encryption_ms_aes_gcm_only",
        "signature_verify_ms", "kem_decapsulation_ms", "kdf_decrypt_ms", "aes_gcm_decrypt_ms",
        "dicom_reparse_ms", "receiver_total_validation_ms",
        "dicom_parse_valid", "manifest_signature_valid",
        "exact_byte_recovery", "recovered_blinded_commitment_matches",
        "payload_length_matches", "recovered_dicom_metadata_matches",
        "ciphertext_tampering_rejected", "manifest_substitution_rejected",
        "wrong_recipient_key_rejected", "kem_ciphertext_substitution_rejected",
        "salt_modification_rejected", "nonce_modification_rejected",
        "manifest_signature_tampering_rejected", "recipient_key_id_swap_rejected",
        "re_enveloping_for_other_recipient_rejected", "all_checks_passed",
    ]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in reports:
            row = dict(r)
            row.update(r.get("checks", {}))
            row.pop("checks", None)
            writer.writerow(row)

    json_path = output_dir / "paper2_dicom_exchange_summary.json"
    json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    if not all_passed:
        raise SystemExit("One or more DICOM exchange checks failed.")


if __name__ == "__main__":
    main()