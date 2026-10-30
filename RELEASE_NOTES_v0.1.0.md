# v0.1.0 — Initial research artifact release

This first version archives the current public research prototype for byte-preserving DICOM exchange with post-quantum cryptography and witness-backed provenance.

## Included

- DICOM exchange harness using ML-KEM-768, HKDF-SHA-256, AES-256-GCM, and ML-DSA-65.
- Custom Merkle-style proof helper.
- Repeated-run and primitive benchmark scripts.
- Merkle, checkpoint/witness, and witness-certificate regression-test scripts.
- Selected Tamarin models for diagnostic duplicate-witness and witness-lock reasoning.
- Sanitized per-object and repeated-run experimental summaries.
- MIT License, CITATION.cff, and Zenodo metadata.

## Recorded experiment snapshot

The documented manifested run processed 11 DICOM-related objects totalling 1.4958 MiB and reported 170/170 programmed outcomes passing. Ten inputs were strict Part 10 files; one raw dataset without a Part 10 preamble was accepted using a parser fallback. A separate ten-run repeat series reported all checks passing in each run. These are recorded local prototype observations, not an independent audit, formal proof, comparative benchmark, or clinical validation.

## Important limitations

- Historical run harness hash does not match the available source copy; see PROVENANCE.md.
- Repeated-run manifest was generated after the runs and is not proof of historical immutability.
- The custom Merkle log is not claimed to fully conform to RFC 9162.
- General signature-based duplicate-witness rejection remains unresolved in the symbolic analysis.
- Witnesses are simulated locally; durable, independently operated witness infrastructure and rollback resistance have not been demonstrated.
- No original DICOM payloads, private keys, or patient-specific inputs are distributed.

Research prototype only. Not for clinical or production use.
