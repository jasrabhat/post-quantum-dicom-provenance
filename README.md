# Post-Quantum, Byte-Preserving DICOM Exchange with Witness-Backed Provenance

**Status:** experimental research prototype; not for clinical or production use.

This repository contains source code, selected regression tests, limited symbolic models, and sanitized results for a prototype that combines post-quantum key establishment, authenticated encryption, signed manifests, and witness-backed provenance for DICOM-file exchange.

## Components

- **ML-KEM-768** for shared-secret establishment (NIST FIPS 203 API through `cryptography`).
- **HKDF-SHA-256** for context-bound session-key derivation.
- **AES-256-GCM** for authenticated payload encryption.
- **ML-DSA-65** for manifest and provenance signatures (NIST FIPS 204 API through `cryptography`).
- A blinded SHA-256 commitment and canonical JSON manifest.
- A custom Merkle-style inclusion/consistency log with signed checkpoints and a seven-witness/five-vote acceptance policy.

The payload path protects the original source byte string; it does not decode and rewrite pixel data during encryption. The custom log is **not** claimed to conform fully to RFC 9162. Witnesses are simulated locally, not operated as an independent network.

## Layout

- `src/` — exchange harness, Merkle helper, repeated-run wrapper, primitive microbenchmark.
- `tests/` — local Merkle, checkpoint/witness, and vote-counting regression tests.
- `models/` — selected Tamarin models for diagnostic and duplicate-signer scenarios.
- `results/` — sanitized summary data. Original DICOM payloads are not distributed.
- `PROVENANCE.md` — limits on run-to-source linkage and historical hashes.
- `TESTING_NOTES.md` — checks rerun while preparing the publication candidate.

## Environment and installation

The recorded experiments used Windows 11 Pro, Python 3.13.14, `cryptography` 50.0.2, and `pydicom` 3.0.2. The exact Tamarin version and command line were not preserved in the available project record.

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Minimal exchange test

Use the pydicom CT example fixture:

```bash
python src/paper2_dicom_exchange_tests_phaseA_audited_corrected_v4.py --sample --max-files 1 --output-dir local_run/smoke
```

Or pass an authorized, de-identified DICOM fixture:

```bash
python src/paper2_dicom_exchange_tests_phaseA_audited_corrected_v4.py --input /path/to/dicom_file_or_directory --max-files 3 --output-dir local_run/test
```

Do not commit patient DICOM files, decrypted payloads, private keys, or site-specific metadata.

## Regression tests

```bash
python tests/paper2_merkle_proofs_adversarial_tests.py --module src/paper2_merkle_proofs_prototype_windows.py --output-dir local_run/merkle-tests
python tests/paper2_checkpoint_witness_adversarial_tests_v4.py --module src/paper2_dicom_exchange_tests_phaseA_audited_corrected_v4.py --output-dir local_run/checkpoint-tests
python tests/paper2_witness_certificate_negative_tests.py
```

Tamarin models must be run separately with a compatible local installation. Model results apply only to the rules and assumptions encoded. General signature-based duplicate-witness rejection remains unresolved in the main analysis; a witness-lock result depends on a trusted `ValidExtension` premise.

## Recorded experimental observations

The manifested local exchange run processed 11 DICOM-related objects totalling 1.4958 MiB. Ten were strict DICOM Part 10 files; one was a raw dataset without a Part 10 preamble and was read through a documented parser fallback. The run reported byte-exact recovery for all 11 objects and 170/170 programmed outcomes passing. The count is a traceability count, not 170 independent security properties.

In a separate ten-run repeat series on the same fixture, all ten runs reported all checks passing. Harness runtime averaged 117.33 ms (sample SD 3.45 ms; range 110.83–121.37 ms); per-run median AES-GCM encryption averaged 0.0616 ms (SD 0.0023 ms), and median receiver validation averaged 1.329 ms (SD 0.016 ms). These are local prototype measurements, not comparative benchmarks.

See `results/`, `PROVENANCE.md`, and `TESTING_NOTES.md` for scope and caveats.

## Known limitations

- No head-to-head benchmark against DICOM PS3.15 CMS media security, TLS/DICOMweb, HPKE, or hybrid alternatives.
- No full DICOM conformance or clinical validation.
- No large-object, networked, multiprocess, crash-recovery, or independently hosted-witness evaluation.
- Rollback after restoration of previously saved state has not been demonstrated as prevented.
- The historical harness hash does not match the currently available source file; the exact executed source has not been reconciled.
- The historical repeated-run manifest was created after the outputs and does not prove historical immutability.
- No original DICOM source files or private keys are included.
- Dataset provenance, local ethics/permission status, and the basis for any de-identification claim must be verified independently before reuse or publication.

## Data and code availability

The source code and sanitized non-sensitive results in this repository are the public artifact. Original DICOM sample files are not mirrored. Acquire sample data from the original pydicom example-data distribution and independently verify version, license, and reuse terms.

## License

No software license has been applied to this repository yet. Unless and until the rights holder adds a license, do not assume permission to reuse, modify, or redistribute the code.

## Disclaimer

Research and educational use only. This prototype has not been independently security-audited, clinically validated, or qualified for production. Do not use it to protect real patient records without further design, implementation review, operational controls, and appropriate approvals.

## Packaging validation

During preparation of the publication candidate, Python files compiled and the local Merkle adversarial suite passed 15/15 checks. The packaging environment did not have `pydicom` and had `cryptography` 46.0.4, so the DICOM/ML-KEM/ML-DSA runtime suite was not rerun there. Historical measurements are reported separately and were not claimed to have been reproduced in the packaging environment.
