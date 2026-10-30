# Post-Quantum, Byte-Preserving DICOM Exchange with Witness-Backed Provenance

**Status:** experimental research prototype; not for clinical or production use.

This repository contains source code and selected validation artifacts for a prototype combining:
- ML-KEM-768 for shared-secret establishment.
- HKDF-SHA-256 for key derivation.
- AES-256-GCM for authenticated payload encryption.
- ML-DSA-65 signatures for manifests and provenance statements.
- A blinded SHA-256 commitment, canonical JSON manifest, custom Merkle-style log, signed checkpoints and a seven-witness/five-vote policy.

The exchange path protects the original DICOM byte string rather than decoding and rewriting pixel data. The Merkle implementation is custom and is not claimed to conform fully to RFC 9162. Witnesses are simulated locally rather than operated as an independent network.

## Repository contents

- `src/paper2_dicom_exchange_tests_phaseA_audited_corrected_v4.py` — DICOM exchange harness.
- `src/paper2_merkle_proofs_prototype_windows.py` — Merkle inclusion/consistency helper.
- `src/paper2_phaseA_repeated_run_benchmark.py` — repeated-run wrapper.
- `tests/paper2_merkle_proofs_adversarial_tests.py` — Merkle proof adversarial checks.
- `tests/paper2_checkpoint_witness_adversarial_tests_v4.py` — checkpoint/witness helper tests.
- `models/` — selected Tamarin diagnostic models.
- `PROVENANCE.md` and `TESTING_NOTES.md` — reproducibility caveats and release checks.
- `results/` — sanitized aggregate results; original DICOM payload files are not included.

## Environment

Recorded experiments used Python 3.13.14, `cryptography` 50.0.2, and `pydicom` 3.0.2 on Windows 11 Pro. The exact Tamarin version and command line were not preserved in the available records.

## Install and run

```bash
python -m venv .venv
# Windows PowerShell: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install cryptography==50.0.2 pydicom==3.0.2
python src/paper2_dicom_exchange_tests_phaseA_audited_corrected_v4.py --sample --max-files 1 --output-dir local_run/smoke
```

To use your own input, provide an authorized and appropriately de-identified fixture with `--input /path/to/dicom_file_or_directory`. Do not commit patient DICOM files, decrypted payloads, private keys, or site-specific metadata.

## Recorded observations

The manifested run processed 11 DICOM-related objects totalling 1.4958 MiB. Ten were strict Part 10 files; one was a raw dataset without a Part 10 preamble, accepted through a forced parser fallback. The run reported exact byte recovery for all 11 objects and 170/170 programmed outcomes passing. That total is a traceability count, not 170 independent security properties.

A separate ten-run series on the same fixture reported all checks passing each time. Mean runtime was 117.33 ms (sample SD 3.45 ms; range 110.83–121.37 ms); per-run median AES-GCM encryption averaged 0.0616 ms, and median receiver validation averaged 1.329 ms. These are local measurements, not comparative benchmarks.

## Limitations

- No head-to-head benchmark against DICOM PS3.15 CMS media security, TLS/DICOMweb, HPKE, or hybrid alternatives.
- No full DICOM conformance or clinical validation.
- No large-object, networked, crash-recovery, or independently hosted-witness evaluation.
- Rollback after restoration of previously saved state has not been demonstrated as prevented.
- General signature-based duplicate-witness rejection remains unresolved in the symbolic analysis.
- The historical run's recorded harness hash does not match the available release source; see `PROVENANCE.md`.
- Dataset provenance and institutional ethics/permission details were not recorded in the available artifacts and must be confirmed before claims are made about them.

## Citation

The archived software release is available from Zenodo at https://doi.org/10.5281/zenodo.23792116. Please cite the archived version using the metadata in `CITATION.cff`. The GitHub repository is the development repository and may contain changes made after the archived version.

## License and use

The repository is released under the MIT License; see `LICENSE`. This prototype has not been independently security-audited or qualified for production use.
