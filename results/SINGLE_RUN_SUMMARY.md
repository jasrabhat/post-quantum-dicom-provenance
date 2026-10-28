# Single-run result summary

The recorded manifested run processed 11 DICOM-related objects totalling 1.4958 MiB. Ten were strict Part 10 files; one raw dataset lacked a Part 10 preamble and was accepted through a forced parser fallback. The run reported byte-exact recovery for all 11 objects and 170/170 programmed outcomes passing. This count is not 170 independent security properties.

Reported median AES-GCM encryption was 0.0626 ms and median receiver validation was 1.3072 ms per object. Counted envelope overhead was 54,280 bytes (3.460728% of payload), excluding JSON framing, witness certificates and Merkle proofs.

These are recorded local prototype results, not an independent security audit, formal proof, clinical validation or comparative benchmark. See `PROVENANCE.md` for the harness-hash mismatch and other evidence limits.
