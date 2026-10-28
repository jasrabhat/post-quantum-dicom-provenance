# Artifact provenance and reproducibility

- Manifested run ID: `P2-20261026T134137`.
- The historical run record lists harness SHA-256 `fce07ddb8aa3b28c4527b0baa09960f62a1f7ec485f130c96a930b7b7ac880b`.
- The currently available harness has a different hash and has been made more portable for this release. The exact source bytes executed historically have not been reconciled with the available copy.
- Results are distributed as recorded outputs, not as independently reproduced results from the source in this repository.
- The repeated-run manifest was generated after the runs and does not prove historical immutability or source-to-output linkage.
- The recorded fixture was identified as pydicom 3.0.2 example/test data; original DICOM files are not redistributed. Ten strict Part 10 files and one raw dataset without a Part 10 preamble were recorded. The latter used a parser fallback and is not presented as a Part 10-conformant file.
- The available evidence does not establish an institutional ethics determination or formal de-identification assessment; confirm local institutional requirements, sample-data licensing and permissions independently.
- General signature-based duplicate-witness rejection remains unresolved. The witness-lock model result depends on a trusted `ValidExtension` premise. The custom Merkle implementation is educational, not a full RFC 9162 implementation.