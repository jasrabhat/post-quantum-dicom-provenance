# Testing notes

The package was syntax-checked. The local Merkle adversarial test suite reported 15/15 passing checks. The environment used for packaging did not include pydicom and used cryptography 46.0.4, so the DICOM/ML-KEM/ML-DSA runtime test was not rerun. Historical benchmark results are reported separately and were not independently reproduced during packaging.