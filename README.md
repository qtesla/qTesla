Provably-secure lattice-based digital signature scheme qTESLA
--------------------------------------------------------------------------------

Principal and auxiliary submitters:
Sedat Akleylek, Erdem Alkim, Paulo Barreto, Nina Bindel, Johannes Buchmann, 
Edward Eaton, Gus Gutoski, Juliane Krämer, Patrick Longa, Harun Polat, 
Jefferson Ricardini, and Gustavo Zanon

--------------------------------------------------------------------------------

The submission of the lattice-based digital signature scheme qTESLA includes three 
folders:

- "KAT":                      Contains the Known Answer Tests
- "Reference_implementation": Contains the reference implementation
- "Additional_implementations/avx2": Contains the AVX2-optimized implementation

Subfolder "KAT": 

- "\ref\PQCsignKAT_qTesla-p-I.rsp"   : Known answer test results for qTesla-p-I, ref implementation
- "\ref\PQCsignKAT_qTesla-p-III.rsp" : Known answer test results for qTesla-p-III, ref implementation
- "\avx2\PQCsignKAT_qTesla-p-I.rsp"   : Known answer test results for qTesla-p-I, AVX2 implementation
- "\avx2\PQCsignKAT_qTesla-p-III.rsp" : Known answer test results for qTesla-p-III, AVX2 implementation

Subfolder "Reference_implementation":

- "qTesla-p-I" : Reference implementation of qTesla-p-I with parameters for
                 NIST’s security category 1
- "qTesla-p-III" : Reference implementation of qTesla-p-III with parameters for
                   NIST’s security category 3

Subfolder "Additional_implementations/avx2":

- "qTesla-p-I" : AVX2-optimized implementation of qTesla-p-I with parameters for
                 NIST’s security category 1
- "qTesla-p-III" : AVX2-optimized implementation of qTesla-p-III with parameters for
                   NIST’s security category 3

