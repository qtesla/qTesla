# Lattice-based digital signature scheme **qTESLA**

This project is part of the submission of the post-quantum lattice-based digital signature
scheme **qTESLA** to the NIST Post-Quantum Standardization
project (2017). 

**qTESLA** is a family of post-quantum signature schemes based on the hardness of the decisional
Ring Learning With Errors (R-LWE) problem. 
The scheme is an efficient variant of the Bai-Galbraith signature scheme, which in
turn is based on the "Fiat-Shamir with Aborts" framework by Lyubashevsky, adapted
to the setting of ideal lattices.

**qTESLA** utilizes two different approaches for parameter generation in order to target a wide
range of application scenarios. The first approach, referred to as "heuristic qTESLA",
follows a heuristic parameter generation. The second approach, referred to as "provably-
secure qTESLA", follows a provably-secure parameter generation according to existing security
reductions.

Concretely, **qTESLA** includes five parameter sets targeting two security levels:

I  Heuristic qTESLA:

* qTESLA-I and qTESLA-I-s: NIST's security category 1.
* qTESLA-II: NIST's security category 2.
* qTESLA-III and qTESLA-III-s: NIST's security category 3.
* qTESLA-V-size and qTESLA-V-size-s: NIST's security category 5 (option for size).
* qTESLA-V and qTESLA-V-s: NIST's security category 5.

II  Provably-secure qTESLA:

* qTESLA-p-I: NIST's security category 1.
* qTESLA-p-III: NIST's security category 3.

The full specification of the scheme can be found in the qTESLA [`website`](http://qtesla.org).

## Contents


- [`KAT`](KAT/):                      Contains the Known Answer Tests
- [`Reference_implementation`](Reference_implementation/): Contains the reference implementation
- [`Optimized_implementation`](Optimized_implementation/): Contains the optimized implementation
- [`Additional_implementations`](Additional_implementation/): Contains AVX2 optimized implementations of the
                              heuristic parameter sets for x64 platforms

## Contents of subfolders

### Subfolder `KAT`:
This folder contains known answer test results for the proposed parameter sets.

- `\ref\KAT32\PQCsignKAT_qTesla-I.rsp`   : Known answer test results for qTesla-I, 
                                           32-bit platforms
- `\ref\KAT32\PQCsignKAT_qTesla-II.rsp`  : Known answer test results for qTesla-III, 
                                           32-bit platforms
- `\ref\KAT32\PQCsignKAT_qTesla-III.rsp` : Known answer test results for qTesla-III, 
                                           32-bit platforms
- `\ref\KAT32\PQCsignKAT_qTesla-V.rsp`   : Known answer test results for qTesla-V, 
                                           32-bit platforms
- `\ref\KAT32\PQCsignKAT_qTesla-V-size.rsp` : Known answer test results for qTesla-V-size, 
                                              32-bit platforms
- `\ref\KAT32\PQCsignKAT_qTesla-p-I.rsp` : Known answer test results for qTesla-p-I, 
                                           32-bit platforms
- `\ref\KAT32\PQCsignKAT_qTesla-p-III.rsp` : Known answer test results for qTesla-p-III, 
                                             32-bit platforms
- `\ref\KAT32\PQCsignKAT_qTesla-I-s.rsp`   : Known answer test results for qTesla-I-s, 
                                           32-bit platforms
- `\ref\KAT32\PQCsignKAT_qTesla-II-s.rsp`  : Known answer test results for qTesla-III-s, 
                                           32-bit platforms
- `\ref\KAT32\PQCsignKAT_qTesla-III-s.rsp` : Known answer test results for qTesla-III-s, 
                                           32-bit platforms
- `\ref\KAT32\PQCsignKAT_qTesla-V-s.rsp`   : Known answer test results for qTesla-V-s, 
                                           32-bit platforms
- `\ref\KAT32\PQCsignKAT_qTesla-V-size-s.rsp` : Known answer test results for qTesla-V-size-s, 
                                              32-bit platforms

- `\ref\KAT64\PQCsignKAT_qTesla-I.rsp`   : Known answer test results for qTesla-I, 
                                           64-bit platforms
- `\ref\KAT64\PQCsignKAT_qTesla-II.rsp`  : Known answer test results for qTesla-II, 
                                           64-bit platforms
- `\ref\KAT64\PQCsignKAT_qTesla-III.rsp` : Known answer test results for qTesla-III, 
                                           64-bit platforms
- `\ref\KAT64\PQCsignKAT_qTesla-V.rsp`   : Known answer test results for qTesla-V, 
                                           64-bit platforms
- `\ref\KAT64\PQCsignKAT_qTesla-V-size.rsp` : Known answer test results for qTesla-V-size, 
                                              64-bit platforms
- `\ref\KAT64\PQCsignKAT_qTesla-p-I.rsp` : Known answer test results for qTesla-p-I, 
                                           64-bit platforms
- `\ref\KAT64\PQCsignKAT_qTesla-p-III.rsp` : Known answer test results for qTesla-p-III, 
                                             64-bit platforms
- `\ref\KAT64\PQCsignKAT_qTesla-I-s.rsp`   : Known answer test results for qTesla-I-s, 
                                           64-bit platforms
- `\ref\KAT64\PQCsignKAT_qTesla-II-s.rsp`  : Known answer test results for qTesla-II-s, 
                                           64-bit platforms
- `\ref\KAT64\PQCsignKAT_qTesla-III-s.rsp` : Known answer test results for qTesla-III-s, 
                                           64-bit platforms
- `\ref\KAT64\PQCsignKAT_qTesla-V-s.rsp`   : Known answer test results for qTesla-V-s, 
                                           64-bit platforms
- `\ref\KAT64\PQCsignKAT_qTesla-V-size-s.rsp` : Known answer test results for qTesla-V-size-s, 
                                              64-bit platforms

- `\avx2\KAT64\PQCsignKAT_qTesla-I.rsp`   : Known answer test results for qTesla-I,
                                             additional AVX2 implementation
- `\avx2\KAT64\PQCsignKAT_qTesla-III.rsp` : Known answer test results for qTesla-III,
                                             additional AVX2 implementation
- `\avx2\KAT64\PQCsignKAT_qTesla-V.rsp`   : Known answer test results for qTesla-V,
                                             additional AVX2 implementation				
- `\avx2\KAT64\PQCsignKAT_qTesla-I-s.rsp`   : Known answer test results for qTesla-I-s,
                                             additional AVX2 implementation
- `\avx2\KAT64\PQCsignKAT_qTesla-III-s.rsp` : Known answer test results for qTesla-III-s,
                                             additional AVX2 implementation
- `\avx2\KAT64\PQCsignKAT_qTesla-V-s.rsp`   : Known answer test results for qTesla-V-s,
                                             additional AVX2 implementation

### Subfolder `Reference_Implementation`:
This folder contains five subfolders which contain the reference implementations
for the proposed parameter sets.

- "qTesla-I"   : Reference implementation of qTesla-I with parameters for
                 NIST’s security category 1
- "qTesla-I-s"   : Reference implementation of qTesla-I-s with parameters for
                 NIST’s security category 1
- "qTesla-II"  : Reference implementation of qTesla-II with parameters for
                 NIST’s security category 2
- "qTesla-III" : Reference implementation of qTesla-III with parameters for
                 NIST’s security category 3
- "qTesla-III-s" : Reference implementation of qTesla-III-s with parameters for
                 NIST’s security category 3
- "qTesla-V"   : Reference implementation of qTesla-V with parameters for
                 NIST’s security category 5
- "qTesla-V-s"   : Reference implementation of qTesla-V-s with parameters for
                 NIST’s security category 5
- "qTesla-V-size" : Reference implementation of qTesla-V-size with parameters for
                 NIST’s security category 5
- "qTesla-V-size-s" : Reference implementation of qTesla-V-size-s with parameters for
                 NIST’s security category 5
- "qTesla-p-I" : Reference implementation of qTesla-p-I with parameters for
                 NIST’s security category 1
- "qTesla-p-III" : Reference implementation of qTesla-p-III with parameters for
                   NIST’s security category 3

### Subfolder `Optimized_implementation`:
This folder contains the following subfolders which contain the optimized implementations
for the proposed parameter sets:

- "qTesla-II"       : Optimized implementation of qTesla-II with parameters for
                    NIST’s security category 2
- "qTesla-II-s"     : Optimized implementation of qTesla-II-s with parameters for
                    NIST’s security category 2
- "qTesla-V-size"   : Optimized implementation of qTesla-V-size with parameters for
                    NIST’s security category 5
- "qTesla-V-size-s" : Optimized implementation of qTesla-V-size-s with parameters for
                    NIST’s security category 5

These implementations are written in C plus a reduction routine written in x64 assembly.
For all the other parameter sets, the reference implementation is the optimized 
implementation for this version of the software. 

### Subfolder `Additional_implementations\avx2`:
This folder contains the following subfolders which contain the AVX2-optimized 
x64 implementations for the proposed heuristic parameter sets:

- "qTesla-I"     : Additional AVX2 implementation of qTesla-I with parameters for
                 NIST’s security category 1
- "qTesla-I-s"   : Additional AVX2 implementation of qTesla-I-s with parameters for
                 NIST’s security category 1
- "qTesla-III"   : Additional AVX2 implementation of qTesla-III with parameters for
                 NIST’s security category 3
- "qTesla-III-s" : Additional AVX2 implementation of qTesla-III-s with parameters for
                 NIST’s security category 3
- "qTesla-V"     : Additional AVX2 implementation of qTesla-V with parameters for
                 NIST’s security category 5
- "qTesla-V-s"   : Additional AVX2 implementation of qTesla-V-s with parameters for
                 NIST’s security category 5


## Instructions for linux

Each implementation directory has its own makefile, and can be compiled by executing

```sh
$ make
```

By default compilation is done with gcc. Testing and benchmarking results can be seen
by running the command:

```sh
$ ./test_qtesla
```

This outputs key and signature sizes, and cycle counts for key generation, signing,
and verification.

If compilation is done with

```sh
$ make DEBUG=TRUE
```

executing test_qtesla additionally outputs acceptance probabilities during key
generation and signing.

KAT files can be generated by executing:

```sh
./PQCgenKAT_sign
```

Precomputed KAT values can be tested against the code by executing:

```sh
./PQCtestKAT_sign
```

## License

The qTESLA source code and header files are released to the public domain.
The software also includes third-party code licensed as follows:

- `src/sha3/fips202.c`: public domain
- `src/sha3/fips202x4.c`: public domain
- `src/sha3/keccak4x`: all files in this folder are public domain  ([CC0](http://creativecommons.org/publicdomain/zero/1.0/)), excepting
- `src/sha3/keccak4x/brg_endian.h` which is copyrighted by Brian Gladman and comes with a BSD 3-clause license.
- `tests/PQCtestKAT_sign.c`: copyrighted by Lawrence E. Bassham 
- `tests/rng.c`: copyrighted by Lawrence E. Bassham

## The qTESLA team

The qTESLA team is integrated by the following researchers from industry and academia
(in alphabetical order):

- Sedat Akleylek, Ondokuz Mayis University, Turkey
- Erdem Alkim, Ondokuz Mayis University, Turkey
- Paulo S. L. M. Barreto, University of Washington Tacoma, USA
- Nina Bindel, Technische Universität Darmstadt, Germany
- Johannes Buchmann, Technische Universität Darmstadt, Germany
- Edward Eaton, ISARA Corporation, Canada
- Gus Gutoski, ISARA Corporation, Canada
- Juliane Krämer, Technische Universität Darmstadt, Germany
- Patrick Longa, Microsoft Research, USA
- Harun Polat, Technische Universität Darmstadt, Germany
- Jefferson E. Ricardini, University of São Paulo, Brazil
- Gustavo Zanon, University of São Paulo, Brazil
