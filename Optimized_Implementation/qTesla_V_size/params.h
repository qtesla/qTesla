/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: qTESLA parameters
**************************************************************************************/

#ifndef PARAMS_H
#define PARAMS_H

#define PARAM_LGM 8
#define PARAM_M (1 << PARAM_LGM)
#define PARAM_N (6*PARAM_M)

#define PARAM_SIGMA 10.2
#define PARAM_Q 33564673
#define PARAM_Q_LOG 26
#define PARAM_QINV 4223674367
#define PARAM_BARR_MULT 127
#define PARAM_BARR_DIV 32
#define PARAM_B_BITS 23
#define PARAM_B ((1 << PARAM_B_BITS) - 1)
#define PARAM_S_BITS 9
#define PARAM_K 1
#define PARAM_SIGMA_E PARAM_SIGMA
#define PARAM_H 77
#define PARAM_D 24
#define PARAM_GEN_A 73
#define PARAM_KEYGEN_BOUND_E 1792
#define PARAM_E (2*PARAM_KEYGEN_BOUND_E)
#define PARAM_KEYGEN_BOUND_S 1792
#define PARAM_S (2*PARAM_KEYGEN_BOUND_S)
#define PARAM_R2_INVN 22253546
#define PARAM_R 32253825
#define RING_QREC 549588076538

#define SHAKE shake256
#define cSHAKE cshake256_simple
#define SHAKE_RATE SHAKE256_RATE

#endif
