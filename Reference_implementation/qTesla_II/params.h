/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: qTESLA parameters
**************************************************************************************/

#ifndef PARAMS_H
#define PARAMS_H

#define PARAM_LGM 7
#define PARAM_M (1 << PARAM_LGM)
#define PARAM_N (6*PARAM_M)

#define PARAM_SIGMA 9.73
#define PARAM_Q 8404993
#define PARAM_Q_LOG 24
#define PARAM_QINV 4034936831
#define PARAM_BARR_MULT 511
#define PARAM_BARR_DIV 32
#define PARAM_B_BITS 21
#define PARAM_B ((1 << PARAM_B_BITS) - 1)
#define PARAM_S_BITS 8
#define PARAM_K 1
#define PARAM_SIGMA_E PARAM_SIGMA
#define PARAM_H 39
#define PARAM_D 22
#define PARAM_GEN_A 28
#define PARAM_KEYGEN_BOUND_E 859
#define PARAM_E (2*PARAM_KEYGEN_BOUND_E)
#define PARAM_KEYGEN_BOUND_S 859
#define PARAM_S (2*PARAM_KEYGEN_BOUND_S)
#define PARAM_R2_INVN 3118783
#define PARAM_R 15873
#define RING_QREC 2194736399388

#define SHAKE shake128
#define cSHAKE cshake128_simple
#define SHAKE_RATE SHAKE128_RATE

#endif
