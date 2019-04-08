/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: qTESLA parameters
**************************************************************************************/

#ifndef PARAMS_H
#define PARAMS_H

#define PARAM_N 2048
#define PARAM_N_LOG 11
#define PARAM_SIGMA 10.2
#define PARAM_Q 16801793
#define PARAM_Q_LOG 25
#define PARAM_QINV 3707789311
#define PARAM_BARR_MULT 255
#define PARAM_BARR_DIV 32
#define PARAM_B 4194303
#define PARAM_B_BITS 22
#define PARAM_S_BITS 9
#define PARAM_K 1
#define PARAM_SIGMA_E PARAM_SIGMA
#define PARAM_H 61
#define PARAM_D 23	
#define PARAM_GEN_A 98
#define PARAM_KEYGEN_BOUND_E 1554 
#define PARAM_E PARAM_KEYGEN_BOUND_E
#define PARAM_KEYGEN_BOUND_S 1554
#define PARAM_S PARAM_KEYGEN_BOUND_S
#define PARAM_R2_INVN 6863778
#define PARAM_R 10510081
#define SHAKE shake256
#define cSHAKE cshake256_simple
#define SHAKE_RATE SHAKE256_RATE

#endif
