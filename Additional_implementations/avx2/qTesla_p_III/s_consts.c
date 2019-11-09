/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: constants for x64 assembly implementation
**************************************************************************************/

#include "params.h"
#include <stdint.h>


int64_t N               = PARAM_N;
int32_t Nx4             = 4*PARAM_N;
int64_t H               = PARAM_H;
int64_t N2m64           = 2*PARAM_N - 64;
int64_t N4m128          = 4*PARAM_N - 128;
int32_t ZEROS[8]         __attribute__((aligned(32))) = {0, 0, 0, 0, 0, 0, 0, 0};
int32_t PERM_MASK[8]     __attribute__((aligned(32))) = {1, 3, 5, 7, 0, 2, 4, 6};
uint32_t PARAM_Qx4[8]    __attribute__((aligned(32))) = {PARAM_Q,    0, PARAM_Q,    0, PARAM_Q,    0, PARAM_Q,    0};
uint32_t PARAM_Rx4[8]    __attribute__((aligned(32))) = {PARAM_R,    0, PARAM_R,    0, PARAM_R,    0, PARAM_R,    0};
uint32_t PARAM_QINVx4[8] __attribute__((aligned(32))) = {PARAM_QINV, 0, PARAM_QINV, 0, PARAM_QINV, 0, PARAM_QINV, 0};
uint32_t PARAM_BARRx4[8] __attribute__((aligned(32))) = {PARAM_BARR_MULT, 0, PARAM_BARR_MULT, 0, PARAM_BARR_MULT, 0, PARAM_BARR_MULT, 0};