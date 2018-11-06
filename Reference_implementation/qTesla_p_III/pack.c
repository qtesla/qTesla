/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: high-level functions of the signature scheme
**************************************************************************************/

#include <string.h>
#include "api.h"
#include "params.h"
#include "poly.h"


void pack_sk(unsigned char *sk, poly s, poly_k e, unsigned char *seeds)
{ // Pack secret key sk
  int i, k;
  int8_t *isk = (int8_t *)sk;

  for (i=0; i<PARAM_N; i++)
    isk[i] = (int8_t)s[i];

  isk += PARAM_N;
  for (k=0; k<PARAM_K; k++)
    for (i=0; i<PARAM_N; i++)
      isk[k*PARAM_N+i] = (int8_t)e[k*PARAM_N+i];
  
  memcpy(&isk[PARAM_K*PARAM_N], seeds, 2*CRYPTO_SEEDBYTES);
} 


void encode_pk(unsigned char *pk, const poly_k t, const unsigned char *seedA)
{ // Encode public key pk
  unsigned int i, j=0;
  uint32_t *pt = (uint32_t*)pk;
  
  for (i=0; i<(PARAM_N*PARAM_K*PARAM_Q_LOG/32); i+=PARAM_Q_LOG) {
    pt[i   ] = (uint32_t)(t[j] | (t[j+1] << 31));             
    pt[i+ 1] = (uint32_t)((t[j+ 1] >>  1) | (t[j+ 2] << 30));  pt[i+ 2] = (uint32_t)((t[j+ 2] >>  2) | (t[j+ 3] << 29)); 
    pt[i+ 3] = (uint32_t)((t[j+ 3] >>  3) | (t[j+ 4] << 28));  pt[i+ 4] = (uint32_t)((t[j+ 4] >>  4) | (t[j+ 5] << 27)); 
    pt[i+ 5] = (uint32_t)((t[j+ 5] >>  5) | (t[j+ 6] << 26));  pt[i+ 6] = (uint32_t)((t[j+ 6] >>  6) | (t[j+ 7] << 25)); 
    pt[i+ 7] = (uint32_t)((t[j+ 7] >>  7) | (t[j+ 8] << 24));  pt[i+ 8] = (uint32_t)((t[j+ 8] >>  8) | (t[j+ 9] << 23)); 
    pt[i+ 9] = (uint32_t)((t[j+ 9] >>  9) | (t[j+10] << 22));  pt[i+10] = (uint32_t)((t[j+10] >> 10) | (t[j+11] << 21)); 
    pt[i+11] = (uint32_t)((t[j+11] >> 11) | (t[j+12] << 20));  pt[i+12] = (uint32_t)((t[j+12] >> 12) | (t[j+13] << 19)); 
    pt[i+13] = (uint32_t)((t[j+13] >> 13) | (t[j+14] << 18));  pt[i+14] = (uint32_t)((t[j+14] >> 14) | (t[j+15] << 17)); 
    pt[i+15] = (uint32_t)((t[j+15] >> 15) | (t[j+16] << 16));  pt[i+16] = (uint32_t)((t[j+16] >> 16) | (t[j+17] << 15)); 
    pt[i+17] = (uint32_t)((t[j+17] >> 17) | (t[j+18] << 14));  pt[i+18] = (uint32_t)((t[j+18] >> 18) | (t[j+19] << 13)); 
    pt[i+19] = (uint32_t)((t[j+19] >> 19) | (t[j+20] << 12));  pt[i+20] = (uint32_t)((t[j+20] >> 20) | (t[j+21] << 11)); 
    pt[i+21] = (uint32_t)((t[j+21] >> 21) | (t[j+22] << 10));  pt[i+22] = (uint32_t)((t[j+22] >> 22) | (t[j+23] <<  9)); 
    pt[i+23] = (uint32_t)((t[j+23] >> 23) | (t[j+24] <<  8));  pt[i+24] = (uint32_t)((t[j+24] >> 24) | (t[j+25] <<  7)); 
    pt[i+25] = (uint32_t)((t[j+25] >> 25) | (t[j+26] <<  6));  pt[i+26] = (uint32_t)((t[j+26] >> 26) | (t[j+27] <<  5)); 
    pt[i+27] = (uint32_t)((t[j+27] >> 27) | (t[j+28] <<  4));  pt[i+28] = (uint32_t)((t[j+28] >> 28) | (t[j+29] <<  3));   
    pt[i+29] = (uint32_t)((t[j+29] >> 29) | (t[j+30] <<  2));  pt[i+30] = (uint32_t)((t[j+30] >> 30) | (t[j+31] <<  1));  
    j += 32;
  }
  memcpy(&pk[PARAM_N*PARAM_K*PARAM_Q_LOG/8], seedA, CRYPTO_SEEDBYTES);
}


void decode_pk(int32_t *pk, unsigned char *seedA, const unsigned char *pk_in)
{ // Decode public key pk
  unsigned int i, j=0;
  uint32_t *pt = (uint32_t*)pk_in, *pp = (uint32_t*)pk, mask31 = (uint32_t)(1<<PARAM_Q_LOG)-1;

  for (i=0; i<PARAM_N*PARAM_K; i+=32) {
    pp[i   ] = pt[j] & mask31; 
    pp[i+ 1] = ((pt[j+ 0] >> 31) | (pt[j+ 1] <<  1)) & mask31;  pp[i+ 2] = ((pt[j+ 1] >> 30) | (pt[j+ 2] <<  2)) & mask31; 
    pp[i+ 3] = ((pt[j+ 2] >> 29) | (pt[j+ 3] <<  3)) & mask31;  pp[i+ 4] = ((pt[j+ 3] >> 28) | (pt[j+ 4] <<  4)) & mask31;
    pp[i+ 5] = ((pt[j+ 4] >> 27) | (pt[j+ 5] <<  5)) & mask31;  pp[i+ 6] = ((pt[j+ 5] >> 26) | (pt[j+ 6] <<  6)) & mask31;
    pp[i+ 7] = ((pt[j+ 6] >> 25) | (pt[j+ 7] <<  7)) & mask31;  pp[i+ 8] = ((pt[j+ 7] >> 24) | (pt[j+ 8] <<  8)) & mask31;
    pp[i+ 9] = ((pt[j+ 8] >> 23) | (pt[j+ 9] <<  9)) & mask31;  pp[i+10] = ((pt[j+ 9] >> 22) | (pt[j+10] << 10)) & mask31;
    pp[i+11] = ((pt[j+10] >> 21) | (pt[j+11] << 11)) & mask31;  pp[i+12] = ((pt[j+11] >> 20) | (pt[j+12] << 12)) & mask31;
    pp[i+13] = ((pt[j+12] >> 19) | (pt[j+13] << 13)) & mask31;  pp[i+14] = ((pt[j+13] >> 18) | (pt[j+14] << 14)) & mask31;
    pp[i+15] = ((pt[j+14] >> 17) | (pt[j+15] << 15)) & mask31;  pp[i+16] = ((pt[j+15] >> 16) | (pt[j+16] << 16)) & mask31; 
    pp[i+17] = ((pt[j+16] >> 15) | (pt[j+17] << 17)) & mask31;  pp[i+18] = ((pt[j+17] >> 14) | (pt[j+18] << 18)) & mask31;
    pp[i+19] = ((pt[j+18] >> 13) | (pt[j+19] << 19)) & mask31;  pp[i+20] = ((pt[j+19] >> 12) | (pt[j+20] << 20)) & mask31;
    pp[i+21] = ((pt[j+20] >> 11) | (pt[j+21] << 21)) & mask31;  pp[i+22] = ((pt[j+21] >> 10) | (pt[j+22] << 22)) & mask31;
    pp[i+23] = ((pt[j+22] >>  9) | (pt[j+23] << 23)) & mask31;  pp[i+24] = ((pt[j+23] >>  8) | (pt[j+24] << 24)) & mask31;
    pp[i+25] = ((pt[j+24] >>  7) | (pt[j+25] << 25)) & mask31;  pp[i+26] = ((pt[j+25] >>  6) | (pt[j+26] << 26)) & mask31;
    pp[i+27] = ((pt[j+26] >>  5) | (pt[j+27] << 27)) & mask31;  pp[i+28] = ((pt[j+27] >>  4) | (pt[j+28] << 28)) & mask31;
    pp[i+29] = ((pt[j+28] >>  3) | (pt[j+29] << 29)) & mask31;  pp[i+30] = ((pt[j+29] >>  2) | (pt[j+30] << 30)) & mask31;
    pp[i+31] = pt[j+30] >> 1;
    j += 31;
  }   
  memcpy(seedA, &pk_in[PARAM_N*PARAM_K*PARAM_Q_LOG/8], CRYPTO_SEEDBYTES);
}


void encode_sig(unsigned char *sm, unsigned char *c, poly z)
{ // Encode signature sm
  unsigned int i, j=0;
  uint64_t *t = (uint64_t*)z;
  uint32_t *pt = (uint32_t*)sm;
  
  for (i=0; i<(PARAM_N*PARAM_D/32); i+=(PARAM_D/8)) {
    pt[i  ] = (uint32_t)((t[j] & ((1<<24)-1)) | (t[j+1] << 24));
    pt[i+1] = (uint32_t)(((t[j+1] >>  8) & ((1<<16)-1)) | (t[j+2] << 16));
    pt[i+2] = (uint32_t)(((t[j+2] >> 16) & ((1<< 8)-1)) | (t[j+3] <<  8));
    j += 4;
  }
  memcpy(&sm[PARAM_N*PARAM_D/8], c, CRYPTO_C_BYTES);
}


void decode_sig(unsigned char *c, poly z, const unsigned char *sm)
{ // Decode signature sm
  unsigned int i, j=0;
  uint32_t *pt = (uint32_t*)sm;

  for (i=0; i<PARAM_N; i+=4) {
    z[i  ] = ((int32_t)pt[j+0] << 8) >> 8;
    z[i+1] = (int32_t)((pt[j+0] >> 24) & ((1<< 8)-1)) | ((int32_t)(pt[j+1] << 16) >> 8);
    z[i+2] = (int32_t)((pt[j+1] >> 16) & ((1<<16)-1)) | ((int32_t)(pt[j+2] << 24) >> 8);
    z[i+3] = (int32_t)(pt[j+2]) >> 8;
    j += 3;
  }  
  memcpy(c, &sm[PARAM_N*PARAM_D/8], CRYPTO_C_BYTES);
}