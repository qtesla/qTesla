/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: packing functions
**************************************************************************************/

#include <string.h>
#include "api.h"
#include "params.h"
#include "poly.h"


void encode_sk(unsigned char *sk, const poly s, const poly e, const unsigned char *seeds)
{ // Encode secret key sk
  unsigned int i, j=0;
  
  for (i=0; i<PARAM_N; i+=4) {
    sk[j+0] = (unsigned char)s[i+0];
    sk[j+1] = (unsigned char)(((s[i+0] >> 8) & 0x03) | (s[i+1] << 2));
    sk[j+2] = (unsigned char)(((s[i+1] >> 6) & 0x0F) | (s[i+2] << 4));
    sk[j+3] = (unsigned char)(((s[i+2] >> 4) & 0x3F) | (s[i+3] << 6));
    sk[j+4] = (unsigned char)(s[i+3] >> 2);
    j += 5;
  }  
  for (i=0; i<PARAM_N; i+=4) {
    sk[j+0] = (unsigned char)e[i+0];
    sk[j+1] = (unsigned char)(((e[i+0] >> 8) & 0x03) | (e[i+1] << 2));
    sk[j+2] = (unsigned char)(((e[i+1] >> 6) & 0x0F) | (e[i+2] << 4));
    sk[j+3] = (unsigned char)(((e[i+2] >> 4) & 0x3F) | (e[i+3] << 6));
    sk[j+4] = (unsigned char)(e[i+3] >> 2);
    j += 5;
  }  
  memcpy(&sk[2*PARAM_S_BITS*PARAM_N/8], seeds, 2*CRYPTO_SEEDBYTES);
}


void decode_sk(unsigned char *seeds, int16_t *s, int16_t *e, const unsigned char *sk)
{ // Decode secret key sk
  unsigned int i, j=0;
  
  for (i=0; i<PARAM_N; i+=4) {
    s[i+0] = (int16_t)sk[j+0]        | (int16_t)(((int32_t)sk[j+1] << 30) >> 22);
    s[i+1] = (int16_t)(sk[j+1] >> 2) | (int16_t)(((int32_t)sk[j+2] << 28) >> 22);
    s[i+2] = (int16_t)(sk[j+2] >> 4) | (int16_t)(((int32_t)sk[j+3] << 26) >> 22);
    s[i+3] = (int16_t)(sk[j+3] >> 6) | (int16_t)(signed char)sk[j+4] << 2;
    j += 5;
  } 
  for (i=0; i<PARAM_N; i+=4) {
    e[i+0] = (int16_t)sk[j+0]        | (int16_t)(((int32_t)sk[j+1] << 30) >> 22);
    e[i+1] = (int16_t)(sk[j+1] >> 2) | (int16_t)(((int32_t)sk[j+2] << 28) >> 22);
    e[i+2] = (int16_t)(sk[j+2] >> 4) | (int16_t)(((int32_t)sk[j+3] << 26) >> 22);
    e[i+3] = (int16_t)(sk[j+3] >> 6) | (int16_t)(signed char)sk[j+4] << 2;
    j += 5;
  }  
  memcpy(seeds, &sk[2*PARAM_S_BITS*PARAM_N/8], 2*CRYPTO_SEEDBYTES);
}


void encode_pk(unsigned char *pk, const poly t, const unsigned char *seedA)
{ // Encode public key pk
  unsigned int i, j=0;
  uint32_t *pt = (uint32_t*)pk;
  
  for (i=0; i<(PARAM_N*PARAM_Q_LOG/32); i+=PARAM_Q_LOG) {
    pt[i   ] = (uint32_t)(t[j] | (t[j+1] << 23));
    pt[i+ 1] = (uint32_t)((t[j+ 1] >>  9) | (t[j+ 2] << 14)); pt[i+ 2] = (uint32_t)((t[j+ 2] >> 18) | (t[j+ 3] <<  5) | (t[j+ 4] << 28));
    pt[i+ 3] = (uint32_t)((t[j+ 4] >>  4) | (t[j+ 5] << 19));
    pt[i+ 4] = (uint32_t)((t[j+ 5] >> 13) | (t[j+ 6] << 10)); pt[i+ 5] = (uint32_t)((t[j+ 6] >> 22) | (t[j+ 7] <<  1) | (t[j+ 8] << 24));
    pt[i+ 6] = (uint32_t)((t[j+ 8] >>  8) | (t[j+ 9] << 15)); pt[i+ 7] = (uint32_t)((t[j+ 9] >> 17) | (t[j+10] <<  6) | (t[j+11] << 29));
    pt[i+ 8] = (uint32_t)((t[j+11] >>  3) | (t[j+12] << 20));
    pt[i+ 9] = (uint32_t)((t[j+12] >> 12) | (t[j+13] << 11)); pt[i+10] = (uint32_t)((t[j+13] >> 21) | (t[j+14] <<  2) | (t[j+15] << 25));
    pt[i+11] = (uint32_t)((t[j+15] >>  7) | (t[j+16] << 16)); pt[i+12] = (uint32_t)((t[j+16] >> 16) | (t[j+17] <<  7) | (t[j+18] << 30));
    pt[i+13] = (uint32_t)((t[j+18] >>  2) | (t[j+19] << 21));
    pt[i+14] = (uint32_t)((t[j+19] >> 11) | (t[j+20] << 12)); pt[i+15] = (uint32_t)((t[j+20] >> 20) | (t[j+21] <<  3) | (t[j+22] << 26));
    pt[i+16] = (uint32_t)((t[j+22] >>  6) | (t[j+23] << 17)); pt[i+17] = (uint32_t)((t[j+23] >> 15) | (t[j+24] <<  8) | (t[j+25] << 31));
    pt[i+18] = (uint32_t)((t[j+25] >>  1) | (t[j+26] << 22));
    pt[i+19] = (uint32_t)((t[j+26] >> 10) | (t[j+27] << 13)); pt[i+20] = (uint32_t)((t[j+27] >> 19) | (t[j+28] <<  4) | (t[j+29] << 27));
    pt[i+21] = (uint32_t)((t[j+29] >>  5) | (t[j+30] << 18));
    pt[i+22] = (uint32_t)((t[j+30] >> 14) | (t[j+31] <<  9));
    j += 32;
  }
  memcpy(&pk[PARAM_N*PARAM_Q_LOG/8], seedA, CRYPTO_SEEDBYTES);
}


void decode_pk(int32_t *pk, unsigned char *seedA, const unsigned char *pk_in)
{ // Decode public key pk
  unsigned int i, j=0;
  uint32_t *pt = (uint32_t*)pk_in, mask23 = (1<<PARAM_Q_LOG)-1;
  uint32_t *pp = (uint32_t*)pk; 

  for (i=0; i<PARAM_N; i+=32) {
    pp[i   ] = pt[j] & mask23; 
    pp[i+ 1] = ((pt[j+ 0] >> 23) | (pt[j+ 1] <<  9)) & mask23; 
    pp[i+ 2] = ((pt[j+ 1] >> 14) | (pt[j+ 2] << 18)) & mask23; pp[i+ 3] = (pt[j+ 2] >> 5) & mask23;
    pp[i+ 4] = ((pt[j+ 2] >> 28) | (pt[j+ 3] <<  4)) & mask23;
    pp[i+ 5] = ((pt[j+ 3] >> 19) | (pt[j+ 4] << 13)) & mask23;
    pp[i+ 6] = ((pt[j+ 4] >> 10) | (pt[j+ 5] << 22)) & mask23; pp[i+ 7] = (pt[j+ 5] >> 1) & mask23;
    pp[i+ 8] = ((pt[j+ 5] >> 24) | (pt[j+ 6] <<  8)) & mask23;
    pp[i+ 9] = ((pt[j+ 6] >> 15) | (pt[j+ 7] << 17)) & mask23; pp[i+10] = (pt[j+ 7] >> 6) & mask23;
    pp[i+11] = ((pt[j+ 7] >> 29) | (pt[j+ 8] <<  3)) & mask23;
    pp[i+12] = ((pt[j+ 8] >> 20) | (pt[j+ 9] << 12)) & mask23;
    pp[i+13] = ((pt[j+ 9] >> 11) | (pt[j+10] << 21)) & mask23; pp[i+14] = (pt[j+10] >> 2) & mask23;
    pp[i+15] = ((pt[j+10] >> 25) | (pt[j+11] <<  7)) & mask23;
    pp[i+16] = ((pt[j+11] >> 16) | (pt[j+12] << 16)) & mask23; pp[i+17] = (pt[j+12] >> 7) & mask23;
    pp[i+18] = ((pt[j+12] >> 30) | (pt[j+13] <<  2)) & mask23;
    pp[i+19] = ((pt[j+13] >> 21) | (pt[j+14] << 11)) & mask23;
    pp[i+20] = ((pt[j+14] >> 12) | (pt[j+15] << 20)) & mask23; pp[i+21] = (pt[j+15] >> 3) & mask23;
    pp[i+22] = ((pt[j+15] >> 26) | (pt[j+16] <<  6)) & mask23;
    pp[i+23] = ((pt[j+16] >> 17) | (pt[j+17] << 15)) & mask23; pp[i+24] = (pt[j+17] >> 8) & mask23;
    pp[i+25] = ((pt[j+17] >> 31) | (pt[j+18] <<  1)) & mask23;
    pp[i+26] = ((pt[j+18] >> 22) | (pt[j+19] << 10)) & mask23;
    pp[i+27] = ((pt[j+19] >> 13) | (pt[j+20] << 19)) & mask23; pp[i+28] = (pt[j+20] >> 4) & mask23;
    pp[i+29] = ((pt[j+20] >> 27) | (pt[j+21] <<  5)) & mask23;
    pp[i+30] = ((pt[j+21] >> 18) | (pt[j+22] << 14)) & mask23;
    pp[i+31] = pt[j+22] >> 9;
    j += 23;
  }   
  memcpy(seedA, &pk_in[PARAM_N*PARAM_Q_LOG/8], CRYPTO_SEEDBYTES);
}


void encode_sig(unsigned char *sm, unsigned char *c, poly z)
{ // Encode signature sm
  unsigned int i, j=0;
  uint32_t *t = (uint32_t*)z;
  uint32_t *pt = (uint32_t*)sm;
  
  for (i=0; i<(PARAM_N*PARAM_D/32); i+=PARAM_D) {
    pt[i   ] = (uint32_t)((t[j] & ((1<<21)-1)) | (t[j+1] << 21));
    pt[i+ 1] = (uint32_t)(((t[j+ 1] >> 11) & ((1<<10)-1)) | ((t[j+ 2] & ((1<<21)-1)) << 10) | (t[j+ 3] << 31));
    pt[i+ 2] = (uint32_t)(((t[j+ 3] >>  1) & ((1<<20)-1)) | (t[j+4] << 20));
    pt[i+ 3] = (uint32_t)(((t[j+ 4] >> 12) & ((1<<9)-1 )) | ((t[j+ 5] & ((1<<21)-1)) <<  9) | (t[j+ 6] << 30));
    pt[i+ 4] = (uint32_t)(((t[j+ 6] >>  2) & ((1<<19)-1)) | (t[j+7] << 19));
    pt[i+ 5] = (uint32_t)(((t[j+ 7] >> 13) & ((1<<8)-1 )) | ((t[j+ 8] & ((1<<21)-1)) <<  8) | (t[j+ 9] << 29));
    pt[i+ 6] = (uint32_t)(((t[j+ 9] >>  3) & ((1<<18)-1)) | (t[j+10] << 18));
    pt[i+ 7] = (uint32_t)(((t[j+10] >> 14) & ((1<<7)-1 )) | ((t[j+11] & ((1<<21)-1)) <<  7) | (t[j+12] << 28));
    pt[i+ 8] = (uint32_t)(((t[j+12] >>  4) & ((1<<17)-1)) | (t[j+13] << 17));
    pt[i+ 9] = (uint32_t)(((t[j+13] >> 15) & ((1<<6)-1 )) | ((t[j+14] & ((1<<21)-1)) <<  6) | (t[j+15] << 27));
    pt[i+10] = (uint32_t)(((t[j+15] >>  5) & ((1<<16)-1)) | (t[j+16] << 16));
    pt[i+11] = (uint32_t)(((t[j+16] >> 16) & ((1<<5)-1 )) | ((t[j+17] & ((1<<21)-1)) <<  5) | (t[j+18] << 26));
    pt[i+12] = (uint32_t)(((t[j+18] >>  6) & ((1<<15)-1)) | (t[j+19] << 15));
    pt[i+13] = (uint32_t)(((t[j+19] >> 17) & ((1<<4)-1 )) | ((t[j+20] & ((1<<21)-1)) <<  4) | (t[j+21] << 25));
    pt[i+14] = (uint32_t)(((t[j+21] >>  7) & ((1<<14)-1)) | (t[j+22] << 14));
    pt[i+15] = (uint32_t)(((t[j+22] >> 18) & ((1<<3)-1 )) | ((t[j+23] & ((1<<21)-1)) <<  3) | (t[j+24] << 24));
    pt[i+16] = (uint32_t)(((t[j+24] >>  8) & ((1<<13)-1)) | (t[j+25] << 13));
    pt[i+17] = (uint32_t)(((t[j+25] >> 19) & ((1<<2)-1 )) | ((t[j+26] & ((1<<21)-1)) <<  2) | (t[j+27] << 23));
    pt[i+18] = (uint32_t)(((t[j+27] >>  9) & ((1<<12)-1)) | (t[j+28] << 12));
    pt[i+19] = (uint32_t)(((t[j+28] >> 20) & ((1<<1)-1 )) | ((t[j+29] & ((1<<21)-1)) <<  1) | (t[j+30] << 22));
    pt[i+20] = (uint32_t)(((t[j+30] >> 10) & ((1<<11)-1)) | (t[j+31] << 11));
    j += 32;
  }
  memcpy(&sm[PARAM_N*PARAM_D/8], c, CRYPTO_C_BYTES);
}


void decode_sig(unsigned char *c, poly z, const unsigned char *sm)
{ // Decode signature sm
  unsigned int i, j=0;
  uint32_t *pt = (uint32_t*)sm;

  for (i=0; i<PARAM_N; i+=32) {
    z[i   ] = (int32_t)(pt[j+ 0] << 11) >> 11; z[i+ 1] = (int32_t)(pt[j+ 0] >> 21) | ((int32_t)(pt[j+ 1] << 22) >> 11); 
    z[i+ 2] = (int32_t)(pt[j+ 1] <<  1) >> 11; z[i+ 3] = (int32_t)(pt[j+ 1] >> 31) | ((int32_t)(pt[j+ 2] << 12) >> 11);
    z[i+ 4] = (int32_t)(pt[j+ 2] >> 20) | ((int32_t)(pt[j+ 3] << 23) >> 11);
    z[i+ 5] = (int32_t)(pt[j+ 3] <<  2) >> 11; z[i+ 6] = (int32_t)(pt[j+ 3] >> 30) | ((int32_t)(pt[j+ 4] << 13) >> 11);
    z[i+ 7] = (int32_t)(pt[j+ 4] >> 19) | ((int32_t)(pt[j+ 5] << 24) >> 11);
    z[i+ 8] = (int32_t)(pt[j+ 5] <<  3) >> 11; z[i+ 9] = (int32_t)(pt[j+ 5] >> 29) | ((int32_t)(pt[j+ 6] << 14) >> 11);
    z[i+10] = (int32_t)(pt[j+ 6] >> 18) | ((int32_t)(pt[j+ 7] << 25) >> 11);
    z[i+11] = (int32_t)(pt[j+ 7] <<  4) >> 11; z[i+12] = (int32_t)(pt[j+ 7] >> 28) | ((int32_t)(pt[j+ 8] << 15) >> 11);
    z[i+13] = (int32_t)(pt[j+ 8] >> 17) | ((int32_t)(pt[j+ 9] << 26) >> 11);
    z[i+14] = (int32_t)(pt[j+ 9] <<  5) >> 11; z[i+15] = (int32_t)(pt[j+ 9] >> 27) | ((int32_t)(pt[j+10] << 16) >> 11);
    z[i+16] = (int32_t)(pt[j+10] >> 16) | ((int32_t)(pt[j+11] << 27) >> 11);
    z[i+17] = (int32_t)(pt[j+11] <<  6) >> 11; z[i+18] = (int32_t)(pt[j+11] >> 26) | ((int32_t)(pt[j+12] << 17) >> 11);
    z[i+19] = (int32_t)(pt[j+12] >> 15) | ((int32_t)(pt[j+13] << 28) >> 11);
    z[i+20] = (int32_t)(pt[j+13] <<  7) >> 11; z[i+21] = (int32_t)(pt[j+13] >> 25) | ((int32_t)(pt[j+14] << 18) >> 11);
    z[i+22] = (int32_t)(pt[j+14] >> 14) | ((int32_t)(pt[j+15] << 29) >> 11);
    z[i+23] = (int32_t)(pt[j+15] <<  8) >> 11; z[i+24] = (int32_t)(pt[j+15] >> 24) | ((int32_t)(pt[j+16] << 19) >> 11);
    z[i+25] = (int32_t)(pt[j+16] >> 13) | ((int32_t)(pt[j+17] << 30) >> 11);
    z[i+26] = (int32_t)(pt[j+17] <<  9) >> 11; z[i+27] = (int32_t)(pt[j+17] >> 23) | ((int32_t)(pt[j+18] << 20) >> 11);
    z[i+28] = (int32_t)(pt[j+18] >> 12) | ((int32_t)(pt[j+19] << 31) >> 11);
    z[i+29] = (int32_t)(pt[j+19] << 10) >> 11; z[i+30] = (int32_t)(pt[j+19] >> 22) | ((int32_t)(pt[j+20] << 21) >> 11);
    z[i+31] = (int32_t)pt[j+20] >> 11;
    j += 21;
  }   
  memcpy(c, &sm[PARAM_N*PARAM_D/8], CRYPTO_C_BYTES);
}