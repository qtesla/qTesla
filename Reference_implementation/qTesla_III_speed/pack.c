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
  
  for (i=0; i<PARAM_N; i+=8) {
    sk[j+0] = (unsigned char)s[i+0];
    sk[j+1] = (unsigned char)(((s[i+0] >> 8) & 0x01) | (s[i+1] << 1));
    sk[j+2] = (unsigned char)(((s[i+1] >> 7) & 0x03) | (s[i+2] << 2));
    sk[j+3] = (unsigned char)(((s[i+2] >> 6) & 0x07) | (s[i+3] << 3));
    sk[j+4] = (unsigned char)(((s[i+3] >> 5) & 0x0F) | (s[i+4] << 4));
    sk[j+5] = (unsigned char)(((s[i+4] >> 4) & 0x1F) | (s[i+5] << 5));
    sk[j+6] = (unsigned char)(((s[i+5] >> 3) & 0x3F) | (s[i+6] << 6));
    sk[j+7] = (unsigned char)(((s[i+6] >> 2) & 0x7F) | (s[i+7] << 7));
    sk[j+8] = (unsigned char)(s[i+7] >> 1);
    j += 9;
  } 
  for (i=0; i<PARAM_N; i+=8) {
    sk[j+0] = (unsigned char)e[i+0];
    sk[j+1] = (unsigned char)(((e[i+0] >> 8) & 0x01) | (e[i+1] << 1));
    sk[j+2] = (unsigned char)(((e[i+1] >> 7) & 0x03) | (e[i+2] << 2));
    sk[j+3] = (unsigned char)(((e[i+2] >> 6) & 0x07) | (e[i+3] << 3));
    sk[j+4] = (unsigned char)(((e[i+3] >> 5) & 0x0F) | (e[i+4] << 4));
    sk[j+5] = (unsigned char)(((e[i+4] >> 4) & 0x1F) | (e[i+5] << 5));
    sk[j+6] = (unsigned char)(((e[i+5] >> 3) & 0x3F) | (e[i+6] << 6));
    sk[j+7] = (unsigned char)(((e[i+6] >> 2) & 0x7F) | (e[i+7] << 7));
    sk[j+8] = (unsigned char)(e[i+7] >> 1);
    j += 9;
  }  
  memcpy(&sk[2*PARAM_S_BITS*PARAM_N/8], seeds, 2*CRYPTO_SEEDBYTES);
}


void decode_sk(unsigned char *seeds, int16_t *s, int16_t *e, const unsigned char *sk)
{ // Decode secret key sk
  unsigned int i, j=0;
  
  for (i=0; i<PARAM_N; i+=8) {
    s[i+0] = (int16_t)sk[j+0]        | (int16_t)(((int32_t)sk[j+1] << 31) >> 23);
    s[i+1] = (int16_t)(sk[j+1] >> 1) | (int16_t)(((int32_t)sk[j+2] << 30) >> 23);
    s[i+2] = (int16_t)(sk[j+2] >> 2) | (int16_t)(((int32_t)sk[j+3] << 29) >> 23);
    s[i+3] = (int16_t)(sk[j+3] >> 3) | (int16_t)(((int32_t)sk[j+4] << 28) >> 23);
    s[i+4] = (int16_t)(sk[j+4] >> 4) | (int16_t)(((int32_t)sk[j+5] << 27) >> 23);
    s[i+5] = (int16_t)(sk[j+5] >> 5) | (int16_t)(((int32_t)sk[j+6] << 26) >> 23);
    s[i+6] = (int16_t)(sk[j+6] >> 6) | (int16_t)(((int32_t)sk[j+7] << 25) >> 23);
    s[i+7] = (int16_t)(sk[j+7] >> 7) | (int16_t)(signed char)sk[j+8] << 1;
    j += 9;
  }
  for (i=0; i<PARAM_N; i+=8) {
    e[i+0] = (int16_t)sk[j+0]        | (int16_t)(((int32_t)sk[j+1] << 31) >> 23);
    e[i+1] = (int16_t)(sk[j+1] >> 1) | (int16_t)(((int32_t)sk[j+2] << 30) >> 23);
    e[i+2] = (int16_t)(sk[j+2] >> 2) | (int16_t)(((int32_t)sk[j+3] << 29) >> 23);
    e[i+3] = (int16_t)(sk[j+3] >> 3) | (int16_t)(((int32_t)sk[j+4] << 28) >> 23);
    e[i+4] = (int16_t)(sk[j+4] >> 4) | (int16_t)(((int32_t)sk[j+5] << 27) >> 23);
    e[i+5] = (int16_t)(sk[j+5] >> 5) | (int16_t)(((int32_t)sk[j+6] << 26) >> 23);
    e[i+6] = (int16_t)(sk[j+6] >> 6) | (int16_t)(((int32_t)sk[j+7] << 25) >> 23);
    e[i+7] = (int16_t)(sk[j+7] >> 7) | (int16_t)(signed char)sk[j+8] << 1;
    j += 9;
  }   
  memcpy(seeds, &sk[2*PARAM_S_BITS*PARAM_N/8], 2*CRYPTO_SEEDBYTES);
}


void encode_pk(unsigned char *pk, const poly t, const unsigned char *seedA)
{ // Encode public key pk
  unsigned int i, j=0;
  uint32_t *pt = (uint32_t*)pk;
  
  for (i=0; i<(PARAM_N*PARAM_Q_LOG/32); i+=(PARAM_Q_LOG/8)) {
    pt[i  ] = (uint32_t)(t[j] | (t[j+1] << 24));
    pt[i+1] = (uint32_t)((t[j+1] >>  8) | (t[j+2] << 16)); 
    pt[i+2] = (uint32_t)((t[j+2] >> 16) | (t[j+3] <<  8));
    j += 4;
  }
  memcpy(&pk[PARAM_N*PARAM_Q_LOG/8], seedA, CRYPTO_SEEDBYTES);
}


void decode_pk(int32_t *pk, unsigned char *seedA, const unsigned char *pk_in)
{ // Decode public key pk
  unsigned int i, j=0;
  uint32_t *pt = (uint32_t*)pk_in, mask24 = (1<<PARAM_Q_LOG)-1;
  uint32_t *pp = (uint32_t*)pk; 

  for (i=0; i<PARAM_N; i+=4) {
    pp[i  ] = pt[j] & mask24; 
    pp[i+1] = ((pt[j  ] >> 24) | (pt[j+1] <<  8)) & mask24; 
    pp[i+2] = ((pt[j+1] >> 16) | (pt[j+2] << 16)) & mask24; 
    pp[i+3] = pt[j+2] >> 8;
    j += 3;
  }   
  memcpy(seedA, &pk_in[PARAM_N*PARAM_Q_LOG/8], CRYPTO_SEEDBYTES);
}


void encode_sig(unsigned char *sm, unsigned char *c, poly z)
{ // Encode signature sm
  unsigned int i, j=0;
  uint32_t *t = (uint32_t*)z;
  uint32_t *pt = (uint32_t*)sm;
  
  for (i=0; i<(PARAM_N*PARAM_D/32); i+=(PARAM_D/2)) {
    pt[i   ] = (uint32_t)((t[j] & ((1<<22)-1)) | (t[j+1] << 22));
    pt[i+ 1] = (uint32_t)(((t[j+ 1] >> 10) & ((1<<12)-1)) | (t[j+2] << 12));
    pt[i+ 2] = (uint32_t)(((t[j+ 2] >> 20) & ((1<< 2)-1)) | ((t[j+ 3] & ((1<<22)-1)) << 2) | (t[j+ 4] << 24));
    pt[i+ 3] = (uint32_t)(((t[j+ 4] >>  8) & ((1<<14)-1)) | (t[j+5] << 14));
    pt[i+ 4] = (uint32_t)(((t[j+ 5] >> 18) & ((1<<4)-1 )) | ((t[j+ 6] & ((1<<22)-1)) << 4) | (t[j+ 7] << 26));
    pt[i+ 5] = (uint32_t)(((t[j+ 7] >>  6) & ((1<<16)-1)) | (t[j+8] << 16));
    pt[i+ 6] = (uint32_t)(((t[j+ 8] >> 16) & ((1<<6)-1 )) | ((t[j+ 9] & ((1<<22)-1)) << 6) | (t[j+10] << 28));
    pt[i+ 7] = (uint32_t)(((t[j+10] >>  4) & ((1<<18)-1)) | (t[j+11] << 18));
    pt[i+ 8] = (uint32_t)(((t[j+11] >> 14) & ((1<<8)-1 )) | ((t[j+12] & ((1<<22)-1)) << 8) | (t[j+13] << 30));
    pt[i+ 9] = (uint32_t)(((t[j+13] >>  2) & ((1<<20)-1)) | (t[j+14] << 20));
    pt[i+10] = (uint32_t)(((t[j+14] >> 12) & ((1<<10)-1)) | (t[j+15] << 10));
    j += 16;
  }
  memcpy(&sm[PARAM_N*PARAM_D/8], c, CRYPTO_C_BYTES);
}


void decode_sig(unsigned char *c, poly z, const unsigned char *sm)
{ // Decode signature sm
  unsigned int i, j=0;
  uint32_t *pt = (uint32_t*)sm;

  for (i=0; i<PARAM_N; i+=16) {
    z[i   ] = ((int32_t)pt[j+ 0] << 10) >> 10; 
    z[i+ 1] = (int32_t)(pt[j+ 0] >> 22) | ((int32_t)(pt[j+ 1] << 20) >> 10); 
    z[i+ 2] = (int32_t)(pt[j+ 1] >> 12) | ((int32_t)(pt[j+ 2] << 30) >> 10);
    z[i+ 3] = (int32_t)(pt[j+ 2] <<  8) >> 10; 
    z[i+ 4] = (int32_t)(pt[j+ 2] >> 24) | ((int32_t)(pt[j+ 3] << 18) >> 10);
    z[i+ 5] = (int32_t)(pt[j+ 3] >> 14) | ((int32_t)(pt[j+ 4] << 28) >> 10);
    z[i+ 6] = (int32_t)(pt[j+ 4] <<  6) >> 10; 
    z[i+ 7] = (int32_t)(pt[j+ 4] >> 26) | ((int32_t)(pt[j+ 5] << 16) >> 10);
    z[i+ 8] = (int32_t)(pt[j+ 5] >> 16) | ((int32_t)(pt[j+ 6] << 26) >> 10);
    z[i+ 9] = (int32_t)(pt[j+ 6] <<  4) >> 10; 
    z[i+10] = (int32_t)(pt[j+ 6] >> 28) | ((int32_t)(pt[j+ 7] << 14) >> 10);
    z[i+11] = (int32_t)(pt[j+ 7] >> 18) | ((int32_t)(pt[j+ 8] << 24) >> 10);
    z[i+12] = (int32_t)(pt[j+ 8] <<  2) >> 10; 
    z[i+13] = (int32_t)(pt[j+ 8] >> 30) | ((int32_t)(pt[j+ 9] << 12) >> 10);
    z[i+14] = (int32_t)(pt[j+ 9] >> 20) | ((int32_t)(pt[j+10] << 22) >> 10);
    z[i+15] = (int32_t)pt[j+10] >> 10;
    j += 11;
  }   
  memcpy(c, &sm[PARAM_N*PARAM_D/8], CRYPTO_C_BYTES);
}