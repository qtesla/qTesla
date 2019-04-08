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

#if PARAM_S_BITS==8 /* <= 8 bits per secret coefficient */
  for (i=0; i<PARAM_N; i++, j++) {
    sk[j] = (unsigned char)s[i];
  }
  for (i=0; i<PARAM_N; i++, j++) {
    sk[j] = (unsigned char)e[i];
  }
#elif PARAM_S_BITS==9
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
#elif PARAM_S_BITS==10
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
#else
    #error "NOT IMPLEMENTED"
#endif
  memcpy(&sk[2*PARAM_S_BITS*PARAM_N/8], seeds, 2*CRYPTO_SEEDBYTES);
}


void decode_sk(unsigned char *seeds, poly s, poly e, const unsigned char *sk)
{ // Decode secret key sk
  unsigned int i, j=0;

#if PARAM_S_BITS==8
  for (i=0; i<PARAM_N; i++, j++) {
    s[i] = (signed char)sk[j];
  }
  for (i=0; i<PARAM_N; i++, j++) {
    e[i] = (signed char)sk[j];
  }
#elif PARAM_S_BITS==9
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
#elif PARAM_S_BITS==10
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
#else
    #error "NOT IMPLEMENTED"
#endif
  memcpy(seeds, &sk[2*PARAM_S_BITS*PARAM_N/8], 2*CRYPTO_SEEDBYTES);
}


void encode_pk(unsigned char *pk, const poly t, const unsigned char *seedA)
{ // Encode public key pk
  unsigned int i, j=0;
  uint32_t *pt = (uint32_t*)pk;

  for (i=0; i<(PARAM_N*PARAM_Q_LOG/32); i+=PARAM_Q_LOG) {
#if PARAM_Q_LOG==23
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
#elif PARAM_Q_LOG==24
    pt[i+ 0] = (uint32_t)( t[j+ 0]        | (t[j+ 1] << 24));
    pt[i+ 1] = (uint32_t)((t[j+ 1] >>  8) | (t[j+ 2] << 16));
    pt[i+ 2] = (uint32_t)((t[j+ 2] >> 16) | (t[j+ 3] <<  8));
    pt[i+ 3] = (uint32_t)( t[j+ 4]        | (t[j+ 5] << 24));
    pt[i+ 4] = (uint32_t)((t[j+ 5] >>  8) | (t[j+ 6] << 16));
    pt[i+ 5] = (uint32_t)((t[j+ 6] >> 16) | (t[j+ 7] <<  8));
    pt[i+ 6] = (uint32_t)( t[j+ 8]        | (t[j+ 9] << 24));
    pt[i+ 7] = (uint32_t)((t[j+ 9] >>  8) | (t[j+10] << 16));
    pt[i+ 8] = (uint32_t)((t[j+10] >> 16) | (t[j+11] <<  8));
    pt[i+ 9] = (uint32_t)( t[j+12]        | (t[j+13] << 24));
    pt[i+10] = (uint32_t)((t[j+13] >>  8) | (t[j+14] << 16));
    pt[i+11] = (uint32_t)((t[j+14] >> 16) | (t[j+15] <<  8));
    pt[i+12] = (uint32_t)( t[j+16]        | (t[j+17] << 24));
    pt[i+13] = (uint32_t)((t[j+17] >>  8) | (t[j+18] << 16));
    pt[i+14] = (uint32_t)((t[j+18] >> 16) | (t[j+19] <<  8));
    pt[i+15] = (uint32_t)( t[j+20]        | (t[j+21] << 24));
    pt[i+16] = (uint32_t)((t[j+21] >>  8) | (t[j+22] << 16));
    pt[i+17] = (uint32_t)((t[j+22] >> 16) | (t[j+23] <<  8));
    pt[i+18] = (uint32_t)( t[j+24]        | (t[j+25] << 24));
    pt[i+19] = (uint32_t)((t[j+25] >>  8) | (t[j+26] << 16));
    pt[i+20] = (uint32_t)((t[j+26] >> 16) | (t[j+27] <<  8));
    pt[i+21] = (uint32_t)( t[j+28]        | (t[j+29] << 24));
    pt[i+22] = (uint32_t)((t[j+29] >>  8) | (t[j+30] << 16));
    pt[i+23] = (uint32_t)((t[j+30] >> 16) | (t[j+31] <<  8));
#elif PARAM_Q_LOG==25
    pt[i+ 0] = (uint32_t)( t[j+ 0]        | (t[j+ 1] << 25));
    pt[i+ 1] = (uint32_t)((t[j+ 1] >>  7) | (t[j+ 2] << 18));
    pt[i+ 2] = (uint32_t)((t[j+ 2] >> 14) | (t[j+ 3] << 11));
    pt[i+ 3] = (uint32_t)((t[j+ 3] >> 21) | (t[j+ 4] <<  4) | (t[j+ 5] << 29));
    pt[i+ 4] = (uint32_t)((t[j+ 5] >>  3) | (t[j+ 6] << 22));
    pt[i+ 5] = (uint32_t)((t[j+ 6] >> 10) | (t[j+ 7] << 15));
    pt[i+ 6] = (uint32_t)((t[j+ 7] >> 17) | (t[j+ 8] <<  8));
    pt[i+ 7] = (uint32_t)((t[j+ 8] >> 24) | (t[j+ 9] <<  1) | (t[j+10] << 26));
    pt[i+ 8] = (uint32_t)((t[j+10] >>  6) | (t[j+11] << 19));
    pt[i+ 9] = (uint32_t)((t[j+11] >> 13) | (t[j+12] << 12));
    pt[i+10] = (uint32_t)((t[j+12] >> 20) | (t[j+13] <<  5) | (t[j+14] << 30));
    pt[i+11] = (uint32_t)((t[j+14] >>  2) | (t[j+15] << 23));
    pt[i+12] = (uint32_t)((t[j+15] >>  9) | (t[j+16] << 16));
    pt[i+13] = (uint32_t)((t[j+16] >> 16) | (t[j+17] <<  9));
    pt[i+14] = (uint32_t)((t[j+17] >> 23) | (t[j+18] <<  2) | (t[j+19] << 27));
    pt[i+15] = (uint32_t)((t[j+19] >>  5) | (t[j+20] << 20));
    pt[i+16] = (uint32_t)((t[j+20] >> 12) | (t[j+21] << 13));
    pt[i+17] = (uint32_t)((t[j+21] >> 19) | (t[j+22] <<  6) | (t[j+23] << 31));
    pt[i+18] = (uint32_t)((t[j+23] >>  1) | (t[j+24] << 24));
    pt[i+19] = (uint32_t)((t[j+24] >>  8) | (t[j+25] << 17));
    pt[i+20] = (uint32_t)((t[j+25] >> 15) | (t[j+26] << 10));
    pt[i+21] = (uint32_t)((t[j+26] >> 22) | (t[j+27] <<  3) | (t[j+28] << 28));
    pt[i+22] = (uint32_t)((t[j+28] >>  4) | (t[j+29] << 21));
    pt[i+23] = (uint32_t)((t[j+29] >> 11) | (t[j+30] << 14));
    pt[i+24] = (uint32_t)((t[j+30] >> 18) | (t[j+31] <<  7));
#elif PARAM_Q_LOG==26
    pt[i+ 0] = (uint32_t)( t[j+ 0]        | (t[j+ 1] << 26));
    pt[i+ 1] = (uint32_t)((t[j+ 1] >>  6) | (t[j+ 2] << 20));
    pt[i+ 2] = (uint32_t)((t[j+ 2] >> 12) | (t[j+ 3] << 14));
    pt[i+ 3] = (uint32_t)((t[j+ 3] >> 18) | (t[j+ 4] <<  8));
    pt[i+ 4] = (uint32_t)((t[j+ 4] >> 24) | (t[j+ 5] <<  2) | (t[j+ 6] << 28));
    pt[i+ 5] = (uint32_t)((t[j+ 6] >>  4) | (t[j+ 7] << 22));
    pt[i+ 6] = (uint32_t)((t[j+ 7] >> 10) | (t[j+ 8] << 16));
    pt[i+ 7] = (uint32_t)((t[j+ 8] >> 16) | (t[j+ 9] << 10));
    pt[i+ 8] = (uint32_t)((t[j+ 9] >> 22) | (t[j+10] <<  4) | (t[j+11] << 30));
    pt[i+ 9] = (uint32_t)((t[j+11] >>  2) | (t[j+12] << 24));
    pt[i+10] = (uint32_t)((t[j+12] >>  8) | (t[j+13] << 18));
    pt[i+11] = (uint32_t)((t[j+13] >> 14) | (t[j+14] << 12));
    pt[i+12] = (uint32_t)((t[j+14] >> 20) | (t[j+15] <<  6));
    pt[i+13] = (uint32_t)( t[j+16]        | (t[j+17] << 26));
    pt[i+14] = (uint32_t)((t[j+17] >>  6) | (t[j+18] << 20));
    pt[i+15] = (uint32_t)((t[j+18] >> 12) | (t[j+19] << 14));
    pt[i+16] = (uint32_t)((t[j+19] >> 18) | (t[j+20] <<  8));
    pt[i+17] = (uint32_t)((t[j+20] >> 24) | (t[j+21] <<  2) | (t[j+22] << 28));
    pt[i+18] = (uint32_t)((t[j+22] >>  4) | (t[j+23] << 22));
    pt[i+19] = (uint32_t)((t[j+23] >> 10) | (t[j+24] << 16));
    pt[i+20] = (uint32_t)((t[j+24] >> 16) | (t[j+25] << 10));
    pt[i+21] = (uint32_t)((t[j+25] >> 22) | (t[j+26] <<  4) | (t[j+27] << 30));
    pt[i+22] = (uint32_t)((t[j+27] >>  2) | (t[j+28] << 24));
    pt[i+23] = (uint32_t)((t[j+28] >>  8) | (t[j+29] << 18));
    pt[i+24] = (uint32_t)((t[j+29] >> 14) | (t[j+30] << 12));
    pt[i+25] = (uint32_t)((t[j+30] >> 20) | (t[j+31] <<  6));
#else
    #error "NOT IMPLEMENTED"
#endif
    j += 32;
  }
  memcpy(&pk[PARAM_N*PARAM_Q_LOG/8], seedA, CRYPTO_SEEDBYTES);
}


#define maskq ((1<<PARAM_Q_LOG)-1)

void decode_pk(int32_t *pk, unsigned char *seedA, const unsigned char *pk_in)
{ // Decode public key pk
  unsigned int i, j=0;
  uint32_t *pt = (uint32_t*)pk_in;
  uint32_t *t = (uint32_t*)pk;

  for (i=0; i<PARAM_N; i+=32) {
#if PARAM_Q_LOG==23
    t[i   ] = pt[j] & maskq;
    t[i+ 1] = ((pt[j+ 0] >> 23) | (pt[j+ 1] <<  9)) & maskq;
    t[i+ 2] = ((pt[j+ 1] >> 14) | (pt[j+ 2] << 18)) & maskq; t[i+ 3] = (pt[j+ 2] >> 5) & maskq;
    t[i+ 4] = ((pt[j+ 2] >> 28) | (pt[j+ 3] <<  4)) & maskq;
    t[i+ 5] = ((pt[j+ 3] >> 19) | (pt[j+ 4] << 13)) & maskq;
    t[i+ 6] = ((pt[j+ 4] >> 10) | (pt[j+ 5] << 22)) & maskq; t[i+ 7] = (pt[j+ 5] >> 1) & maskq;
    t[i+ 8] = ((pt[j+ 5] >> 24) | (pt[j+ 6] <<  8)) & maskq;
    t[i+ 9] = ((pt[j+ 6] >> 15) | (pt[j+ 7] << 17)) & maskq; t[i+10] = (pt[j+ 7] >> 6) & maskq;
    t[i+11] = ((pt[j+ 7] >> 29) | (pt[j+ 8] <<  3)) & maskq;
    t[i+12] = ((pt[j+ 8] >> 20) | (pt[j+ 9] << 12)) & maskq;
    t[i+13] = ((pt[j+ 9] >> 11) | (pt[j+10] << 21)) & maskq; t[i+14] = (pt[j+10] >> 2) & maskq;
    t[i+15] = ((pt[j+10] >> 25) | (pt[j+11] <<  7)) & maskq;
    t[i+16] = ((pt[j+11] >> 16) | (pt[j+12] << 16)) & maskq; t[i+17] = (pt[j+12] >> 7) & maskq;
    t[i+18] = ((pt[j+12] >> 30) | (pt[j+13] <<  2)) & maskq;
    t[i+19] = ((pt[j+13] >> 21) | (pt[j+14] << 11)) & maskq;
    t[i+20] = ((pt[j+14] >> 12) | (pt[j+15] << 20)) & maskq; t[i+21] = (pt[j+15] >> 3) & maskq;
    t[i+22] = ((pt[j+15] >> 26) | (pt[j+16] <<  6)) & maskq;
    t[i+23] = ((pt[j+16] >> 17) | (pt[j+17] << 15)) & maskq; t[i+24] = (pt[j+17] >> 8) & maskq;
    t[i+25] = ((pt[j+17] >> 31) | (pt[j+18] <<  1)) & maskq;
    t[i+26] = ((pt[j+18] >> 22) | (pt[j+19] << 10)) & maskq;
    t[i+27] = ((pt[j+19] >> 13) | (pt[j+20] << 19)) & maskq; t[i+28] = (pt[j+20] >> 4) & maskq;
    t[i+29] = ((pt[j+20] >> 27) | (pt[j+21] <<  5)) & maskq;
    t[i+30] = ((pt[j+21] >> 18) | (pt[j+22] << 14)) & maskq;
    t[i+31] = pt[j+22] >> 9;
#elif PARAM_Q_LOG==24
    t[i+ 0] = ( pt[j+ 0]       ) & maskq;
    t[i+ 1] = ((pt[j+ 0] >> 24) | (pt[j+ 1] <<  8)) & maskq;
    t[i+ 2] = ((pt[j+ 1] >> 16) | (pt[j+ 2] << 16)) & maskq;
    t[i+ 3] = ((pt[j+ 2] >>  8)) & maskq;
    t[i+ 4] = ( pt[j+ 3]       ) & maskq;
    t[i+ 5] = ((pt[j+ 3] >> 24) | (pt[j+ 4] <<  8)) & maskq;
    t[i+ 6] = ((pt[j+ 4] >> 16) | (pt[j+ 5] << 16)) & maskq;
    t[i+ 7] = ((pt[j+ 5] >>  8)) & maskq;
    t[i+ 8] = ( pt[j+ 6]       ) & maskq;
    t[i+ 9] = ((pt[j+ 6] >> 24) | (pt[j+ 7] <<  8)) & maskq;
    t[i+10] = ((pt[j+ 7] >> 16) | (pt[j+ 8] << 16)) & maskq;
    t[i+11] = ((pt[j+ 8] >>  8)) & maskq;
    t[i+12] = ( pt[j+ 9]       ) & maskq;
    t[i+13] = ((pt[j+ 9] >> 24) | (pt[j+10] <<  8)) & maskq;
    t[i+14] = ((pt[j+10] >> 16) | (pt[j+11] << 16)) & maskq;
    t[i+15] = ((pt[j+11] >>  8)) & maskq;
    t[i+16] = ( pt[j+12]       ) & maskq;
    t[i+17] = ((pt[j+12] >> 24) | (pt[j+13] <<  8)) & maskq;
    t[i+18] = ((pt[j+13] >> 16) | (pt[j+14] << 16)) & maskq;
    t[i+19] = ((pt[j+14] >>  8)) & maskq;
    t[i+20] = ( pt[j+15]       ) & maskq;
    t[i+21] = ((pt[j+15] >> 24) | (pt[j+16] <<  8)) & maskq;
    t[i+22] = ((pt[j+16] >> 16) | (pt[j+17] << 16)) & maskq;
    t[i+23] = ((pt[j+17] >>  8)) & maskq;
    t[i+24] = ( pt[j+18]       ) & maskq;
    t[i+25] = ((pt[j+18] >> 24) | (pt[j+19] <<  8)) & maskq;
    t[i+26] = ((pt[j+19] >> 16) | (pt[j+20] << 16)) & maskq;
    t[i+27] = ((pt[j+20] >>  8)) & maskq;
    t[i+28] = ( pt[j+21]       ) & maskq;
    t[i+29] = ((pt[j+21] >> 24) | (pt[j+22] <<  8)) & maskq;
    t[i+30] = ((pt[j+22] >> 16) | (pt[j+23] << 16)) & maskq;
    t[i+31] = ((pt[j+23] >>  8)) & maskq;
#elif PARAM_Q_LOG==25
    t[i+ 0] = ( pt[j+ 0]       ) & maskq;
    t[i+ 1] = ((pt[j+ 0] >> 25) | (pt[j+ 1] <<  7)) & maskq;
    t[i+ 2] = ((pt[j+ 1] >> 18) | (pt[j+ 2] << 14)) & maskq;
    t[i+ 3] = ((pt[j+ 2] >> 11) | (pt[j+ 3] << 21)) & maskq;
    t[i+ 4] = ((pt[j+ 3] >>  4)) & maskq;
    t[i+ 5] = ((pt[j+ 3] >> 29) | (pt[j+ 4] <<  3)) & maskq;
    t[i+ 6] = ((pt[j+ 4] >> 22) | (pt[j+ 5] << 10)) & maskq;
    t[i+ 7] = ((pt[j+ 5] >> 15) | (pt[j+ 6] << 17)) & maskq;
    t[i+ 8] = ((pt[j+ 6] >>  8) | (pt[j+ 7] << 24)) & maskq;
    t[i+ 9] = ((pt[j+ 7] >>  1)) & maskq;
    t[i+10] = ((pt[j+ 7] >> 26) | (pt[j+ 8] <<  6)) & maskq;
    t[i+11] = ((pt[j+ 8] >> 19) | (pt[j+ 9] << 13)) & maskq;
    t[i+12] = ((pt[j+ 9] >> 12) | (pt[j+10] << 20)) & maskq;
    t[i+13] = ((pt[j+10] >>  5)) & maskq;
    t[i+14] = ((pt[j+10] >> 30) | (pt[j+11] <<  2)) & maskq;
    t[i+15] = ((pt[j+11] >> 23) | (pt[j+12] <<  9)) & maskq;
    t[i+16] = ((pt[j+12] >> 16) | (pt[j+13] << 16)) & maskq;
    t[i+17] = ((pt[j+13] >>  9) | (pt[j+14] << 23)) & maskq;
    t[i+18] = ((pt[j+14] >>  2)) & maskq;
    t[i+19] = ((pt[j+14] >> 27) | (pt[j+15] <<  5)) & maskq;
    t[i+20] = ((pt[j+15] >> 20) | (pt[j+16] << 12)) & maskq;
    t[i+21] = ((pt[j+16] >> 13) | (pt[j+17] << 19)) & maskq;
    t[i+22] = ((pt[j+17] >>  6)) & maskq;
    t[i+23] = ((pt[j+17] >> 31) | (pt[j+18] <<  1)) & maskq;
    t[i+24] = ((pt[j+18] >> 24) | (pt[j+19] <<  8)) & maskq;
    t[i+25] = ((pt[j+19] >> 17) | (pt[j+20] << 15)) & maskq;
    t[i+26] = ((pt[j+20] >> 10) | (pt[j+21] << 22)) & maskq;
    t[i+27] = ((pt[j+21] >>  3)) & maskq;
    t[i+28] = ((pt[j+21] >> 28) | (pt[j+22] <<  4)) & maskq;
    t[i+29] = ((pt[j+22] >> 21) | (pt[j+23] << 11)) & maskq;
    t[i+30] = ((pt[j+23] >> 14) | (pt[j+24] << 18)) & maskq;
    t[i+31] = ((pt[j+24] >>  7)) & maskq;
#elif PARAM_Q_LOG==26
    t[i+ 0] = ( pt[j+ 0]       ) & maskq;
    t[i+ 1] = ((pt[j+ 0] >> 26) | (pt[j+ 1] <<  6)) & maskq;
    t[i+ 2] = ((pt[j+ 1] >> 20) | (pt[j+ 2] << 12)) & maskq;
    t[i+ 3] = ((pt[j+ 2] >> 14) | (pt[j+ 3] << 18)) & maskq;
    t[i+ 4] = ((pt[j+ 3] >>  8) | (pt[j+ 4] << 24)) & maskq;
    t[i+ 5] = ((pt[j+ 4] >>  2)) & maskq;
    t[i+ 6] = ((pt[j+ 4] >> 28) | (pt[j+ 5] <<  4)) & maskq;
    t[i+ 7] = ((pt[j+ 5] >> 22) | (pt[j+ 6] << 10)) & maskq;
    t[i+ 8] = ((pt[j+ 6] >> 16) | (pt[j+ 7] << 16)) & maskq;
    t[i+ 9] = ((pt[j+ 7] >> 10) | (pt[j+ 8] << 22)) & maskq;
    t[i+10] = ((pt[j+ 8] >>  4)) & maskq;
    t[i+11] = ((pt[j+ 8] >> 30) | (pt[j+ 9] <<  2)) & maskq;
    t[i+12] = ((pt[j+ 9] >> 24) | (pt[j+10] <<  8)) & maskq;
    t[i+13] = ((pt[j+10] >> 18) | (pt[j+11] << 14)) & maskq;
    t[i+14] = ((pt[j+11] >> 12) | (pt[j+12] << 20)) & maskq;
    t[i+15] = ((pt[j+12] >>  6)) & maskq;
    t[i+16] = ( pt[j+13]       ) & maskq;
    t[i+17] = ((pt[j+13] >> 26) | (pt[j+14] <<  6)) & maskq;
    t[i+18] = ((pt[j+14] >> 20) | (pt[j+15] << 12)) & maskq;
    t[i+19] = ((pt[j+15] >> 14) | (pt[j+16] << 18)) & maskq;
    t[i+20] = ((pt[j+16] >>  8) | (pt[j+17] << 24)) & maskq;
    t[i+21] = ((pt[j+17] >>  2)) & maskq;
    t[i+22] = ((pt[j+17] >> 28) | (pt[j+18] <<  4)) & maskq;
    t[i+23] = ((pt[j+18] >> 22) | (pt[j+19] << 10)) & maskq;
    t[i+24] = ((pt[j+19] >> 16) | (pt[j+20] << 16)) & maskq;
    t[i+25] = ((pt[j+20] >> 10) | (pt[j+21] << 22)) & maskq;
    t[i+26] = ((pt[j+21] >>  4)) & maskq;
    t[i+27] = ((pt[j+21] >> 30) | (pt[j+22] <<  2)) & maskq;
    t[i+28] = ((pt[j+22] >> 24) | (pt[j+23] <<  8)) & maskq;
    t[i+29] = ((pt[j+23] >> 18) | (pt[j+24] << 14)) & maskq;
    t[i+30] = ((pt[j+24] >> 12) | (pt[j+25] << 20)) & maskq;
    t[i+31] = ((pt[j+25] >>  6)) & maskq;
#else
    #error "NOT IMPLEMENTED"
#endif
    j += PARAM_Q_LOG;
  }
  memcpy(seedA, &pk_in[PARAM_N*PARAM_Q_LOG/8], CRYPTO_SEEDBYTES);
}


#define maskd ((1<<(PARAM_B_BITS+1))-1)

void encode_sig(unsigned char *sm, unsigned char *c, poly z)
{ // Encode signature sm
  unsigned int i, j=0;
  uint32_t *t = (uint32_t*)z;
  uint32_t *pt = (uint32_t*)sm;

#if (PARAM_B_BITS+1)==21
  for (i=0; i<(PARAM_N*(PARAM_B_BITS+1)/32); i+=(PARAM_B_BITS+1)) {
    pt[i   ] = (uint32_t)((t[j] & ((1<<21)-1)) | (t[j+1] << 21));
    pt[i+ 1] = (uint32_t)(((t[j+ 1] >> 11) & ((1<<10)-1)) | ((t[j+ 2] & maskd) << 10) | (t[j+ 3] << 31));
    pt[i+ 2] = (uint32_t)(((t[j+ 3] >>  1) & ((1<<20)-1)) | (t[j+4] << 20));
    pt[i+ 3] = (uint32_t)(((t[j+ 4] >> 12) & ((1<<9)-1 )) | ((t[j+ 5] & maskd) <<  9) | (t[j+ 6] << 30));
    pt[i+ 4] = (uint32_t)(((t[j+ 6] >>  2) & ((1<<19)-1)) | (t[j+7] << 19));
    pt[i+ 5] = (uint32_t)(((t[j+ 7] >> 13) & ((1<<8)-1 )) | ((t[j+ 8] & maskd) <<  8) | (t[j+ 9] << 29));
    pt[i+ 6] = (uint32_t)(((t[j+ 9] >>  3) & ((1<<18)-1)) | (t[j+10] << 18));
    pt[i+ 7] = (uint32_t)(((t[j+10] >> 14) & ((1<<7)-1 )) | ((t[j+11] & maskd) <<  7) | (t[j+12] << 28));
    pt[i+ 8] = (uint32_t)(((t[j+12] >>  4) & ((1<<17)-1)) | (t[j+13] << 17));
    pt[i+ 9] = (uint32_t)(((t[j+13] >> 15) & ((1<<6)-1 )) | ((t[j+14] & maskd) <<  6) | (t[j+15] << 27));
    pt[i+10] = (uint32_t)(((t[j+15] >>  5) & ((1<<16)-1)) | (t[j+16] << 16));
    pt[i+11] = (uint32_t)(((t[j+16] >> 16) & ((1<<5)-1 )) | ((t[j+17] & maskd) <<  5) | (t[j+18] << 26));
    pt[i+12] = (uint32_t)(((t[j+18] >>  6) & ((1<<15)-1)) | (t[j+19] << 15));
    pt[i+13] = (uint32_t)(((t[j+19] >> 17) & ((1<<4)-1 )) | ((t[j+20] & maskd) <<  4) | (t[j+21] << 25));
    pt[i+14] = (uint32_t)(((t[j+21] >>  7) & ((1<<14)-1)) | (t[j+22] << 14));
    pt[i+15] = (uint32_t)(((t[j+22] >> 18) & ((1<<3)-1 )) | ((t[j+23] & maskd) <<  3) | (t[j+24] << 24));
    pt[i+16] = (uint32_t)(((t[j+24] >>  8) & ((1<<13)-1)) | (t[j+25] << 13));
    pt[i+17] = (uint32_t)(((t[j+25] >> 19) & ((1<<2)-1 )) | ((t[j+26] & maskd) <<  2) | (t[j+27] << 23));
    pt[i+18] = (uint32_t)(((t[j+27] >>  9) & ((1<<12)-1)) | (t[j+28] << 12));
    pt[i+19] = (uint32_t)(((t[j+28] >> 20) & ((1<<1)-1 )) | ((t[j+29] & maskd) <<  1) | (t[j+30] << 22));
    pt[i+20] = (uint32_t)(((t[j+30] >> 10) & ((1<<11)-1)) | (t[j+31] << 11));
    j += 32;
  }
#elif (PARAM_B_BITS+1)==22
  for (i=0; i<(PARAM_N*(PARAM_B_BITS+1)/32); i+=((PARAM_B_BITS+1)/2)) {
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
#elif (PARAM_B_BITS+1)==23
  for (i=0; i<(PARAM_N*(PARAM_B_BITS+1)/32); i+=(PARAM_B_BITS+1)) {
    pt[i+ 0] = (uint32_t)( (t[j+ 0]        & ((1<<23)-1)) |  (t[j+ 1] << 23));
    pt[i+ 1] = (uint32_t)(((t[j+ 1] >>  9) & ((1<<14)-1)) |  (t[j+ 2] << 14));
    pt[i+ 2] = (uint32_t)(((t[j+ 2] >> 18) & ((1<< 5)-1)) | ((t[j+ 3] & maskd) <<  5) |  (t[j+ 4] << 28));
    pt[i+ 3] = (uint32_t)(((t[j+ 4] >>  4) & ((1<<19)-1)) |  (t[j+ 5] << 19));
    pt[i+ 4] = (uint32_t)(((t[j+ 5] >> 13) & ((1<<10)-1)) |  (t[j+ 6] << 10));
    pt[i+ 5] = (uint32_t)(((t[j+ 6] >> 22) & ((1<< 1)-1)) | ((t[j+ 7] & maskd) <<  1) |  (t[j+ 8] << 24));
    pt[i+ 6] = (uint32_t)(((t[j+ 8] >>  8) & ((1<<15)-1)) |  (t[j+ 9] << 15));
    pt[i+ 7] = (uint32_t)(((t[j+ 9] >> 17) & ((1<< 6)-1)) | ((t[j+10] & maskd) <<  6) |  (t[j+11] << 29));
    pt[i+ 8] = (uint32_t)(((t[j+11] >>  3) & ((1<<20)-1)) |  (t[j+12] << 20));
    pt[i+ 9] = (uint32_t)(((t[j+12] >> 12) & ((1<<11)-1)) |  (t[j+13] << 11));
    pt[i+10] = (uint32_t)(((t[j+13] >> 21) & ((1<< 2)-1)) | ((t[j+14] & maskd) <<  2) |  (t[j+15] << 25));
    pt[i+11] = (uint32_t)(((t[j+15] >>  7) & ((1<<16)-1)) |  (t[j+16] << 16));
    pt[i+12] = (uint32_t)(((t[j+16] >> 16) & ((1<< 7)-1)) | ((t[j+17] & maskd) <<  7) |  (t[j+18] << 30));
    pt[i+13] = (uint32_t)(((t[j+18] >>  2) & ((1<<21)-1)) |  (t[j+19] << 21));
    pt[i+14] = (uint32_t)(((t[j+19] >> 11) & ((1<<12)-1)) |  (t[j+20] << 12));
    pt[i+15] = (uint32_t)(((t[j+20] >> 20) & ((1<< 3)-1)) | ((t[j+21] & maskd) <<  3) |  (t[j+22] << 26));
    pt[i+16] = (uint32_t)(((t[j+22] >>  6) & ((1<<17)-1)) |  (t[j+23] << 17));
    pt[i+17] = (uint32_t)(((t[j+23] >> 15) & ((1<< 8)-1)) | ((t[j+24] & maskd) <<  8) |  (t[j+25] << 31));
    pt[i+18] = (uint32_t)(((t[j+25] >>  1) & ((1<<22)-1)) |  (t[j+26] << 22));
    pt[i+19] = (uint32_t)(((t[j+26] >> 10) & ((1<<13)-1)) |  (t[j+27] << 13));
    pt[i+20] = (uint32_t)(((t[j+27] >> 19) & ((1<< 4)-1)) | ((t[j+28] & maskd) <<  4) |  (t[j+29] << 27));
    pt[i+21] = (uint32_t)(((t[j+29] >>  5) & ((1<<18)-1)) |  (t[j+30] << 18));
    pt[i+22] = (uint32_t)(((t[j+30] >> 14) & ((1<< 9)-1)) |  (t[j+31] <<  9));
    j += 32;
  }
#elif (PARAM_B_BITS+1)==24
  for (i=0; i<(PARAM_N*(PARAM_B_BITS+1)/32); i+=(PARAM_B_BITS+1)/2) {
    pt[i+ 0] = (uint32_t)( (t[j+ 0]        & ((1<<24)-1)) |  (t[j+ 1] << 24));
    pt[i+ 1] = (uint32_t)(((t[j+ 1] >>  8) & ((1<<16)-1)) |  (t[j+ 2] << 16));
    pt[i+ 2] = (uint32_t)(((t[j+ 2] >> 16) & ((1<< 8)-1)) |  (t[j+ 3] <<  8));
    pt[i+ 3] = (uint32_t)( (t[j+ 4]        & ((1<<24)-1)) |  (t[j+ 5] << 24));
    pt[i+ 4] = (uint32_t)(((t[j+ 5] >>  8) & ((1<<16)-1)) |  (t[j+ 6] << 16));
    pt[i+ 5] = (uint32_t)(((t[j+ 6] >> 16) & ((1<< 8)-1)) |  (t[j+ 7] <<  8));
    pt[i+ 6] = (uint32_t)( (t[j+ 8]        & ((1<<24)-1)) |  (t[j+ 9] << 24));
    pt[i+ 7] = (uint32_t)(((t[j+ 9] >>  8) & ((1<<16)-1)) |  (t[j+10] << 16));
    pt[i+ 8] = (uint32_t)(((t[j+10] >> 16) & ((1<< 8)-1)) |  (t[j+11] <<  8));
    pt[i+ 9] = (uint32_t)( (t[j+12]        & ((1<<24)-1)) |  (t[j+13] << 24));
    pt[i+10] = (uint32_t)(((t[j+13] >>  8) & ((1<<16)-1)) |  (t[j+14] << 16));
    pt[i+11] = (uint32_t)(((t[j+14] >> 16) & ((1<< 8)-1)) |  (t[j+15] <<  8));
    j += 16;
  }
#else
    #error "NOT IMPLEMENTED"
#endif
  memcpy(&sm[PARAM_N*(PARAM_B_BITS+1)/8], c, CRYPTO_C_BYTES);
}


void decode_sig(unsigned char *c, poly z, const unsigned char *sm)
{ // Decode signature sm
  unsigned int i, j=0;
  uint32_t *pt = (uint32_t*)sm;

#if (PARAM_B_BITS+1)==21
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
    j += (PARAM_B_BITS+1);
  }
#elif (PARAM_B_BITS+1)==22
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
#elif (PARAM_B_BITS+1)==23
  for (i=0; i<PARAM_N; i+=32) {
    z[i+ 0] = ((int32_t) pt[j+ 0] << 9) >> 9;
    z[i+ 1] =  (int32_t)(pt[j+ 0] >> 23) | ((int32_t)(pt[j+ 1] << 18) >> 9);
    z[i+ 2] =  (int32_t)(pt[j+ 1] >> 14) | ((int32_t)(pt[j+ 2] << 27) >> 9);
    z[i+ 3] = ((int32_t) pt[j+ 2] <<  4) >> 9;
    z[i+ 4] =  (int32_t)(pt[j+ 2] >> 28) | ((int32_t)(pt[j+ 3] << 13) >> 9);
    z[i+ 5] =  (int32_t)(pt[j+ 3] >> 19) | ((int32_t)(pt[j+ 4] << 22) >> 9);
    z[i+ 6] =  (int32_t)(pt[j+ 4] >> 10) | ((int32_t)(pt[j+ 5] << 31) >> 9);
    z[i+ 7] = ((int32_t) pt[j+ 5] <<  8) >> 9;
    z[i+ 8] =  (int32_t)(pt[j+ 5] >> 24) | ((int32_t)(pt[j+ 6] << 17) >> 9);
    z[i+ 9] =  (int32_t)(pt[j+ 6] >> 15) | ((int32_t)(pt[j+ 7] << 26) >> 9);
    z[i+10] = ((int32_t) pt[j+ 7] <<  3) >> 9;
    z[i+11] =  (int32_t)(pt[j+ 7] >> 29) | ((int32_t)(pt[j+ 8] << 12) >> 9);
    z[i+12] =  (int32_t)(pt[j+ 8] >> 20) | ((int32_t)(pt[j+ 9] << 21) >> 9);
    z[i+13] =  (int32_t)(pt[j+ 9] >> 11) | ((int32_t)(pt[j+10] << 30) >> 9);
    z[i+14] = ((int32_t) pt[j+10] <<  7) >> 9;
    z[i+15] =  (int32_t)(pt[j+10] >> 25) | ((int32_t)(pt[j+11] << 16) >> 9);
    z[i+16] =  (int32_t)(pt[j+11] >> 16) | ((int32_t)(pt[j+12] << 25) >> 9);
    z[i+17] = ((int32_t) pt[j+12] <<  2) >> 9;
    z[i+18] =  (int32_t)(pt[j+12] >> 30) | ((int32_t)(pt[j+13] << 11) >> 9);
    z[i+19] =  (int32_t)(pt[j+13] >> 21) | ((int32_t)(pt[j+14] << 20) >> 9);
    z[i+20] =  (int32_t)(pt[j+14] >> 12) | ((int32_t)(pt[j+15] << 29) >> 9);
    z[i+21] = ((int32_t) pt[j+15] <<  6) >> 9;
    z[i+22] =  (int32_t)(pt[j+15] >> 26) | ((int32_t)(pt[j+16] << 15) >> 9);
    z[i+23] =  (int32_t)(pt[j+16] >> 17) | ((int32_t)(pt[j+17] << 24) >> 9);
    z[i+24] = ((int32_t) pt[j+17] <<  1) >> 9;
    z[i+25] =  (int32_t)(pt[j+17] >> 31) | ((int32_t)(pt[j+18] << 10) >> 9);
    z[i+26] =  (int32_t)(pt[j+18] >> 22) | ((int32_t)(pt[j+19] << 19) >> 9);
    z[i+27] =  (int32_t)(pt[j+19] >> 13) | ((int32_t)(pt[j+20] << 28) >> 9);
    z[i+28] = ((int32_t) pt[j+20] <<  5) >> 9;
    z[i+29] =  (int32_t)(pt[j+20] >> 27) | ((int32_t)(pt[j+21] << 14) >> 9);
    z[i+30] =  (int32_t)(pt[j+21] >> 18) | ((int32_t)(pt[j+22] << 23) >> 9);
    z[i+31] =  (int32_t) pt[j+22] >> 9;
    j += (PARAM_B_BITS+1);
  }
#elif (PARAM_B_BITS+1)==24
  for (i=0; i<PARAM_N; i+=16) {
    z[i+ 0] = ((int32_t) pt[j+ 0] << 8) >> 8;
    z[i+ 1] =  (int32_t)(pt[j+ 0] >> 24) | ((int32_t)(pt[j+ 1] << 16) >> 8);
    z[i+ 2] =  (int32_t)(pt[j+ 1] >> 16) | ((int32_t)(pt[j+ 2] << 24) >> 8);
    z[i+ 3] =  (int32_t) pt[j+ 2] >> 8;
    z[i+ 4] = ((int32_t) pt[j+ 3] << 8) >> 8;
    z[i+ 5] =  (int32_t)(pt[j+ 3] >> 24) | ((int32_t)(pt[j+ 4] << 16) >> 8);
    z[i+ 6] =  (int32_t)(pt[j+ 4] >> 16) | ((int32_t)(pt[j+ 5] << 24) >> 8);
    z[i+ 7] =  (int32_t) pt[j+ 5] >> 8;
    z[i+ 8] = ((int32_t) pt[j+ 6] << 8) >> 8;
    z[i+ 9] =  (int32_t)(pt[j+ 6] >> 24) | ((int32_t)(pt[j+ 7] << 16) >> 8);
    z[i+10] =  (int32_t)(pt[j+ 7] >> 16) | ((int32_t)(pt[j+ 8] << 24) >> 8);
    z[i+11] =  (int32_t) pt[j+ 8] >> 8;
    z[i+12] = ((int32_t) pt[j+ 9] << 8) >> 8;
    z[i+13] =  (int32_t)(pt[j+ 9] >> 24) | ((int32_t)(pt[j+10] << 16) >> 8);
    z[i+14] =  (int32_t)(pt[j+10] >> 16) | ((int32_t)(pt[j+11] << 24) >> 8);
    z[i+15] =  (int32_t) pt[j+11] >> 8;
    j += 12;
  }
#else
    #error "NOT IMPLEMENTED"
#endif
  memcpy(c, &sm[PARAM_N*(PARAM_B_BITS+1)/8], CRYPTO_C_BYTES);
}
