/*************************************************************************************
* qTESLA: an efficient post-quantum signature scheme based on the R-LWE problem
*
* Abstract: high-level functions of the signature scheme
**************************************************************************************/

#include <string.h>
#include <stdlib.h>
#include "api.h"
#include "params.h"
#include "poly.h"
#include "pack.h"
#include "sample.h"
#include "gauss.h"
#include "sha3/fips202.h"
#include "random/random.h"

#ifdef DEBUG
unsigned long long rejwctr;
unsigned long long rejyzctr;
unsigned long long ctr_keygen;
unsigned long long ctr_sign;
#endif


void hash_H(unsigned char *c_bin, poly v, const unsigned char *hm)
{ // Hash-based function H to generate c'
  unsigned char t[PARAM_N+HM_BYTES];
  int32_t mask, cL;

  for (int i=0; i<PARAM_N; i++) { 
    // If v[i] > PARAM_Q/2 then v[i] -= PARAM_Q
    mask = (PARAM_Q/2 - v[i]) >> (RADIX32-1);                    
    v[i] = ((v[i]-PARAM_Q) & mask) | (v[i] & ~mask);
    
    cL = v[i] & ((1<<PARAM_D)-1);
    // If cL > 2^(d-1) then cL -= 2^d
    mask = ((1<<(PARAM_D-1)) - cL) >> (RADIX32-1);                    
    cL = ((cL-(1<<PARAM_D)) & mask) | (cL & ~mask);  
    t[i] = (unsigned char)((v[i] - cL) >> PARAM_D);      
  }  
  memcpy(&t[PARAM_N], hm, HM_BYTES);
  SHAKE(c_bin, CRYPTO_C_BYTES, t, PARAM_N+HM_BYTES);
}


static __inline int32_t Abs(int32_t value)
{ // Compute absolute value

    int32_t mask = value >> (RADIX32-1);
    return ((mask ^ value) - mask);
}


static int test_rejection(poly z)
{ // Check bounds for signature vector z during signing. Returns 0 if valid, otherwise outputs 1 if invalid (rejected).
  // This function does not leak any information about the coefficient that fails the test.
  uint32_t valid = 0;

  for (int i=0; i<PARAM_N; i++) {
    valid |= (uint32_t)(PARAM_B-PARAM_S) - Abs(z[i]);
  }
  return (int)(valid >> 31);
}


static int test_correctness(poly v)
{ // Check bounds for w = v - ec during signature verification. Returns 0 if valid, otherwise outputs 1 if invalid (rejected).
  // This function leaks the position of the coefficient that fails the test (but this is independent of the secret data). 
  // It does not leak the sign of the coefficients.
  int32_t mask, left, val;
  uint32_t t0, t1;
  
  for (int i=0; i<PARAM_N; i++) {      
    // If v[i] > PARAM_Q/2 then v[i] -= PARAM_Q
    mask = (PARAM_Q/2 - v[i]) >> (RADIX32-1);
    val = ((v[i]-PARAM_Q) & mask) | (v[i] & ~mask);
    // If (Abs(val) < PARAM_Q/2 - PARAM_E) then t0 = 0, else t0 = 1
    t0 = (uint32_t)(~(Abs(val) - (PARAM_Q/2 - PARAM_E))) >> (RADIX32-1);
                     
    left = val;
    val = (val + (1<<(PARAM_D-1))-1) >> PARAM_D; 
    val = left - (val << PARAM_D);
    // If (Abs(val) < (1<<(PARAM_D-1))-PARAM_E) then t1 = 0, else t1 = 1 
    t1 = (uint32_t)(~(Abs(val) - ((1<<(PARAM_D-1))-PARAM_E))) >> (RADIX32-1); 

    if ((t0 | t1) == 1)  // Returns 1 if any of the two tests failed
      return 1;
  }
  return 0;
}


static int test_z(poly z)
{ // Check bounds for signature vector z during signature verification
  // Returns 0 if valid, otherwise outputs 1 if invalid (rejected)
  
  for (int i=0; i<PARAM_N; i++) {                                  
    if (z[i] < -(PARAM_B-PARAM_S) || z[i] > (PARAM_B-PARAM_S))
      return 1;
  }
  return 0;
}


static int check_ES(poly p, unsigned int bound)
{ // Checks the generated polynomial e or s
  // Returns 0 if ok, otherwise returns 1
  unsigned int i, j, sum = 0, limit = PARAM_N;
  int32_t temp, mask, list[PARAM_N];

  for (j=0; j<PARAM_N; j++)    
    list[j] = Abs(p[j]);

  for (j=0; j<PARAM_H; j++) {
    for (i=0; i<limit-1; i++) {
      // If list[i+1] > list[i] then exchange contents
      mask = (list[i+1] - list[i]) >> (RADIX32-1);  
      temp = (list[i+1] & mask) | (list[i] & ~mask);
      list[i+1] = (list[i] & mask) | (list[i+1] & ~mask);
      list[i] = temp;
    }
    sum += (unsigned int)list[limit-1];
    limit -= 1;
  }

  if (sum > bound)
    return 1;
  return 0;
}


/*********************************************************
* Name:        crypto_sign_keypair
* Description: generates a public and private key pair
* Parameters:  inputs:  none
*              outputs:
*              - unsigned char *pk: public key
*              - unsigned char *sk: secret key
* Returns:     0 for successful execution
**********************************************************/
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk)
{
  unsigned char randomness[CRYPTO_RANDOMBYTES], randomness_extended[4*CRYPTO_SEEDBYTES];
  poly s, e, a, t;
  int nonce = 0;  // Initialize domain separator for error and secret polynomials
#ifdef DEBUG
  ctr_keygen=0;
#endif

  // Get randomness_extended <- seed_e, seed_s, seed_a, seed_y
  randombytes(randomness, CRYPTO_RANDOMBYTES);
  SHAKE(randomness_extended, 4*CRYPTO_SEEDBYTES, randomness, CRYPTO_RANDOMBYTES);

  do {  // Sample the error polynomial
#ifdef DEBUG
  ctr_keygen++;
#endif
    sample_gauss_poly(e, randomness_extended, ++nonce);        
  } while(check_ES(e, PARAM_KEYGEN_BOUND_E) != 0);  
 
  do {  // Sample the secret polynomial
#ifdef DEBUG
  ctr_keygen++;
#endif
    sample_gauss_poly(s, &randomness_extended[CRYPTO_SEEDBYTES], ++nonce);
  } while(check_ES(s, PARAM_KEYGEN_BOUND_S) != 0);

  // Generate uniform polynomial "a"
  poly_uniform(a, &randomness_extended[2*CRYPTO_SEEDBYTES]);
  
  // Compute the public key t = as+e
  poly_mul(t, a, s);
  poly_add_correct(t, t, e);
    
  // Pack public and private keys
  encode_sk(sk, s, e, &randomness_extended[2*CRYPTO_SEEDBYTES]);
  encode_pk(pk, t, &randomness_extended[2*CRYPTO_SEEDBYTES]);

  return 0;
}


/***************************************************************
* Name:        crypto_sign
* Description: outputs a signature for a given message m
* Parameters:  inputs:
*              - const unsigned char *m: message to be signed
*              - unsigned long long mlen: message length
*              - const unsigned char* sk: secret key
*              outputs:
*              - unsigned char *sm: signature
*              - unsigned long long *smlen: signature length*
* Returns:     0 for successful execution
***************************************************************/
int crypto_sign(unsigned char *sm, unsigned long long *smlen, const unsigned char *m, unsigned long long mlen, const unsigned char* sk)
{
  unsigned char c[CRYPTO_C_BYTES], randomness[CRYPTO_SEEDBYTES], randomness_input[CRYPTO_RANDOMBYTES+CRYPTO_SEEDBYTES+HM_BYTES], seeds[2*CRYPTO_SEEDBYTES];
  uint32_t pos_list[PARAM_H];
  int16_t sign_list[PARAM_H], s[PARAM_N], e[PARAM_N];
  poly y, v, Sc, Ec, z, a;
  int nonce = 0;  // Initialize domain separator for sampling y   
#ifdef DEBUG
  ctr_sign=0;
  rejwctr=0;
  rejyzctr=0;
#endif
  
  // Get {seed_a, seed_y}, s and e 
  decode_sk(seeds, s, e, sk);

  // Get H(seed_y, r, H(m)) to sample y
  randombytes(randomness_input+CRYPTO_RANDOMBYTES, CRYPTO_RANDOMBYTES);
  memcpy(randomness_input, &seeds[CRYPTO_SEEDBYTES], CRYPTO_SEEDBYTES);
  SHAKE(randomness_input+CRYPTO_RANDOMBYTES+CRYPTO_SEEDBYTES, HM_BYTES, m, mlen);
  SHAKE(randomness, CRYPTO_SEEDBYTES, randomness_input, CRYPTO_RANDOMBYTES+CRYPTO_SEEDBYTES+HM_BYTES);
  
  poly_uniform(a, seeds);

  while (1) {
#ifdef DEBUG
  ctr_sign++;
#endif    
    sample_y(y, randomness, ++nonce);           // Sample y uniformly at random from [-B,B]
    poly_mul(v, a, y); 
    hash_H(c, v, randomness_input+CRYPTO_RANDOMBYTES+CRYPTO_SEEDBYTES);
    encode_c(pos_list, sign_list, c);           // Generate c = Enc(c'), where c' is the hashing of v together with m
    sparse_mul16(Sc, s, pos_list, sign_list);
    poly_add(z, y, Sc);                         // Compute z = y + sc
    
    if (test_rejection(z) != 0) {               // Rejection sampling
#ifdef DEBUG
  rejyzctr++;
#endif
      continue;
    }
 
    sparse_mul16(Ec, e, pos_list, sign_list);
    poly_sub_correct(v, v, Ec);                       
    
    if (test_correctness(v) != 0) {
#ifdef DEBUG
  rejwctr++;
#endif
      continue;
    }    

    // Copy message to signature package, and pack signature
    for (unsigned long long i = 0; i < mlen; i++)
      sm[CRYPTO_BYTES+i] = m[i];
    *smlen = CRYPTO_BYTES + mlen; 
    encode_sig(sm, c, z);

    return 0;
  }
}


/************************************************************
* Name:        crypto_sign_open
* Description: verification of a signature sm
* Parameters:  inputs:
*              - const unsigned char *sm: signature
*              - unsigned long long smlen: signature length
*              - const unsigned char* pk: public Key
*              outputs:
*              - unsigned char *m: original (signed) message
*              - unsigned long long *mlen: message length*
* Returns:     0 for valid signature
*              <0 for invalid signature
************************************************************/
int crypto_sign_open(unsigned char *m, unsigned long long *mlen, const unsigned char *sm, unsigned long long smlen, const unsigned char *pk)
{
  unsigned char c[CRYPTO_C_BYTES], c_sig[CRYPTO_C_BYTES], seed[CRYPTO_SEEDBYTES], hm[HM_BYTES];
  uint32_t pos_list[PARAM_H];
  int16_t sign_list[PARAM_H]; 
  int32_t pk_t[PARAM_N];
  poly w, z, a, Tc;

  if (smlen < CRYPTO_BYTES) return -1;

  decode_sig(c, z, sm);  
  if (test_z(z) != 0) return -2;                 // Check norm of z
  decode_pk(pk_t, seed, pk);
  poly_uniform(a, seed);
  encode_c(pos_list, sign_list, c);              
  sparse_mul32(Tc, pk_t, pos_list, sign_list);    
  poly_mul(w, a, z);          
  poly_sub_reduce(w, w, Tc);                     // Compute w = az - tc
  SHAKE(hm, HM_BYTES, sm+CRYPTO_BYTES, smlen-CRYPTO_BYTES);
  hash_H(c_sig, w, hm);

  // Check if the calculated c matches c from the signature
  if (memcmp(c, c_sig, CRYPTO_C_BYTES)) return -3;
  
  *mlen = smlen-CRYPTO_BYTES;
  for (unsigned long long i = 0; i < *mlen; i++)
    m[i] = sm[CRYPTO_BYTES+i];

  return 0;
}