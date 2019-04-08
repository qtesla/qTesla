#ifndef POLY_H
#define POLY_H

#include "params.h"
#include "config.h"
#include <stdint.h>

typedef int32_t poly[PARAM_N]     __attribute__((aligned(32)));
typedef int32_t poly2x[2*PARAM_N] __attribute__((aligned(32)));

int32_t reduce(int64_t a);
void poly_mul(poly result, const poly x, const poly y);
void poly_add(poly result, const poly x, const poly y);
void poly_add_correct(poly result, const poly x, const poly y);
void poly_sub_correct(poly result, const poly x, const poly y);
void poly_sub_reduce(poly result, const poly x, const poly y);
void sparse_mul16(poly prod, const int16_t *s, const uint32_t pos_list[PARAM_H], const int16_t sign_list[PARAM_H]);
void sparse_mul32(poly prod, const int32_t *pk, const uint32_t pos_list[PARAM_H], const int16_t sign_list[PARAM_H]);
void poly_uniform(poly a, const unsigned char *seed);

void poly_mul_asm(poly c, const poly a, const poly2x w, const poly2x temp, const poly b);
void sparse_mul16_asm(poly prod, const unsigned char *sk, const uint32_t pos_list[PARAM_H], const int16_t sign_list[PARAM_H]);

#endif
