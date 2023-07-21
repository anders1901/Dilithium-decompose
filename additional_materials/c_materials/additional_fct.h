#ifndef SIGN_H
#define SIGN_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "params.h"
#include "polyvec.h"
#include "poly.h"


int	FindMarker(FILE *infile, const char *marker);
int	ReadHex(FILE *infile, unsigned char *a, int Length, char *str);
void	fprintBstr(FILE *fp, char *s, unsigned char *a, unsigned long long l);

void poly_2gamma2(poly *a);

void polyveck_2gamma2(polyveck *v) ;

#define crypto_sign_collect_w0 DILITHIUM_NAMESPACE(collect)
int crypto_sign_collect_w0(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk);

#define crypto_sign_filter DILITHIUM_NAMESPACE(filter)
void crypto_sign_filter(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk,
                          const uint8_t *pk,
                          uint64_t *w0_to_0_detected_filter,
                          uint64_t *w0_to_0_total,
                          uint64_t *values_detected_filter);
#endif
