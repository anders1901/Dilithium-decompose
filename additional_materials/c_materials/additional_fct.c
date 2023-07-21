#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "params.h"
#include "packing.h"
#include "polyvec.h"
#include "poly.h"
#include "randombytes.h"
#include "symmetric.h"
#include "fips202.h"

#include "additional_fct.h"


#define	MAX_MARKER_LEN      50


//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
FindMarker(FILE *infile, const char *marker)
{
	char	line[MAX_MARKER_LEN];
	int	i, len;
	int	curr_line;

	len = (int)strlen(marker);
	if ( len > MAX_MARKER_LEN-1 )
	    len = MAX_MARKER_LEN-1;

	for ( i=0; i<len; i++ )
	  {
	    curr_line = fgetc(infile);
	    line[i] = curr_line;
	    if (curr_line == EOF )
	      return 0;
	  }
	line[len] = '\0';

	while ( 1 ) {
		if ( !strncmp(line, marker, len) )
			return 1;

		for ( i=0; i<len-1; i++ )
			line[i] = line[i+1];
		curr_line = fgetc(infile);
		line[len-1] = curr_line;
		if (curr_line == EOF )
			return 0;
		line[len] = '\0';
	}

	// shouldn't get here
	return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
ReadHex(FILE *infile, unsigned char *a, int Length, char *str)
{
	int		i, ch, started;
	unsigned char	ich;

	if ( Length == 0 ) {
		a[0] = 0x00;
		return 1;
	}
	memset(a, 0x00, Length);
	started = 0;
	if ( FindMarker(infile, str) )
		while ( (ch = fgetc(infile)) != EOF ) {
			if ( !isxdigit(ch) ) {
				if ( !started ) {
					if ( ch == '\n' )
						break;
					else
						continue;
				}
				else
					break;
			}
			started = 1;
			if ( (ch >= '0') && (ch <= '9') )
				ich = ch - '0';
			else if ( (ch >= 'A') && (ch <= 'F') )
				ich = ch - 'A' + 10;
			else if ( (ch >= 'a') && (ch <= 'f') )
				ich = ch - 'a' + 10;
			else // shouldn't ever get here
				ich = 0;

			for ( i=0; i<Length-1; i++ )
				a[i] = (a[i] << 4) | (a[i+1] >> 4);
			a[Length-1] = (a[Length-1] << 4) | ich;
		}
	else
		return 0;

	return 1;
}

void
fprintBstr(FILE *fp, char *s, unsigned char *a, unsigned long long l)
{
	unsigned long long  i;

	fprintf(fp, "%s", s);

	for ( i=0; i<l; i++ )
		fprintf(fp, "%02X", a[i]);

	if ( l == 0 )
		fprintf(fp, "00");

	fprintf(fp, "\n");
}


void
fprintBstr2(FILE *fp, int b, char *s, unsigned char *a, unsigned long long l)
{
	unsigned long long  i;

	fprintf(fp, "%s", s);

	for ( i=0; i<l; i++ )
		fprintf(fp, "%02X", a[i]);

	if ( l == 0 )
		fprintf(fp, "00");

	fprintf(fp, ";%d", b);
	fprintf(fp, "\n");
}

/* FUNCTIONS ADDED FOR OUR ATTACK */
/*************************************************
* Name:        poly_2gamma2
*
* Description: Multiply polynomial by 2*GAMMA2 without modular reduction. Assumes
*              input coefficients to be less than 2^{31-D} in absolute value.
*
* Arguments:   - poly *a: pointer to input/output polynomial
**************************************************/
void poly_2gamma2(poly *a) {
  unsigned int i;

  for(i = 0; i < N; ++i)
    a->coeffs[i] = (a->coeffs[i])*(2*GAMMA2);

}


/*************************************************
* Name:        polyveck_2gamma2
*
* Description: Multiply vector of polynomials of Length K by 2*GAMMA2 without modular
*              reduction. Assumes input coefficients to be less than 2^{31-D}.
*
* Arguments:   - polyveck *v: pointer to input/output vector
**************************************************/
void polyveck_2gamma2(polyveck *v) {
  unsigned int i;

  for(i = 0; i < K; ++i)
    poly_2gamma2(&v->vec[i]);
}





/*************************************************
* Name:        crypto_sign_collect_w0
*
* Description: Collects index corresponding to the first w0 = 0 value detected
*
* Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen: pointer to output length of signature
*              - uint8_t *m:     pointer to message to be signed
*              - size_t mlen:    length of message
*              - uint8_t *sk:    pointer to bit-packed secret key
*
* Returns:     i*N + j: such that w0[i][j] = 0
**************************************************/
int crypto_sign_collect_w0(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk)
{
  unsigned int n;
  uint8_t seedbuf[3*SEEDBYTES + 2*CRHBYTES];
  uint8_t *rho, *tr, *key, *mu, *rhoprime;
  uint16_t nonce = 0;
  polyvecl mat[K], s1, y, z;
  polyveck t0, s2, w1, w0, h, w0backup;
  poly cp;
  keccak_state state;

  /* This is where the w0 will be stored */
  for(int i = 0; i < K; i++){
    for(int j = 0; j < N; j++){
      w0backup.vec[i].coeffs[j] = 0;
    }
  }

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + SEEDBYTES;
  mu = key + SEEDBYTES;
  rhoprime = mu + CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute CRH(tr, msg) */
  shake256_init(&state);
  shake256_absorb(&state, tr, SEEDBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
  randombytes(rhoprime, CRHBYTES);
#else
  shake256(rhoprime, CRHBYTES, key, SEEDBYTES + CRHBYTES);
#endif

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);

  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);

rej:
  /* Sample intermediate vector y */
  polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

  /* Matrix-vector multiplication */
  z = y;
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Decompose w and call the random oracle */
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &w0, &w1);
  polyveck_pack_w1(sig, &w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, sig, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, SEEDBYTES, &state);
  poly_challenge(&cp, sig);
  poly_ntt(&cp);

  /* Compute z, reject if it reveals secret */
  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  polyvecl_invntt_tomont(&z);
  polyvecl_add(&z, &z, &y);
  polyvecl_reduce(&z);
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto rej;

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */

  /* We store the w0 before reusing it*/
  for(int i = 0; i < K; i++){
    for(int j = 0; j < N; j++){
      w0backup.vec[i].coeffs[j] = w0.vec[i].coeffs[j];
    }
  }

  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  polyveck_invntt_tomont(&h);
  polyveck_sub(&w0, &w0, &h);
  polyveck_reduce(&w0);
  if(polyveck_chknorm(&w0, GAMMA2 - BETA))
    goto rej;

  /* Compute hints for w1 */
  polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  polyveck_invntt_tomont(&h);
  polyveck_reduce(&h);
  if(polyveck_chknorm(&h, GAMMA2))
    goto rej;

  polyveck_add(&w0, &w0, &h);
  n = polyveck_make_hint(&h, &w0, &w1);
  if(n > OMEGA)
    goto rej;

  /* Write signature */
  pack_sig(sig, sig, &z, &h);
  *siglen = CRYPTO_BYTES;

  /* We verify if there is at least one 0 and return the indices accordingly */
  for(int i = 0; i < K; i++){
    for(int j = 0; j < N; j++){
      if (w0backup.vec[i].coeffs[j] == 0){
        return i*N+j;
      }
    }
  }
  // If there is no w0 = 0 we return -1
  return -1;
}


/*************************************************
* Name:        crypto_sign_filter
*
* Description: Practicall evaluation of the filter described in Section XX for fixed given sk/ pk.
*              Computes the percentage of real w0 = 0 detected as well as the êrcentage of values filteres overall.
*
* Arguments:   - uint8_t *sig:                      pointer to output signature (of length CRYPTO_BYTES)
*              - size_t *siglen:                    pointer to output length of signature
*              - uint8_t *m:                        pointer to message to be signed
*              - size_t mlen:                       length of message
*              - const uint8_t *pk:                 pointer to bit-packed public key
*              - const uint8_t *sk:                 pointer to bit-packed secret key
               - uint64_t *w0_to_0_detected_filter: number of w0 = 0 detected by the filter
               - uint64_t *w0_to_0_total:           total number of w0 = 0 
               - uint64_t *values_detected_filter:  number values filtered and potentially = 0
*
**************************************************/
void crypto_sign_filter(uint8_t *sig,
                          size_t *siglen,
                          const uint8_t *m,
                          size_t mlen,
                          const uint8_t *sk,
                          const uint8_t *pk,
                          uint64_t *w0_to_0_detected_filter,
                          uint64_t *w0_to_0_total,
                          uint64_t *values_detected_filter)
{
  unsigned int n;
  uint8_t      seedbuf[3*SEEDBYTES + 2*CRHBYTES];
  uint8_t      *rho, *tr, *key, *mu, *rhoprime;
  uint16_t     nonce = 0, sigma = 29537, cpt_filter_calues = 0;
  uint16_t     i, j;
  polyvecl     mat[K], s1, y, z;
  polyveck     t0, t1, s2, w1, w0, w02, h, val;
  poly         cp;
  keccak_state state;

  rho = seedbuf;
  tr = rho + SEEDBYTES;
  key = tr + SEEDBYTES;
  mu = key + SEEDBYTES;
  rhoprime = mu + CRHBYTES;
  unpack_sk(rho, tr, key, &t0, &s1, &s2, sk);

  /* Compute CRH(tr, msg) */
  shake256_init(&state);
  shake256_absorb(&state, tr, SEEDBYTES);
  shake256_absorb(&state, m, mlen);
  shake256_finalize(&state);
  shake256_squeeze(mu, CRHBYTES, &state);

#ifdef DILITHIUM_RANDOMIZED_SIGNING
  randombytes(rhoprime, CRHBYTES);
#else
  shake256(rhoprime, CRHBYTES, key, SEEDBYTES + CRHBYTES);
#endif

  /* Expand matrix and transform vectors */
  polyvec_matrix_expand(mat, rho);
  polyvecl_ntt(&s1);
  polyveck_ntt(&s2);
  polyveck_ntt(&t0);
  // printf("test 2 \n");
rej:
  /* Sample intermediate vector y */
  polyvecl_uniform_gamma1(&y, rhoprime, nonce++);

  /* Matrix-vector multiplication */
  z = y;
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&w1, mat, &z);
  polyveck_reduce(&w1);
  polyveck_invntt_tomont(&w1);

  /* Decompose w and call the random oracle */
  polyveck_caddq(&w1);
  polyveck_decompose(&w1, &w0, &w1);
  polyveck_pack_w1(sig, &w1);

  shake256_init(&state);
  shake256_absorb(&state, mu, CRHBYTES);
  shake256_absorb(&state, sig, K*POLYW1_PACKEDBYTES);
  shake256_finalize(&state);
  shake256_squeeze(sig, SEEDBYTES, &state);
  poly_challenge(&cp, sig);
  poly_ntt(&cp);

  /* Compute z, reject if it reveals secret */
  polyvecl_pointwise_poly_montgomery(&z, &cp, &s1);
  polyvecl_invntt_tomont(&z);
  polyvecl_add(&z, &z, &y);
  polyvecl_reduce(&z);
  if(polyvecl_chknorm(&z, GAMMA1 - BETA))
    goto rej;

  /* Check that subtracting cs2 does not change high bits of w and low bits
   * do not reveal secret information */
  polyveck_pointwise_poly_montgomery(&h, &cp, &s2);
  polyveck_invntt_tomont(&h);
  polyveck_sub(&w02, &w0, &h);
  polyveck_reduce(&w02);
  if(polyveck_chknorm(&w02, GAMMA2 - BETA))
    goto rej;

  /* Compute hints for w1 */
  polyveck_pointwise_poly_montgomery(&h, &cp, &t0);
  polyveck_invntt_tomont(&h);
  polyveck_reduce(&h);
  if(polyveck_chknorm(&h, GAMMA2))
    goto rej;

  polyveck_add(&w02, &w02, &h);
  n = polyveck_make_hint(&h, &w02, &w1);
  if(n > OMEGA)
    goto rej;

  /* Everything is ok, we have the valid signature */
  /* Unpack necessary information from the pk*/
  for(i = 0; i < K; ++i){
    polyt1_unpack(&(t1.vec[i]), pk + SEEDBYTES + i*POLYT1_PACKEDBYTES);
  }

  /* Matrix-vector multiplication; compute Az - c2^dt1 */
  polyvecl_ntt(&z);
  polyvec_matrix_pointwise_montgomery(&val, mat, &z);

  polyveck_shiftl(&t1);
  polyveck_ntt(&t1);
  polyveck_pointwise_poly_montgomery(&t1, &cp, &t1);

  polyveck_sub(&val, &val, &t1);
  polyveck_caddq(&val);
  polyveck_invntt_tomont(&val);

  // Compute 2gamma2 * w1
  polyveck_2gamma2(&w1);
  polyveck_reduce(&w1);

  // We have the value approximating w_0 i.e Az - ct12^d - w12gamma2
  polyveck_sub(&val, &val, &w1);

  //////////////////////////////////////////////////////////////////////
  //////////////////////////////////////////////////////////////////////
  for(i = 0; i < K; ++i){
    for(j = 0; j < N; ++j){

      if (w0.vec[i].coeffs[j] == 0){
        // printf("######### REAL W0 = 0 AND THE VALUE TESTED #########\n");
        // printf("    w0[%d][%d] = %d\n", i, j, w0.vec[i].coeffs[j]);
        // printf("    val[%d][%d] = %d\n", i, j, val.vec[i].coeffs[j]);
        (*w0_to_0_total)++;
      }
      if (abs(val.vec[i].coeffs[j]) < sigma ){
        if (w0.vec[i].coeffs[j] == 0){
          (*w0_to_0_detected_filter)++;
        }
        (*values_detected_filter)++;
      }
    }
  }

  // printf("total_w0 = %d\n",total_w0);
  // printf("w0_detected_by_filter = %d\n",w0_detected_by_filter);
}