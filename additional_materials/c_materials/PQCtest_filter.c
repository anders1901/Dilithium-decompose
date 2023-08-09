//
//  PQCgenKAT_sign.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "additional_fct.h"

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int	FindMarker(FILE *infile, const char *marker);
int	ReadHex(FILE *infile, unsigned char *a, int Length, char *str);
void	fprintBstr(FILE *fp, char *s, unsigned char *a, unsigned long long l);


int
main()
{
    char                fn_req[35], fn_rsp[34];
    FILE                *fp_req, *fp_rsp;
    uint8_t             seed[48];
    uint8_t             msg[3300];
    uint8_t             m[32];
    int8_t              sm[3300];
    uint8_t             entropy_input[48];
    // uint8_t             *m, *m1;
    size_t              mlen, smlen, mlen1;
    int                 count;
    int                 w0, cpt_indices;
    int                 done;
    uint8_t             pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;
    int                 cpt = 0;
    int                 NB = 1000000;
    int                 targeted_value = 0;
    uint8_t             hw_w0;
    int                 number = 0;
    long                i = 0;
    long long int       global_counter = 0;
    uint64_t            w0_to_0_detected_filter = 0, w0_to_0_total = 0, values_detected_filter = 0;
    long long int       total_w0_to_0_detected_filter = 0, total_w0_to_0_total = 0, total_values_detected_filter = 0;

    sprintf(fn_rsp, "%.16s_%d_msg_filter.rsp", CRYPTO_ALGNAME, NB);

    if ( (fp_rsp = fopen(fn_rsp, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }

    for (int i=0; i<48; i++)
        entropy_input[i] = 0;

    randombytes_init(entropy_input, NULL, 256);

    // Open the file with the pk/ sk to test the filter
    sprintf(fn_req, "PQCpksk_test_filter_%.16s.req", CRYPTO_ALGNAME);

    if ( (fp_req = fopen(fn_req, "r")) == NULL ) {
        printf("Couldn't open <%s> for read\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }

    done = 0;
    if ( !ReadHex(fp_req, pk, (int)CRYPTO_PUBLICKEYBYTES, "pk = ") ) {
        printf("ERROR: unable to read 'pk' from <%s>\n", fn_req);
        return KAT_DATA_ERROR;
    }

    if ( !ReadHex(fp_req, sk, (int)CRYPTO_SECRETKEYBYTES, "sk = ") ) {
        printf("ERROR: unable to read 'sk' from <%s>\n", fn_req);
        return KAT_DATA_ERROR;
    }

    do{
        randombytes(msg, 32);

        w0_to_0_detected_filter = 0;
        w0_to_0_total = 0;
        values_detected_filter = 0;
        crypto_sign_filter(sm, &smlen, msg, 32, sk, pk, &w0_to_0_detected_filter, &w0_to_0_total, &values_detected_filter);


        total_w0_to_0_total += w0_to_0_total;
        total_w0_to_0_detected_filter += w0_to_0_detected_filter;
        total_values_detected_filter += values_detected_filter;
        number++;
        i++;

        if (i%25000 == 0){
            // printf("%d/%d\r", i, NB);
            printf("%d/%ld\r", number, i);
            fflush(stdout);
        }

    } while ( number < NB );

    fclose(fp_req);
    fclose(fp_rsp);

    printf("percentage of w0 detected     = %f\n", (float)total_w0_to_0_detected_filter/ total_w0_to_0_total);
    printf("percentage of values filtered = %f\n", (float)total_values_detected_filter/ (NB*N*K));
    return KAT_SUCCESS;
}
