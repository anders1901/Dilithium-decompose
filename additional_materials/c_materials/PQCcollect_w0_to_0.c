//
//  PQCcollect_w0_to_0.c
//
//
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "rng.h"
#include "sign.h"
#include "additional_fct.h"

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int	    FindMarker(FILE *infile, const char *marker);
int	    ReadHex(FILE *infile, unsigned char *a, int Length, char *str);
void	fprintBstr2(FILE *fp, int b, char *s, unsigned char *a, unsigned long long l);


int
main()
{
    char                fn_req[37], fn_rsp[39];
    FILE                *fp_req, *fp_rsp;
    uint8_t             msg[3300];
    uint8_t             entropy_input[48];
    uint8_t             m[32];
    int8_t              sm[3300];
    size_t              mlen, smlen;
    int                 count;
    int                 done;
    uint8_t             sk[CRYPTO_SECRETKEYBYTES];
    int                 ret_val;
    int                 i, j;
    uint8_t             counts[K*N];
    long                iter = 0;
    int                 number = 0;
    int                 w0_to_0_index;
    // Initializing the counter allowing to determine if we have all the index
    for (i = 0; i < K*N; i++){
        counts[i] = 0;
    }
    
    sprintf(fn_rsp, "%.16s_sign_with_index_w0_to_0.rsp", CRYPTO_ALGNAME);

    if ( (fp_rsp = fopen(fn_rsp, "w")) == NULL ) {
        printf("Couldn't open <%s> for write\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }

    for (i = 0; i < 48; i++)
        entropy_input[i] = 1;

    randombytes_init(entropy_input, NULL, 256);

    // open the file with the  sk
    sprintf(fn_req, "PQCsk_collect_w0_to_0_%.16s.req", CRYPTO_ALGNAME);

    //Create the RESPONSE file based on what's in the REQUEST file
    if ( (fp_req = fopen(fn_req, "r")) == NULL ) {
        printf("Couldn't open <%s> for read\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }

    done = 0;
    if ( !ReadHex(fp_req, sk, (int)CRYPTO_SECRETKEYBYTES, "sk = ") ) {
        printf("ERROR: unable to read 'sk' from <%s>\n", fn_req);
        return KAT_DATA_ERROR;
    }

    
    do{
        randombytes(msg, 32);

        w0_to_0_index = crypto_sign_collect_w0(sm, &smlen, msg, 32, sk); 

        if (w0_to_0_index >=0){
            fprintBstr2(fp_rsp, w0_to_0_index, "", sm, smlen);

            if (counts[w0_to_0_index] == 0){
                counts[w0_to_0_index] = 1;
                number++;
            }
        }
        iter++;

        if (iter%50000 == 0){
            // printf("%d/%d\r", i, NB);
            printf("%d/%ld\r", number, iter);
            fflush(stdout);
        }
    } while ( number < N*K );

    fclose(fp_req);
    fclose(fp_rsp);
	printf("\n>>> END: %d/%ld\n", number, iter);
    return KAT_SUCCESS;
}
