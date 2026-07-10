/*
 * Author: Maher Mamah.
 *
 * Part of the Dual-LESS modification: hidden-isodual key generation and
 * dual-augmented challenge space.
 */
/* Actual execution: generate one key pair, then sign 10 random messages of
 * length 80 bytes, verifying each and reporting the real signature size.
 * Prints public-key / secret-key sizes and the average signature size. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "rng.h"
#include "parameters.h"

#define MLEN  80
#define ITERS 10

int main(void) {
    unsigned char seed[48];
    for (uint32_t i = 0; i < sizeof(seed); i++) seed[i] = (unsigned char)(i*17 + 5);
    initialize_csprng(&platform_csprng_state, seed, sizeof(seed));

#ifdef DUAL_HIDDEN_C0
    const char *variant = "B (J secret, challenges {+1,-1,-0}, cheat 1/3)";
#else
    const char *variant = "A (J public, challenges {+1,-1}, cheat 1/2)";
#endif

    printf("=========================================================\n");
    printf(" Dual-LESS actual execution\n");
    printf(" params : N=%d K=%d Q=%d  T=%d W=%d  (stored keypairs s=%d)\n",
           N, K, Q, T, W, NUM_KEYPAIRS);
    printf(" variant: %s\n", variant);
    printf("=========================================================\n");
    printf(" public key size : %u bytes\n", (unsigned)CRYPTO_PUBLICKEYBYTES);
    printf(" secret key size : %u bytes\n", (unsigned)CRYPTO_SECRETKEYBYTES);
    printf(" message length  : %d bytes\n", MLEN);
    printf("---------------------------------------------------------\n");

    unsigned char *pk = malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char *sk = malloc(CRYPTO_SECRETKEYBYTES);
    unsigned char  m[MLEN];
    unsigned char *sm   = malloc(MLEN + CRYPTO_BYTES);
    unsigned char *mout = malloc(MLEN + CRYPTO_BYTES);

    if (crypto_sign_keypair(pk, sk) != 0) { printf("keygen FAILED\n"); return 1; }

    unsigned long long total = 0;
    for (int it = 0; it < ITERS; it++) {
        randombytes(m, MLEN);                         /* random 80-byte message */

        unsigned long long smlen = 0, mlen1 = 0;
        if (crypto_sign(sm, &smlen, m, MLEN, sk) != 0) { printf("sign FAILED\n"); return 1; }

        /* verify the freshly produced signature */
        int ok = crypto_sign_open(mout, &mlen1, sm, smlen, pk);
        if (ok != 0 || mlen1 != MLEN || memcmp(mout, m, MLEN) != 0) {
            printf("iter %2d: VERIFY FAILED\n", it); return 1;
        }

        const unsigned long long sig = smlen - MLEN;  /* signature bytes only */
        total += sig;
        printf(" iter %2d: signature = %llu bytes   [verify OK]\n", it, sig);
    }

    printf("---------------------------------------------------------\n");
    printf(" average signature size over %d signatures: %.1f bytes (%.3f KiB)\n",
           ITERS, (double)total/ITERS, ((double)total/ITERS)/1024.0);
    printf("=========================================================\n");

    free(pk); free(sk); free(sm); free(mout);
    return 0;
}
