/*
 * Author: Maher Mamah.
 *
 * Part of the Dual-LESS modification: hidden-isodual key generation and
 * dual-augmented challenge space.
 */
/**
 * Measures the average Dual-LESS signature size over 10 iterations.
 * The actual signature size varies per signature because the number of GGM
 * seed-tree nodes published depends on the (pseudorandom) challenge string.
 *
 * This code is hereby placed in the public domain.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "rng.h"

#define ITERS 10
#define MLEN  64

int main(void) {
    unsigned char seed[48];
    for (uint32_t i = 0; i < sizeof(seed); i++) { seed[i] = (unsigned char)(i * 11 + 3); }
    initialize_csprng(&platform_csprng_state, seed, sizeof(seed));

    unsigned char *pk = malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char *sk = malloc(CRYPTO_SECRETKEYBYTES);
    unsigned char m[MLEN];
    unsigned char *sm = malloc(MLEN + CRYPTO_BYTES);

    printf("params: N=%d K=%d Q=%d  NUM_KEYPAIRS=%d  T=%d W=%d\n",
           N, K, Q, NUM_KEYPAIRS, T, W);
    printf("public key : %u B\n", (unsigned)CRYPTO_PUBLICKEYBYTES);
    printf("secret key : %u B\n", (unsigned)CRYPTO_SECRETKEYBYTES);
    printf("worst-case sig (CRYPTO_BYTES): %u B\n\n", (unsigned)CRYPTO_BYTES);

    unsigned long long total = 0;
    for (int it = 0; it < ITERS; it++) {
        randombytes(m, MLEN);
        if (crypto_sign_keypair(pk, sk) != 0) { printf("keygen failed\n"); return 1; }

        unsigned long long smlen = 0;
        if (crypto_sign(sm, &smlen, m, MLEN, sk) != 0) { printf("sign failed\n"); return 1; }

        const unsigned long long sig_size = smlen - MLEN; /* exclude the message */
        printf("iter %2d: signature = %llu B\n", it, sig_size);
        total += sig_size;
    }

    printf("\naverage signature size over %d iterations: %.1f B (%.3f KiB)\n",
           ITERS, (double)total / ITERS, ((double)total / ITERS) / 1024.0);
    free(pk); free(sk); free(sm);
    return 0;
}
