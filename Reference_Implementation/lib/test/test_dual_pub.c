/*
 * Author: Maher Mamah.
 *
 * Part of the Dual-LESS modification: hidden-isodual key generation and
 * dual-augmented challenge space.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "rng.h"
#include "parameters.h"

#define ITERS 20
#define MLEN 64

int main(void) {
    unsigned char seed[48];
    for (uint32_t i = 0; i < sizeof(seed); i++) seed[i] = (unsigned char)(i*5+2);
    initialize_csprng(&platform_csprng_state, seed, sizeof(seed));

    unsigned char *pk = malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char *sk = malloc(CRYPTO_SECRETKEYBYTES);
    unsigned char m[MLEN];
    unsigned char *sm = malloc(MLEN + CRYPTO_BYTES);

    int fixed = 2*HASH_DIGEST_LENGTH + N8*W + 1;
    printf("T=%d W=%d N8=%d HASH=%d  MAX_PUB=%d\n", T, W, N8, HASH_DIGEST_LENGTH, MAX_PUBLISHED_SEEDS);
    printf("fixed part = 2*%d + %d*%d + 1 = %d B\n", HASH_DIGEST_LENGTH, N8, W, fixed);

    long total_pub = 0, total_sig = 0;
    for (int it = 0; it < ITERS; it++) {
        randombytes(m, MLEN);
        crypto_sign_keypair(pk, sk);
        unsigned long long smlen = 0;
        crypto_sign(sm, &smlen, m, MLEN, sk);
        int pub = sm[smlen-1];
        long sig = (long)smlen - MLEN;
        total_pub += pub; total_sig += sig;
        printf("iter %2d: published=%2d  sig=%ld B\n", it, pub, sig);
    }
    printf("\navg published seeds = %.1f\n", (double)total_pub/ITERS);
    printf("avg signature       = %.1f B\n", (double)total_sig/ITERS);
    free(pk); free(sk); free(sm);
    return 0;
}
