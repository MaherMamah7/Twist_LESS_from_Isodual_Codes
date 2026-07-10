/*
 * Author: Maher Mamah.
 *
 * Part of the Dual-LESS modification: hidden-isodual key generation and
 * dual-augmented challenge space.
 */
/* Fast, exact average signature-size estimator.
 *
 * The signature size is  fixed + num_published_seeds * SEED_LENGTH_BYTES,
 * where fixed = 2*HASH_DIGEST_LENGTH + N8*W + 1 and num_published_seeds is
 * exactly what LESS_sign would obtain: GGMPath(!!SampleChallenge(digest)).
 * No keygen / RREF / canonical forms are needed, so this runs in milliseconds.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parameters.h"
#include "seedtree.h"
#include "utils.h"
#include "rng.h"

#ifndef ITERS
#define ITERS 100000
#endif

int main(void) {
    unsigned char seed[48];
    for (uint32_t i = 0; i < sizeof(seed); i++) seed[i] = (unsigned char)(i*13+7);
    initialize_csprng(&platform_csprng_state, seed, sizeof(seed));

    static unsigned char tree[NUM_NODES_SEED_TREE*SEED_LENGTH_BYTES];
    static unsigned char storage[SEED_TREE_MAX_PUBLISHED_BYTES];
    memset(tree, 0, sizeof(tree));

    const int fixed = 2*HASH_DIGEST_LENGTH + N8*W + 1;
    long total_pub = 0; int mn = 1<<30, mx = 0;
    for (int it = 0; it < ITERS; it++) {
        uint8_t digest[HASH_DIGEST_LENGTH];
        randombytes(digest, sizeof(digest));
        uint8_t fws[T];
        SampleChallenge(fws, digest);
        unsigned char idx[T];
        for (uint32_t i = 0; i < T; i++) idx[i] = !!fws[i];
        int pub = (int)GGMPath(tree, idx, storage);
        total_pub += pub;
        if (pub < mn) mn = pub;
        if (pub > mx) mx = pub;
    }
    double avg_pub = (double)total_pub/ITERS;
    double avg_sig = fixed + avg_pub*SEED_LENGTH_BYTES;
    printf("N=%d K=%d  T=%d W=%d  s=%d  SEED=%d\n", N, K, T, W, NUM_KEYPAIRS, SEED_LENGTH_BYTES);
    printf("public key            : %u B\n", (unsigned)LESS_CRYPTO_PUBLICKEYBYTES);
    printf("fixed part            : %d B (2*%d + %d*%d + 1)\n", fixed, HASH_DIGEST_LENGTH, N8, W);
    printf("published seeds        : avg %.2f  (min %d, max %d, MAX_PUB %d)\n", avg_pub, mn, mx, MAX_PUBLISHED_SEEDS);
    printf("AVG SIGNATURE SIZE    : %.1f B (%.3f KiB)   over %d samples\n",
           avg_sig, avg_sig/1024.0, ITERS);
    return 0;
}
