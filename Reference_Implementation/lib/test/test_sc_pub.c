/*
 * Author: Maher Mamah.
 *
 * Part of the Dual-LESS modification: hidden-isodual key generation and
 * dual-augmented challenge space.
 */
/* Feed SampleChallenge output into GGMPath and count published seeds + verify
 * the weight (number of nonzero challenges) is exactly W. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parameters.h"
#include "seedtree.h"
#include "utils.h"
#include "rng.h"

#define ITERS 2000

int main(void) {
    unsigned char seed[48];
    for (uint32_t i = 0; i < sizeof(seed); i++) seed[i] = (unsigned char)(i*9+4);
    initialize_csprng(&platform_csprng_state, seed, sizeof(seed));

    static unsigned char tree[NUM_NODES_SEED_TREE*SEED_LENGTH_BYTES];
    static unsigned char storage[SEED_TREE_MAX_PUBLISHED_BYTES];
    memset(tree, 0, sizeof(tree));

    long total_pub = 0, total_wt = 0;
    for (int it = 0; it < ITERS; it++) {
        uint8_t digest[HASH_DIGEST_LENGTH];
        randombytes(digest, sizeof(digest));
        uint8_t fws[T];
        SampleChallenge(fws, digest);

        unsigned char idx[T];
        int wt = 0;
        for (uint32_t i = 0; i < T; i++) { idx[i] = !!fws[i]; wt += idx[i]; }
        total_wt += wt;
        total_pub += (int)GGMPath(tree, idx, storage);
    }
    printf("T=%d W=%d\n", T, W);
    printf("avg weight (nonzero challenges) = %.2f  (should be %d)\n", (double)total_wt/ITERS, W);
    printf("avg published seeds via SampleChallenge = %.2f\n", (double)total_pub/ITERS);
    return 0;
}
