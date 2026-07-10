/*
 * Author: Maher Mamah.
 *
 * Part of the Dual-LESS modification: hidden-isodual key generation and
 * dual-augmented challenge space.
 */
/* Isolated check: how many seeds does the (untouched) GGM seed tree publish for
 * a uniformly random weight-W challenge string? Depends ONLY on seedtree.c and
 * the tree constants -- independent of keygen/sign/SampleChallenge changes. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parameters.h"
#include "seedtree.h"
#include "rng.h"

#define ITERS 2000

int main(void) {
    unsigned char seed[48];
    for (uint32_t i = 0; i < sizeof(seed); i++) seed[i] = (unsigned char)(i*3+1);
    initialize_csprng(&platform_csprng_state, seed, sizeof(seed));

    static unsigned char tree[NUM_NODES_SEED_TREE*SEED_LENGTH_BYTES];
    static unsigned char storage[SEED_TREE_MAX_PUBLISHED_BYTES];
    memset(tree, 0, sizeof(tree));

    long total = 0; int mx = 0;
    for (int it = 0; it < ITERS; it++) {
        unsigned char idx[T];
        memset(idx, 0, sizeof(idx));
        /* set exactly W random positions to 1 (hidden leaves) */
        int placed = 0;
        while (placed < W) {
            unsigned char r[2];
            randombytes(r, 2);
            unsigned int p = ((r[0]<<8)|r[1]) % T;
            if (!idx[p]) { idx[p] = 1; placed++; }
        }
        int pub = (int)GGMPath(tree, idx, storage);
        total += pub;
        if (pub > mx) mx = pub;
    }
    printf("T=%d W=%d MAX_PUBLISHED_SEEDS=%d\n", T, W, MAX_PUBLISHED_SEEDS);
    printf("over %d random weight-W strings: avg published = %.2f, observed max = %d\n",
           ITERS, (double)total/ITERS, mx);
    return 0;
}
