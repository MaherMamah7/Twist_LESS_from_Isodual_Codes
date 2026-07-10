/*
 * Author: Maher Mamah.
 *
 * Part of the Dual-LESS modification: hidden-isodual key generation and
 * dual-augmented challenge space.
 */
/* Reconstruction of the ORIGINAL (stock) SampleChallenge for TARGET 192
 * (NUM_KEYPAIRS==2 path), run through GGMPath to count published seeds.
 * Compares against a uniform weight-W reference. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parameters.h"
#include "seedtree.h"
#include "rng.h"

#define POSITION_MASK (((uint16_t)1 << BITS_TO_REPRESENT(T-1))-1)

/* verbatim original stock SampleChallenge (NUM_KEYPAIRS==2 branch) */
static void SampleChallengeOrig(uint8_t fws[T], const uint8_t digest[HASH_DIGEST_LENGTH]) {
    SHAKE_STATE_STRUCT shake_state;
    initialize_csprng(&shake_state, digest, HASH_DIGEST_LENGTH);
    uint64_t rnd_buf; uint32_t c = 0;
    for (uint32_t i = 0; i < T-W; i++) fws[i] = 0;
    for (uint32_t i = T-W; i < T; i++) fws[i] = 1;   /* NUM_KEYPAIRS==2 */
    for (uint32_t p = T-W; p < T; p++) {
        POSITION_T pos;
        do {
            if (c == 0) { csprng_randombytes((unsigned char*)&rnd_buf, 8, &shake_state); c = 64u/BITS_TO_REPRESENT(T-1); }
            pos = rnd_buf & POSITION_MASK;
            rnd_buf >>= BITS_TO_REPRESENT(T-1);
            c -= 1;
        } while (pos > p);
        uint8_t tmp = fws[p]; fws[p] = fws[pos]; fws[pos] = tmp;
    }
}

#define ITERS 2000
int main(void) {
    unsigned char seed[48];
    for (uint32_t i = 0; i < sizeof(seed); i++) seed[i] = (unsigned char)(i*9+4);
    initialize_csprng(&platform_csprng_state, seed, sizeof(seed));
    static unsigned char tree[NUM_NODES_SEED_TREE*SEED_LENGTH_BYTES];
    static unsigned char storage[SEED_TREE_MAX_PUBLISHED_BYTES];
    memset(tree, 0, sizeof(tree));

    long total = 0, total_wt = 0;
    for (int it = 0; it < ITERS; it++) {
        uint8_t digest[HASH_DIGEST_LENGTH];
        randombytes(digest, sizeof(digest));
        uint8_t fws[T];
        SampleChallengeOrig(fws, digest);
        unsigned char idx[T]; int wt = 0;
        for (uint32_t i = 0; i < T; i++) { idx[i] = !!fws[i]; wt += idx[i]; }
        total_wt += wt;
        total += (int)GGMPath(tree, idx, storage);
    }
    printf("ORIGINAL SampleChallenge: avg weight=%.2f  avg published=%.2f\n",
           (double)total_wt/ITERS, (double)total/ITERS);
    return 0;
}
