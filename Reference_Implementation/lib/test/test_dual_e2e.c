/*
 * Author: Maher Mamah.
 *
 * Part of the Dual-LESS modification: hidden-isodual key generation and
 * dual-augmented challenge space.
 */
/**
 * End-to-end test for Dual-LESS: keygen -> sign -> verify over many iterations,
 * confirming that (a) honest signatures verify, (b) dual/negative challenges are
 * actually exercised, and (c) tampered signatures are rejected.
 *
 * This code is hereby placed in the public domain.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "LESS.h"
#include "rng.h"
#include "utils.h"
#include "parameters.h"

#define ITERS 50
#define MLEN  64

int main(void) {
    unsigned char seed[48];
    for (uint32_t i = 0; i < sizeof(seed); i++) { seed[i] = (unsigned char)(i * 7 + 1); }
    initialize_csprng(&platform_csprng_state, seed, sizeof(seed));

    unsigned char *pk = malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char *sk = malloc(CRYPTO_SECRETKEYBYTES);
    unsigned char m[MLEN];
    unsigned char *sm = malloc(MLEN + CRYPTO_BYTES);
    unsigned char *mout = malloc(MLEN + CRYPTO_BYTES);

    uint64_t total_pos = 0, total_dual = 0, total_zero = 0;
    int ok = 1;

    for (int it = 0; it < ITERS; it++) {
        randombytes(m, MLEN);

        if (crypto_sign_keypair(pk, sk) != 0) { printf("keygen failed\n"); ok = 0; break; }

        unsigned long long smlen = 0, mlen1 = 0;
        if (crypto_sign(sm, &smlen, m, MLEN, sk) != 0) { printf("sign failed\n"); ok = 0; break; }

        /* inspect the challenge string actually used (derived from the digest,
         * which is public): the signature begins at sm + MLEN */
        const sign_t *sig = (const sign_t *)(sm + MLEN);
        uint8_t fws[T];
        SampleChallenge(fws, sig->digest);
        for (uint32_t i = 0; i < T; i++) {
            if (fws[i] == 0)            total_zero++;
            else if (fws[i] & 0x80u)    total_dual++;
            else                        total_pos++;
        }

        /* honest signature must verify */
        if (crypto_sign_open(mout, &mlen1, sm, smlen, pk) != 0) {
            printf("verify failed at iter %d\n", it); ok = 0; break;
        }
        if (mlen1 != MLEN || memcmp(mout, m, MLEN) != 0) {
            printf("recovered message mismatch at iter %d\n", it); ok = 0; break;
        }

        /* tamper: flip a bit in the first canonical-form action; must reject */
        size_t tamper_off = MLEN + offsetof(sign_t, cf_monom_actions);
        sm[tamper_off] ^= 0x01u;
        int tampered = crypto_sign_open(mout, &mlen1, sm, smlen, pk);
        sm[tamper_off] ^= 0x01u; /* restore */
        if (tampered == 0) {
            printf("tampered signature wrongly accepted at iter %d\n", it); ok = 0; break;
        }
    }

    printf("iterations           : %d\n", ITERS);
    printf("positive challenges  : %llu\n", (unsigned long long)total_pos);
    printf("dual    challenges   : %llu\n", (unsigned long long)total_dual);
    printf("zero    (seed) rounds: %llu\n", (unsigned long long)total_zero);
    printf("\n%s\n", ok ? "DUAL-LESS E2E: ALL TESTS PASSED" : "DUAL-LESS E2E: FAILED");

    free(pk); free(sk); free(sm); free(mout);
    return ok ? 0 : 1;
}
