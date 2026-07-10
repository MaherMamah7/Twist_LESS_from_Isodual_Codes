/*
 * Author: Maher Mamah.
 *
 * Part of the Dual-LESS modification: hidden-isodual key generation and
 * dual-augmented challenge space.
 */
/* TRUE CPU-cycle measurement for keygen / sign / verify via the hardware
 * cycle counter (rdtscp on x86, kperf PMU on Apple Silicon).
 *
 * On Apple Silicon the PMU requires root -> run this binary with sudo.
 * If every reading is identical/zero, the PMU could not be programmed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "cycles.h"
#include "api.h"
#include "LESS.h"
#include "rng.h"
#include "parameters.h"

#ifndef RUNS
#define RUNS 16
#endif
#define MLEN 80

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return (x > y) - (x < y);
}

static void report(const char *label, uint64_t *s, int n) {
    qsort(s, n, sizeof(uint64_t), cmp_u64);
    long double sum = 0; for (int i = 0; i < n; i++) sum += s[i];
    printf("  %-7s median %12llu cyc | min %12llu | avg %14.0Lf\n",
           label, (unsigned long long)s[n/2], (unsigned long long)s[0], sum/n);
}

int main(void) {
    setup_cycle_counter();

    unsigned char seed[16] = "0123456789012345";
    initialize_csprng(&platform_csprng_state, seed, 16);

#ifdef DUAL_HIDDEN_C0
    const char *variant = "B (J secret)";
#else
    const char *variant = "A (J public)";
#endif
    printf("Dual-LESS TRUE cycles: N=%d K=%d T=%d W=%d  variant %s\n", N, K, T, W, variant);

    /* sanity: two reads should differ if the counter is live */
    uint64_t a = read_cycle_counter(), b = read_cycle_counter();
    if (a == 0 || a == b) {
        printf("\n  WARNING: cycle counter not live (read %llu then %llu).\n",
               (unsigned long long)a, (unsigned long long)b);
        printf("  On Apple Silicon run this with sudo.\n\n");
    }

    unsigned char *pk = malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char *sk = malloc(CRYPTO_SECRETKEYBYTES);
    unsigned char  m[MLEN];
    unsigned char *sm = malloc(MLEN + CRYPTO_BYTES);
    unsigned char *mo = malloc(MLEN + CRYPTO_BYTES);
    randombytes(m, MLEN);

    uint64_t kc[RUNS], sc[RUNS], vc[RUNS];
    unsigned long long smlen = 0, mlen1 = 0;

    for (int i = 0; i < RUNS; i++) {
        uint64_t c0 = read_cycle_counter();
        crypto_sign_keypair(pk, sk);
        kc[i] = read_cycle_counter() - c0;

        c0 = read_cycle_counter();
        crypto_sign(sm, &smlen, m, MLEN, sk);
        sc[i] = read_cycle_counter() - c0;

        c0 = read_cycle_counter();
        (void)crypto_sign_open(mo, &mlen1, sm, smlen, pk);
        vc[i] = read_cycle_counter() - c0;
    }

    printf("over %d runs:\n", RUNS);
    report("keygen", kc, RUNS);
    report("sign",   sc, RUNS);
    report("verify", vc, RUNS);

    free(pk); free(sk); free(sm); free(mo);
    return 0;
}
