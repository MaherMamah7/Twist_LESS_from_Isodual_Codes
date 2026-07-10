/*
 * Author: Maher Mamah.
 *
 * Part of the Dual-LESS modification: hidden-isodual key generation and
 * dual-augmented challenge space.
 */
/* Times keygen / sign / verify with a high-resolution monotonic clock and
 * reports time per operation plus an estimated cycle count.
 *
 * On Apple Silicon there is no reliable user-space core-cycle counter (the
 * kperf PMU needs root and a chip-specific layout), so we measure wall-clock
 * time and convert to cycles using an assumed clock frequency. Override the
 * frequency at compile time with -DCPU_GHZ=<value> (default: 3.2 GHz, the M1
 * performance-core max). The "min" column is the cleanest estimate.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#include "api.h"
#include "LESS.h"
#include "rng.h"
#include "parameters.h"

#ifndef RUNS
#define RUNS 11
#endif
#ifndef CPU_GHZ
#define CPU_GHZ 3.2          /* Apple M1 performance core max ~3.2 GHz */
#endif
#define MLEN 80

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return (x > y) - (x < y);
}

static void report(const char *label, uint64_t *ns, int n) {
    qsort(ns, n, sizeof(uint64_t), cmp_u64);
    long double sum = 0; for (int i = 0; i < n; i++) sum += ns[i];
    long double med = ns[n/2], mn = ns[0], avg = sum/n;
    /* cycles = nanoseconds * GHz */
    printf("  %-7s | time: median %8.3Lf ms  min %8.3Lf ms | est. cycles: median %12.0Lf  min %12.0Lf\n",
           label, med/1e6L, mn/1e6L,
           med*(long double)CPU_GHZ, mn*(long double)CPU_GHZ);
}

int main(void) {
    unsigned char seed[16] = "0123456789012345";
    initialize_csprng(&platform_csprng_state, seed, 16);

#ifdef DUAL_HIDDEN_C0
    const char *variant = "B (J secret)";
#else
    const char *variant = "A (J public)";
#endif
    printf("Dual-LESS timing: N=%d K=%d T=%d W=%d  variant %s\n", N, K, T, W, variant);
    printf("assumed clock: %.3f GHz (override with -DCPU_GHZ=...)\n", (double)CPU_GHZ);

    unsigned char *pk = malloc(CRYPTO_PUBLICKEYBYTES);
    unsigned char *sk = malloc(CRYPTO_SECRETKEYBYTES);
    unsigned char  m[MLEN];
    unsigned char *sm = malloc(MLEN + CRYPTO_BYTES);
    unsigned char *mo = malloc(MLEN + CRYPTO_BYTES);
    randombytes(m, MLEN);

    uint64_t kc[RUNS], sc[RUNS], vc[RUNS];
    unsigned long long smlen = 0, mlen1 = 0;

    for (int i = 0; i < RUNS; i++) {
        uint64_t t0 = now_ns();
        crypto_sign_keypair(pk, sk);
        kc[i] = now_ns() - t0;

        t0 = now_ns();
        crypto_sign(sm, &smlen, m, MLEN, sk);
        sc[i] = now_ns() - t0;

        t0 = now_ns();
        (void)crypto_sign_open(mo, &mlen1, sm, smlen, pk);
        vc[i] = now_ns() - t0;
    }

    printf("over %d runs:\n", RUNS);
    report("keygen", kc, RUNS);
    report("sign",   sc, RUNS);
    report("verify", vc, RUNS);

    free(pk); free(sk); free(sm); free(mo);
    return 0;
}
