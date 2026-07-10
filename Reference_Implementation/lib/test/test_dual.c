/*
 * Author: Maher Mamah.
 *
 * Part of the Dual-LESS modification: hidden-isodual key generation and
 * dual-augmented challenge space.
 */
/**
 * Stage-1 correctness test for the Dual-LESS hidden-isodual key generation.
 *
 * Verifies, numerically and inside the repo's own primitives, that:
 *   (T1) D^perp = D * J_H            where D = <[I|A]>, A skew-symmetric
 *   (T2) C0^perp = C0 * J            where C0 = D R0, J = R0^{-1} J_H R0^{-T}
 *   (T3) every row of C0 is orthogonal to every row of (C0 J)  [independent
 *        check of (T2) not relying on generator_dual]
 *   (T4) monomial identities: R0 R0^{-1} = I, (M^T)^T = M
 *
 * Build (toy parameters, N=16 K=8 Q=127):
 *   gcc -Iinclude lib/test/test_dual.c lib/dual.c lib/codes.c lib/monomial.c \
 *       lib/rng.c lib/fips202.c lib/keccakf1600.c lib/utils.c -o /tmp/test_dual
 *
 * This code is hereby placed in the public domain.
 */

#include <stdio.h>
#include <string.h>

#include "codes.h"
#include "monomial_mat.h"
#include "dual.h"
#include "rng.h"
#include "fq_arith.h"

/* Reduce a copy of G to RREF and report success. */
static int rref_copy(generator_mat_t *out, const generator_mat_t *const G) {
    memcpy(out, G, sizeof(generator_mat_t));
    uint8_t piv[N_pad];
    memset(piv, 0, sizeof(piv));
    return generator_RREF(out, piv);
}

/* Returns 1 iff <G1> == <G2> (compares RREF representations). */
static int code_equal(const generator_mat_t *const G1,
                      const generator_mat_t *const G2) {
    generator_mat_t R1, R2;
    if (!rref_copy(&R1, G1) || !rref_copy(&R2, G2)) {
        return 0;
    }
    for (uint32_t r = 0; r < K; r++) {
        for (uint32_t c = 0; c < N; c++) {
            if (R1.values[r][c] != R2.values[r][c]) {
                return 0;
            }
        }
    }
    return 1;
}

/* Returns 1 iff every row of A is orthogonal to every row of B. */
static int rows_orthogonal(const generator_mat_t *const A,
                          const generator_mat_t *const B) {
    for (uint32_t a = 0; a < K; a++) {
        for (uint32_t b = 0; b < K; b++) {
            FQ_ELEM acc = 0;
            for (uint32_t c = 0; c < N; c++) {
                acc = fq_add(acc, fq_mul(A->values[a][c], B->values[b][c]));
            }
            if (acc != 0) { return 0; }
        }
    }
    return 1;
}

static int monomial_is_identity(const monomial_t *const M) {
    for (uint32_t i = 0; i < N; i++) {
        if (M->permutation[i] != i) { return 0; }
        if (M->coefficients[i] != 1) { return 0; }
    }
    return 1;
}

static int monomial_equal(const monomial_t *const A, const monomial_t *const B) {
    for (uint32_t i = 0; i < N; i++) {
        if (A->permutation[i] != B->permutation[i]) { return 0; }
        if (A->coefficients[i] != B->coefficients[i]) { return 0; }
    }
    return 1;
}

int main(void) {
    int all_ok = 1;

    /* deterministic state for A; separate seed for R0 */
    unsigned char seed[PRIVATE_KEY_SEED_LENGTH_BYTES];
    for (uint32_t i = 0; i < sizeof(seed); i++) { seed[i] = (unsigned char) (0xA5 ^ i); }
    SHAKE_STATE_STRUCT state;
    initialize_csprng(&state, seed, PRIVATE_KEY_SEED_LENGTH_BYTES);

    /* ---- build G_D = [I | A], A skew-symmetric ---- */
    generator_mat_t GD;
    dual_sample_GD(&GD, &state);

    /* sanity: A skew-symmetric and zero diagonal */
    int skew_ok = 1;
    for (uint32_t i = 0; i < K; i++) {
        if (GD.values[i][K + i] != 0) { skew_ok = 0; }
        for (uint32_t j = 0; j < K; j++) {
            FQ_ELEM aij = GD.values[i][K + j];
            FQ_ELEM aji = GD.values[j][K + i];
            if (aij != fq_sub((FQ_ELEM) 0, aji)) { skew_ok = 0; }
        }
    }
    printf("[%s] A is skew-symmetric with zero diagonal\n", skew_ok ? "PASS" : "FAIL");
    all_ok &= skew_ok;

    /* ---- T1: D^perp == D * J_H ---- */
    monomial_t JH;
    dual_build_JH(&JH);

    generator_mat_t D_perp, D_JH;
    int dual_ok = generator_dual(&D_perp, &GD);
    generator_monomial_mul(&D_JH, &GD, &JH);

    int t1 = dual_ok && code_equal(&D_perp, &D_JH);
    printf("[%s] T1: D^perp == D * J_H\n", t1 ? "PASS" : "FAIL");
    all_ok &= t1;

    /* ---- sample secret monomial R0, build C0 = D R0 ---- */
    monomial_t R0;
    monomial_sample_prikey(&R0, seed);

    generator_mat_t C0;
    generator_monomial_mul(&C0, &GD, &R0);

    /* ---- T4: monomial identities ---- */
    monomial_t R0_inv, prod, R0_T, R0_TT;
    monomial_inv(&R0_inv, &R0);
    monomial_mat_mul(&prod, &R0, &R0_inv);
    int t4a = monomial_is_identity(&prod);
    monomial_transpose(&R0_T, &R0);
    monomial_transpose(&R0_TT, &R0_T);
    int t4b = monomial_equal(&R0, &R0_TT);
    printf("[%s] T4: R0 * R0^{-1} = I  and  (R0^T)^T = R0\n",
           (t4a && t4b) ? "PASS" : "FAIL");
    all_ok &= (t4a && t4b);

    /* ---- compute J and C0 * J ---- */
    monomial_t J;
    dual_compute_J(&J, &R0);

    generator_mat_t C0J;
    generator_monomial_mul(&C0J, &C0, &J);

    /* ---- T2: C0^perp == C0 * J ---- */
    generator_mat_t C0_perp;
    int c0dual_ok = generator_dual(&C0_perp, &C0);
    int t2 = c0dual_ok && code_equal(&C0_perp, &C0J);
    printf("[%s] T2: C0^perp == C0 * J\n", t2 ? "PASS" : "FAIL");
    all_ok &= t2;

    /* ---- T3: rows of C0 orthogonal to rows of C0 J ---- */
    int t3 = rows_orthogonal(&C0, &C0J);
    printf("[%s] T3: <C0 row, (C0 J) row> = 0 for all rows\n", t3 ? "PASS" : "FAIL");
    all_ok &= t3;

    printf("\n%s\n", all_ok ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    return all_ok ? 0 : 1;
}
