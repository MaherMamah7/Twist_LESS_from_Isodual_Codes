/*
 * Author: Maher Mamah.
 *
 * Part of the Dual-LESS modification: hidden-isodual key generation and
 * dual-augmented challenge space.
 */
/**
 * Dual-LESS additions: hidden-isodual key-generation primitives.
 *
 * This code is hereby placed in the public domain.
 */

#include <string.h>

#include "dual.h"
#include "fq_arith.h"

#if (N != 2 * K)
#error "Dual-LESS requires N = 2K"
#endif

/* Builds the block-swap monomial J_H = [[0, I_k],[I_k, 0]] (all coeffs = 1). */
void dual_build_JH(monomial_t *JH) {
    for (uint32_t i = 0; i < N; i++) {
        JH->coefficients[i] = 1;
    }
    for (uint32_t i = 0; i < K; i++) {
        JH->permutation[i]     = i + K; /* top block -> bottom */
        JH->permutation[i + K] = i;     /* bottom block -> top */
    }
} /* end dual_build_JH */

/* Samples a skew-symmetric A (A^T = -A, zero diagonal, K x K) and writes the
 * systematic generator G_D = [I_K | A]. */
void dual_sample_GD(generator_mat_t *GD, SHAKE_STATE_STRUCT *state) {
    /* zero the whole (padded) matrix */
    for (uint32_t r = 0; r < K; r++) {
        for (uint32_t c = 0; c < N_pad; c++) {
            GD->values[r][c] = 0;
        }
    }

    /* identity block on the first K columns */
    for (uint32_t i = 0; i < K; i++) {
        GD->values[i][i] = 1;
    }

    /* sample the strict upper triangle of A in one batch, then mirror with
     * negation; the diagonal stays 0 (forced since char(F_q) is odd) */
    FQ_ELEM tri[(K * (K - 1)) / 2];
    rand_range_q_state_elements(state, tri, (K * (K - 1)) / 2);

    uint32_t idx = 0;
    for (uint32_t i = 0; i < K; i++) {
        for (uint32_t j = i + 1; j < K; j++) {
            const FQ_ELEM a = tri[idx++];
            GD->values[i][K + j] = a;
            GD->values[j][K + i] = fq_sub((FQ_ELEM) 0, a);
        }
    }
} /* end dual_sample_GD */

/* Computes J = R0^{-1} J_H R0^{-T}. */
void dual_compute_J(monomial_t *J, const monomial_t *const R0) {
    monomial_t R0_inv, R0_inv_T, JH, tmp;

    monomial_inv(&R0_inv, R0);          /* R0^{-1}  */
    monomial_transpose(&R0_inv_T, &R0_inv); /* R0^{-T}  */
    dual_build_JH(&JH);

    monomial_mat_mul(&tmp, &R0_inv, &JH);   /* R0^{-1} J_H        */
    monomial_mat_mul(J, &tmp, &R0_inv_T);   /* R0^{-1} J_H R0^{-T} */
} /* end dual_compute_J */
