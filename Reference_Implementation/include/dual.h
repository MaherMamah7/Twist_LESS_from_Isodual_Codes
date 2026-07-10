/*
 * Author: Maher Mamah.
 *
 * Part of the Dual-LESS modification: hidden-isodual key generation and
 * dual-augmented challenge space.
 */
/**
 * Dual-LESS additions: hidden-isodual key-generation primitives.
 *
 * Implements the building blocks for the dual-augmented LESS variant:
 *   - the block-swap monomial J_H = [[0, I_k], [I_k, 0]]
 *   - sampling a skew-symmetric A and the systematic generator G_D = [I_k | A]
 *   - the secret monomial J = R0^{-1} J_H R0^{-T}, for which C0^perp = C0 J.
 *
 * Requires N = 2K and odd Q (both hold for all LESS parameter sets).
 *
 * This code is hereby placed in the public domain.
 */

#pragma once

#include "codes.h"
#include "monomial_mat.h"
#include "rng.h"

/* Builds the block-swap monomial J_H = [[0, I_k],[I_k, 0]] (all coeffs = 1). */
void dual_build_JH(monomial_t *JH);

/* Samples a skew-symmetric matrix A in F_q^{KxK} (A^T = -A, zero diagonal) and
 * writes the systematic generator G_D = [I_K | A] (K x N) using the supplied
 * CSPRNG state. */
void dual_sample_GD(generator_mat_t *GD, SHAKE_STATE_STRUCT *state);

/* Computes the secret monomial J = R0^{-1} J_H R0^{-T}.
 * With C0 = D R0 (D = <[I|A]> isodual), this J satisfies C0^perp = C0 J. */
void dual_compute_J(monomial_t *J, const monomial_t *const R0);
