/**
 *
 * Reference ISO-C11 Implementation of LESS.
 *
 * @version 1.2 (February 2025)
 *
 * Dual-LESS modification (hidden-isodual key generation + dual-augmented
 * challenge space). Design choice implemented here: J is PUBLIC and the dual of
 * keypair 0 (C_{-0}) is NOT part of the challenge set. Negative (dual)
 * challenges therefore range over keypairs 1..NUM_KEYPAIRS-1 only.

 * Author of the Dual-Less modification: Maher Mamah

 * Original Authors:
 * @author Alessandro Barenghi <alessandro.barenghi@polimi.it>
 * @author Gerardo Pelosi <gerardo.pelosi@polimi.it>
 * @author Floyd Zweydinger <zweydfg8+github@rub.de>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **/
#include <string.h> // memcpy, memset
#include "LESS.h"
#include "canonical.h"
#include "seedtree.h"
#include "rng.h"
#include "utils.h"
#include "fips202.h"
#include "sha3.h"
#include "dual.h"
#include "monomial_mat.h"
#include "codes.h"

/* A challenge value in the fixed-weight string is one byte:
 *   0                       -> unchallenged round (ephemeral seed is revealed)
 *   v in [1, NUM_KEYPAIRS)  -> positive challenge on keypair v   (use C_v)
 *   0x80 | v                -> dual/negative challenge on keypair v (use C_v^perp)
 */
#define CHALLENGE_DUAL_FLAG   (0x80u)
#define CHALLENGE_IS_DUAL(c)  (((c) & CHALLENGE_DUAL_FLAG) != 0)
#define CHALLENGE_MAGNITUDE(c) ((c) & (uint8_t)0x7Fu)

/* index of keypair v in PK->SF_G: variant B stores C_0 at [0] so C_v is at [v];
 * the default variant stores only C_1.. so C_v is at [v-1]. */
#ifdef DUAL_HIDDEN_C0
#define SFG_INDEX(v) (v)
#else
#define SFG_INDEX(v) ((v) - 1u)
#endif

/* Length (in bytes) of the seed that derives the hidden-isodual base code C_0
 * (it deterministically produces both the skew matrix A and the monomial R0).
 * Since J is public, this seed is public and lives in the public key. */
#define DUAL_SEED_R0_LEN  (PRIVATE_KEY_SEED_LENGTH_BYTES)

/// Expands the hidden-isodual public code C_0 from its single (public) seed.
/// Builds G_D = [I | A] and the hiding monomial R0 from the seed, forms the
/// generator G_D R0 of C_0 and reduces it to RREF.
/// \param G0_full[out]: RREF generator matrix of C_0
/// \param R0_out[out]:  the sampled hiding monomial R0 (may be NULL)
/// \param C0_seed[in]:  the (public) seed for A and R0
static void dual_expand_C0(generator_mat_t *G0_full,
                           monomial_t *R0_out,
                           uint8_t *pivot_flags_out,
                           int reduce,
                           const unsigned char C0_seed[SEED_LENGTH_BYTES]) {
    SHAKE_STATE_STRUCT state;
    initialize_csprng(&state, C0_seed, SEED_LENGTH_BYTES);

    /* sample A (consumes from the state) then derive R0's seed from the same
     * stream; keygen, sign and verify all call this helper identically. */
    generator_mat_t GD;
    dual_sample_GD(&GD, &state);

    unsigned char seed_R0[DUAL_SEED_R0_LEN];
    csprng_randombytes(seed_R0, DUAL_SEED_R0_LEN, &state);

    monomial_t R0;
    monomial_sample_prikey(&R0, seed_R0);

    generator_monomial_mul(G0_full, &GD, &R0);

    /* The RREF of C_0 is only needed when C_0 itself must be stored/used in
     * reduced form (sign commitments, verify, and storing C_0 in variant B).
     * For variant-A keygen the keypairs are RREF(C_0 * Q) regardless of C_0's
     * basis, so the reduction here would be pure waste -> skip it. */
    if (reduce) {
        uint8_t is_pivot_column[N_pad];
        memset(is_pivot_column, 0, sizeof(is_pivot_column));
        generator_RREF(G0_full, is_pivot_column);
        if (pivot_flags_out != NULL) { memcpy(pivot_flags_out, is_pivot_column, N_pad); }
    }

    if (R0_out != NULL) { *R0_out = R0; }
}

void LESS_keygen(prikey_t *SK,
                 pubkey_t *PK) {
    /* generating private key from a single seed */
    randombytes(SK->compressed_sk, PRIVATE_KEY_SEED_LENGTH_BYTES);

    /* expanding it onto private seeds */
    SHAKE_STATE_STRUCT sk_shake_state;
    initialize_csprng(&sk_shake_state, SK->compressed_sk, PRIVATE_KEY_SEED_LENGTH_BYTES);

    /* seed for the hidden-isodual base code C_0 = <SF(G_D R0)>, derived from
     * the secret key. In the default variant it is published (J is public); in
     * the DUAL_HIDDEN_C0 variant it stays internal and C_0 is stored as a
     * matrix instead (so R0 / J remain secret). */
    unsigned char c0_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(c0_seed, SEED_LENGTH_BYTES, &sk_shake_state);

    /* private monomials for keypairs 1..NUM_KEYPAIRS-1 */
    unsigned char private_monomial_seeds[NUM_KEYPAIRS - 1][PRIVATE_KEY_SEED_LENGTH_BYTES];
    for (uint32_t i = 0; i < NUM_KEYPAIRS - 1; i++) {
        csprng_randombytes(private_monomial_seeds[i],
                           PRIVATE_KEY_SEED_LENGTH_BYTES,
                           &sk_shake_state);
    }

    /* Build the hidden-isodual base code C_0 */
    generator_mat_t full_G0;
#ifdef DUAL_HIDDEN_C0
    /* C_0 is stored, so we need it reduced; capture its pivots for compress */
    uint8_t c0_pivot_flags[N_pad];
    dual_expand_C0(&full_G0, NULL, c0_pivot_flags, 1, c0_seed);
    compress_rref(PK->SF_G[0], &full_G0, c0_pivot_flags);
    const uint32_t sfg_base = 1;
#else
    /* C_0 is the public seed and is NOT stored as a matrix; publish the seed.
     * The keypairs are RREF(C_0*Q) regardless of C_0's basis, so skip reducing
     * C_0 here (saves one RREF). */
    memcpy(PK->C0_seed, c0_seed, SEED_LENGTH_BYTES);
    dual_expand_C0(&full_G0, NULL, NULL, 0, c0_seed);
    const uint32_t sfg_base = 0;
#endif

    /* Build and store keypairs 1..NUM_KEYPAIRS-1: C_v = C_0 Q_v */
    for (uint32_t i = 0; i < NUM_KEYPAIRS - 1; i++) {
        uint8_t is_pivot_column[N_pad] = {0};
        /* expand inverse monomial from seed, then invert to get Q_v */
        monomial_t private_Q;
        monomial_t private_Q_inv;
        monomial_sample_prikey(&private_Q_inv, private_monomial_seeds[i]);
        monomial_inv(&private_Q, &private_Q_inv);

        generator_mat_t result_G = {0};
        generator_monomial_mul(&result_G, &full_G0, &private_Q);
        memset(is_pivot_column, 0, sizeof(is_pivot_column));
        generator_RREF(&result_G, is_pivot_column);
        compress_rref(PK->SF_G[sfg_base + i], &result_G, is_pivot_column);
    }
} /* end LESS_keygen */

/// returns the number of opened seeds in the tree.
/// \param SK[in]: secret key
/// \param m[in]: message to sign
/// \param mlen[in]: length of the message to sign in bytes
/// \param sig[out]: signature
/// \return: x: number of leaves opened by the algorithm
size_t LESS_sign(const prikey_t *SK,
                 const char *const m,
                 const uint64_t mlen,
                 sign_t *sig) {
    uint8_t is_pivot_column[N_pad];

    /*         Private key expansion        */
    SHAKE_STATE_STRUCT sk_shake_state;
    initialize_csprng(&sk_shake_state, SK->compressed_sk, PRIVATE_KEY_SEED_LENGTH_BYTES);

    /* public seed for the hidden-isodual base code C_0 (same derivation as in
     * keygen, so it matches the seed stored in the public key) */
    unsigned char C0_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(C0_seed, SEED_LENGTH_BYTES, &sk_shake_state);

    /* private monomials for keypairs 1..NUM_KEYPAIRS-1 */
    unsigned char private_monomial_seeds[NUM_KEYPAIRS - 1][PRIVATE_KEY_SEED_LENGTH_BYTES];
    for (uint32_t i = 0; i < NUM_KEYPAIRS - 1; i++) {
        csprng_randombytes(private_monomial_seeds[i],
                           PRIVATE_KEY_SEED_LENGTH_BYTES,
                           &sk_shake_state);
    }

    // generate the salt from a TRNG
    randombytes(sig->salt, HASH_DIGEST_LENGTH);

    /*         Ephemeral monomial generation        */
    unsigned char ephem_monomials_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(ephem_monomials_seed,
                       SEED_LENGTH_BYTES,
                       &sk_shake_state);

    /* create the prng for the "blinding" monomials for the canonical form computation */
    uint8_t cf_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(cf_seed,
                       SEED_LENGTH_BYTES,
                       &sk_shake_state);
    SHAKE_STATE_STRUCT cf_shake_state;
    initialize_csprng(&cf_shake_state, cf_seed, SEED_LENGTH_BYTES);

    unsigned char seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES] = {0};
    BuildGGM(seed_tree, ephem_monomials_seed, sig->salt);

    unsigned char linearized_rounds_seeds[T*SEED_LENGTH_BYTES] = {0};
    seed_leaves(linearized_rounds_seeds,seed_tree);

    /*         Public C_0 expansion + secret J for the dual responses  */
    generator_mat_t full_G0;
    monomial_t R0;
    uint8_t g0_initial_pivot_flags[N_pad] = {0};
    dual_expand_C0(&full_G0, &R0, g0_initial_pivot_flags, 1, C0_seed);

    /* J = R0^{-1} J_H R0^{-T} ; needed (as J^{-1}) for dual challenges */
    monomial_t J, J_inv;
    dual_compute_J(&J, &R0);
    monomial_inv(&J_inv, &J);

    monomial_t mu_tilde;
    monomial_action_IS_t pi_tilde[T];
    normalized_IS_t A_i = {0};
    generator_mat_t G0;

    LESS_SHA3_INC_CTX state;
    LESS_SHA3_INC_INIT(&state);

    for (uint32_t i = 0; i < T; i++) {
        monomial_sample_salt(&mu_tilde,
                             linearized_rounds_seeds + i * SEED_LENGTH_BYTES,
                             sig->salt,
                             i);
        generator_monomial_mul(&G0, &full_G0, &mu_tilde);
        memset(is_pivot_column, 0, N_pad);
#if defined(LESS_REUSE_PIVOTS_SG)
        /* predict pivot positions from C_0's pivots through the ephemeral
         * monomial permutation, and reuse them in the Gaussian elimination */
        uint8_t permuted_pivot_flags[N_pad];
        for (uint32_t t = 0; t < N; t++) {
            permuted_pivot_flags[mu_tilde.permutation[t]] = g0_initial_pivot_flags[t];
        }
        if (generator_RREF_pivot_reuse(&G0, is_pivot_column, permuted_pivot_flags, SIGN_PIVOT_REUSE_LIMIT) == 0) {
            return 0;
        }
#else
        if (generator_RREF(&G0, is_pivot_column) == 0) {
            return 0;
        }
#endif

        // just copy the non IS
        uint32_t ctr = 0;
        for(uint32_t j = 0; j < N-K; j++) {
            while (is_pivot_column[ctr]) {
                ctr += 1;
            }
            /// copy column
            for (uint32_t k = 0; k < K; k++) {
                A_i.values[k][j] = G0.values[k][ctr];
            }
            ctr += 1;
        }

        POSITION_T piv_idx = 0;
        for(uint32_t col_idx = 0; col_idx < N; col_idx++) {
            POSITION_T row_idx = 0;
            for(uint32_t t = 0; t < N; t++) {
               if (mu_tilde.permutation[t] == col_idx) {
                   row_idx = t;
                   break;
               }
            }
            if(is_pivot_column[col_idx] == 1) {
               pi_tilde[i].permutation[piv_idx] = row_idx;
               piv_idx++;
            }
        }

        blind(&A_i, &cf_shake_state);
        const int t = CF(&A_i);

        if (t == 0) {
            *(linearized_rounds_seeds + i*SEED_LENGTH_BYTES) += 1;
            i -= 1;
        } else {
            // NOTE: as we increase the size of the `normalized_IS_t`
            // we need to hash the values row by row.
#if defined(USE_AVX2) || defined(USE_NEON)
            for (uint32_t sl = 0; sl < K; sl++) {
                LESS_SHA3_INC_ABSORB(&state, A_i.values[sl], K);
            }
#else
            LESS_SHA3_INC_ABSORB(&state, (uint8_t *)&A_i, sizeof(normalized_IS_t));
#endif
        }
    }

    LESS_SHA3_INC_ABSORB(&state, (const uint8_t *)m, mlen);
    LESS_SHA3_INC_ABSORB(&state, sig->salt, HASH_DIGEST_LENGTH);

    /* Squeeze output */
    LESS_SHA3_INC_FINALIZE(sig->digest, &state);
    // (b_0, ..., b_{t-1})
    uint8_t fixed_weight_string[T] = {0};
    SampleChallenge(fixed_weight_string, sig->digest);

    uint8_t indices_to_publish[T];
    for (uint32_t i = 0; i < T; i++) {
        indices_to_publish[i] = !!(fixed_weight_string[i]);
    }

    int emitted_monoms = 0;
    memset(&sig->seed_storage, 0, SEED_TREE_MAX_PUBLISHED_BYTES);

    const uint32_t num_seeds_published =
            GGMPath(seed_tree,
                           indices_to_publish,
                           (unsigned char *) &sig->seed_storage);

    monomial_action_IS_t mono_action;
    for (uint32_t i = 0; i < T; i++) {
        if (fixed_weight_string[i] != 0) {
            const uint8_t challenge = fixed_weight_string[i];
            const uint32_t v = CHALLENGE_MAGNITUDE(challenge);

            monomial_t Q_to_multiply;
            if (v == 0) {
                /* dual of keypair 0 (-0): C_0^perp = C_0 J, linking monomial J,
                 * so the response is J^{-1}. (Only used when DUAL_HIDDEN_C0.) */
                Q_to_multiply = J_inv;
            } else {
                /* Q_v^{-1} is exactly the monomial sampled from the private seed */
                monomial_t Q_v_inv;
                monomial_sample_prikey(&Q_v_inv, private_monomial_seeds[v - 1]);

                if (!CHALLENGE_IS_DUAL(challenge)) {
                    /* positive challenge: response uses (C_v = C_0 Q_v)^{-1} link */
                    Q_to_multiply = Q_v_inv;
                } else {
                    /* dual challenge: C_v^perp = C_0 (J Q_v^{-T}), linking
                     * monomial J Q_v^{-T}, response Q_v^T J^{-1}. */
                    monomial_t Q_v, Q_v_T;
                    monomial_inv(&Q_v, &Q_v_inv);            /* Q_v        */
                    monomial_transpose(&Q_v_T, &Q_v);        /* Q_v^T      */
                    monomial_mat_mul(&Q_to_multiply, &Q_v_T, &J_inv); /* Q_v^T J^{-1} */
                }
            }

            monomial_compose_action(&mono_action, &Q_to_multiply, &pi_tilde[i]);
            CosetRep(sig->cf_monom_actions[emitted_monoms], &mono_action);
            emitted_monoms++;
        }
    }
    return num_seeds_published;
} /* end LESS_sign */

/// NOTE: non-constant time
/// \param PK[in]: public key
/// \param m[in]: message for which a signature was computed
/// \param mlen[in]: length of the message in bytes
/// \param sig[in]: signature
/// \return 0: on failure
///         1: on success
int LESS_verify(const pubkey_t *const PK,
                const char *const m,
                const uint64_t mlen,
                const sign_t *const sig) {
    uint8_t fixed_weight_string[T] = {0};
    uint8_t is_pivot_column[N_pad];
    uint8_t g0_pivot_flags[N];
    uint8_t gi_pivot_flags[N];
    uint8_t g0_permuted_pivot_flags[N_pad];
    SampleChallenge(fixed_weight_string, sig->digest);

    uint8_t published_seed_indexes[T];
    for (uint32_t i = 0; i < T; i++) {
        published_seed_indexes[i] = !!(fixed_weight_string[i]);
    }

    unsigned char seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES] = {0};
    uint32_t rebuilding_seeds_went_fine;
    rebuilding_seeds_went_fine = RebuildGGM(seed_tree,
                                                          published_seed_indexes,
                                                          (unsigned char *) &sig->seed_storage,
                                                          sig->salt);
    if (!rebuilding_seeds_went_fine) {
        return 0;
    }

    unsigned char linearized_rounds_seeds[T*SEED_LENGTH_BYTES] = {0};
    seed_leaves(linearized_rounds_seeds,seed_tree);

    int employed_monoms = 0;

    /* expand the hidden-isodual base code G_0 */
    generator_mat_t G0_full;
#ifdef DUAL_HIDDEN_C0
    /* C_0 is stored explicitly at SF_G[0] (J is secret) */
    expand_to_rref(&G0_full, PK->SF_G[0], g0_pivot_flags);
#else
    /* C_0 is regenerated from the public seed (J is public) */
    dual_expand_C0(&G0_full, NULL, g0_pivot_flags, 1, PK->C0_seed);
#endif

    generator_mat_t G_v = {0}, G_used = {0};
    generator_mat_t G_prime = {0};
    monomial_t mu_tilde;
    normalized_IS_t Ai = {0};
    LESS_SHA3_INC_CTX state;
    LESS_SHA3_INC_INIT(&state);

    /* Precompute the dual code generators once, instead of recomputing them on
     * every negative-challenge round. dual_gen[v] = generator of C_v^perp.
     * dual_gen[0] (C_0^perp) is only reachable with DUAL_HIDDEN_C0. */
    generator_mat_t dual_gen[NUM_KEYPAIRS];
#ifdef DUAL_HIDDEN_C0
    if (generator_dual(&dual_gen[0], &G0_full) == 0) { return 0; }
#endif
    for (uint32_t vv = 1; vv < NUM_KEYPAIRS; vv++) {
        generator_mat_t cv;
        uint8_t pf[N];
        expand_to_rref(&cv, PK->SF_G[SFG_INDEX(vv)], pf);
        if (generator_dual(&dual_gen[vv], &cv) == 0) { return 0; }
    }

    for (uint32_t i = 0; i < T; i++) {
        memset(is_pivot_column, 0, N_pad);
        if (fixed_weight_string[i] == 0) {
            monomial_sample_salt(&mu_tilde,
                                 linearized_rounds_seeds + i * SEED_LENGTH_BYTES,
                                 sig->salt,
                                 i);

            generator_monomial_mul(&G_prime, &G0_full, &mu_tilde);
#if defined(LESS_REUSE_PIVOTS_VY)
            uint8_t permuted_pivot_flags[N_pad] = {0};
            for (uint32_t t = 0; t < N; t++) {
                permuted_pivot_flags[mu_tilde.permutation[t]] = g0_pivot_flags[t];
            }
            if (generator_RREF_pivot_reuse(&G_prime, is_pivot_column, permuted_pivot_flags, VERIFY_PIVOT_REUSE_LIMIT) == 0) {
                return 0;
            }
#else
            if (generator_RREF(&G_prime, is_pivot_column) == 0) {
                return 0;
            }
#endif
        } else {
            const uint8_t challenge = fixed_weight_string[i];
            const uint32_t v = CHALLENGE_MAGNITUDE(challenge);

            if (!CheckCanonicalAction(sig->cf_monom_actions[employed_monoms])) {
                return 0;
            }

            if (v == 0) {
                /* dual of keypair 0 (-0): use precomputed C_0^perp generator */
                G_used = dual_gen[0];
            } else {
                if (!CHALLENGE_IS_DUAL(challenge)) {
                    /* positive challenge: expand and use C_v directly */
                    expand_to_rref(&G_v, PK->SF_G[SFG_INDEX(v)], gi_pivot_flags);
                    G_used = G_v;
                } else {
                    /* dual challenge: use precomputed C_v^perp generator */
                    G_used = dual_gen[v];
                }
            }

            /* Positive (non-dual) challenges keep C_v in RREF form, so we know
             * its pivot pattern (gi_pivot_flags) and can reuse pivots. Dual
             * challenges use a dual generator with no carried-over pivot
             * structure, so they fall back to a full RREF. */
            const int positive_challenge = (v != 0) && !CHALLENGE_IS_DUAL(challenge);
            int ret;
#if defined(LESS_REUSE_PIVOTS_VY)
            if (positive_challenge) {
                apply_cf_action_to_G_with_pivots(&G_prime, &G_used,
                                                 sig->cf_monom_actions[employed_monoms],
                                                 gi_pivot_flags, g0_permuted_pivot_flags);
                ret = generator_RREF_pivot_reuse(&G_prime, is_pivot_column,
                                                 g0_permuted_pivot_flags,
                                                 VERIFY_PIVOT_REUSE_LIMIT);
            } else
#endif
            {
                apply_cf_action_to_G(&G_prime, &G_used, sig->cf_monom_actions[employed_monoms]);
                ret = generator_RREF(&G_prime, is_pivot_column);
            }
            if (ret == 0) {
                return 0;
            }

            employed_monoms++;
        }
        // just copy the non IS
        uint32_t ctr = 0;
        for(uint32_t j = 0; j < N-K; j++) {
            while (is_pivot_column[ctr]) {
                ctr += 1;
            }
            /// copy column
            for (uint32_t k = 0; k < K; k++) {
                Ai.values[k][j] = G_prime.values[k][ctr];
            }
            ctr += 1;
        }
        const int r = CF(&Ai);
        if (r == 0) {
            return 0;
        }
#if defined(USE_AVX2) || defined(USE_NEON)
        for (uint32_t sl = 0; sl < K; sl++) {
            LESS_SHA3_INC_ABSORB(&state, Ai.values[sl], K);
        }
#else
        LESS_SHA3_INC_ABSORB(&state, (uint8_t *)&Ai, sizeof(normalized_IS_t));
#endif
    }

    uint8_t recomputed_digest[HASH_DIGEST_LENGTH] = {0};
    LESS_SHA3_INC_ABSORB(&state, (const uint8_t *) m, mlen);
    LESS_SHA3_INC_ABSORB(&state, sig->salt, HASH_DIGEST_LENGTH);
    /* Squeeze output */
    LESS_SHA3_INC_FINALIZE(recomputed_digest, &state);

    return (verify(recomputed_digest, sig->digest,
                   HASH_DIGEST_LENGTH) == 0);
} /* end LESS_verify */
