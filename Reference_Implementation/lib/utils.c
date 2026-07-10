/**
 *
 * Reference ISO-C11 Implementation of LESS.
 *
 * @version 1.2 (February 2025)
 *
 * @author Alessandro Barenghi <alessandro.barenghi@polimi.it>
 * @author Gerardo Pelosi <gerardo.pelosi@polimi.it>
 * @author Floyd Zweydinge <zweydfg8+github@rub.de>
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

#include "utils.h"
#include <stdlib.h>

/// swaps a and b if mask == -1ull
void cswap(uintptr_t *a,
           uintptr_t *b,
           const uintptr_t mask) {
    *a ^= (mask & *b);
    *b ^= (mask & *a);
    *a ^= (mask & *b);
}

/// taken from the kyber impl.
/// Description: Compare two arrays for equality in constant time.
///
/// Arguments:   const uint8_t *a: pointer to first byte array
///              const uint8_t *b: pointer to second byte array
///              size_t len:       length of the byte arrays
///
/// Returns 0 if the byte arrays are equal, 1 otherwise
int verify(const uint8_t *a,
           const uint8_t *b,
           const size_t len) {
    uint8_t r = 0;

    for(size_t i=0;i<len;i++) {
        r |= a[i] ^ b[i];
    }

    return (-(uint64_t)r) >> 63;
}

///
#define MAX_KEYPAIR_INDEX (NUM_KEYPAIRS-1)
///
#define KEYPAIR_INDEX_MASK (((uint16_t)1u << BITS_TO_REPRESENT(MAX_KEYPAIR_INDEX)) - 1u)
/* bitmask for rejection sampling of the position */
#define  POSITION_MASK (( (uint16_t)1 << BITS_TO_REPRESENT(T-1))-1)

/* Dual-LESS: the nonzero challenge alphabet is {+1,..,+(s-1), -1,..,-(s-1)},
 * i.e. 2*(NUM_KEYPAIRS-1) symbols. A symbol is sampled as an index r in
 * [0, NUM_NONZERO_CHALLENGES): r < s-1 maps to positive keypair (r+1), while
 * r >= s-1 maps to the dual challenge 0x80 | (r-(s-1)+1). */
#define NUM_NONZERO_CHALLENGES (2u*(NUM_KEYPAIRS-1u))
#define CHALLENGE_SAMPLE_MASK (((uint16_t)1u << BITS_TO_REPRESENT(NUM_NONZERO_CHALLENGES-1u)) - 1u)

/* Expands a digest into a fixed weight string of length T and weight W, whose
 * nonzero entries are signed challenges over keypairs 1..NUM_KEYPAIRS-1. */
void SampleChallenge(uint8_t fixed_weight_string[T],
                     const uint8_t digest[HASH_DIGEST_LENGTH]) {
    SHAKE_STATE_STRUCT shake_state;
    initialize_csprng(&shake_state,
                      (const unsigned char *) digest,
                      HASH_DIGEST_LENGTH);

    uint64_t rnd_buf;
    uint32_t c = 0;
    for (uint32_t i = 0; i < T-W; i++) {
        fixed_weight_string[i] = 0;
    }

#ifdef DUAL_HIDDEN_C0
    /* Variant B (J secret): three nonzero challenges per active round,
     * {+1, -1, -0} = {0x01, 0x81, 0x80}. Cheating probability 1/3. */
    {
        static const uint8_t dual_sym[3] = {0x01u, 0x81u, 0x80u};
        for (uint32_t i = T-W; i < T; i++) {
            uint16_t value;
            do {
                if (c == 0) {
                    csprng_randombytes((unsigned char *) &rnd_buf,
                                       sizeof(uint64_t), &shake_state);
                    c = 64u / 2u;
                }
                value = rnd_buf & 0x3u;   /* 2 bits cover {0,1,2,3} */
                rnd_buf >>= 2;
                c -= 1;
            } while (value >= 3u);
            fixed_weight_string[i] = dual_sym[value];
        }
    }
#else
    if (NUM_NONZERO_CHALLENGES != 1) {
        for (uint32_t i = T-W; i < T; i++) {
            uint16_t value;
            do {
                if (c == 0) {
                    csprng_randombytes((unsigned char *) &rnd_buf,
                                     sizeof(uint64_t),
                                     &shake_state);
                    c = 64u / BITS_TO_REPRESENT(NUM_NONZERO_CHALLENGES-1u);
                }

                value = rnd_buf & (CHALLENGE_SAMPLE_MASK);
                rnd_buf >>= BITS_TO_REPRESENT(NUM_NONZERO_CHALLENGES-1u);
                c -= 1;
          } while (value >= NUM_NONZERO_CHALLENGES);

          if (value < (uint16_t)(NUM_KEYPAIRS-1)) {
              /* positive challenge on keypair (value+1) */
              fixed_weight_string[i] = (uint8_t)(value + 1u);
          } else {
              /* dual challenge on keypair (value-(s-1)+1) */
              const uint16_t mag = value - (uint16_t)(NUM_KEYPAIRS-1) + 1u;
              fixed_weight_string[i] = (uint8_t)(0x80u | mag);
          }
       }
    } else {
        /* NUM_KEYPAIRS == 2: the only choices are +1 and -1 (one bit) */
        for (uint32_t i = T-W; i < T; i++) {
            uint8_t bit;
            if (c == 0) {
                csprng_randombytes((unsigned char *) &rnd_buf,
                                   sizeof(uint64_t), &shake_state);
                c = 64;
            }
            bit = rnd_buf & 1u;
            rnd_buf >>= 1;
            c -= 1;
            fixed_weight_string[i] = bit ? (uint8_t)(0x80u | 1u) : (uint8_t)1u;
        }
    }
#endif

    /* Reset the RNG buffer counter before sampling positions. The value loop
     * above consumes samples of a different bit-width than the position loop;
     * sharing the leftover buffer state would misalign (and bias/cluster) the
     * sampled positions. Forcing a fresh refill keeps positions uniform. */
    c = 0;

    for (uint32_t p = T - W; p < T; p++) {
        POSITION_T pos;
        do {
            if (c == 0) {
                csprng_randombytes((unsigned char *) &rnd_buf,
                                   sizeof(uint64_t),
                                   &shake_state);
                c = 64u / BITS_TO_REPRESENT(T-1);
            }
            pos = rnd_buf & (POSITION_MASK);
            rnd_buf >>= BITS_TO_REPRESENT(T-1);
            c -= 1;
        } while (pos > p);
        const uint8_t tmp = fixed_weight_string[p];
        fixed_weight_string[p] = fixed_weight_string[pos];
        fixed_weight_string[pos] = tmp;
    }
}
