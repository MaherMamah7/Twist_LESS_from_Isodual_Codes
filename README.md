# Dual-LESS

**Author:** Maher Mamah.

This repository is a modified version of the **LESS** post-quantum signature
scheme. The Dual-LESS twist and its implementation (hidden-isodual key
generation, the dual-augmented challenge space, the new parameter sets, and the
supporting tooling) were designed and written by Maher Mamah.

It is built on top of the original LESS reference and optimized implementations,
which were written by **Alessandro Barenghi, Gerardo Pelosi and Floyd
Zweydinger** (with seed-tree contributions by **Patrick Karl**). All credit for
the underlying LESS scheme and its codebase goes to the original authors; the
original code is in the public domain. 

## The idea

LESS proves knowledge of a monomial map between equivalent linear codes. In each
round the verifier challenges one of `s` public codes `C_0, ..., C_{s-1}`.
Dual-LESS **augments the challenge space with the dual codes** `C_i^perp`,
roughly doubling the number of effective challenges without enlarging the public
key: the verifier derives `C_i^perp` on the fly from the public `C_i` via linear
algebra (its parity-check matrix), so nothing extra is stored.

To make this sound, the base code `C_0` is generated as a **hidden-isodual**
code. With `n = 2k` and odd `q`, sample a skew-symmetric `A`, set
`G_D = [I_k | A]`, and hide it with a secret monomial `R_0`, giving
`C_0 = <SF(G_D R_0)>`. Then

```
C_0^perp = C_0 * J,   with   J = R_0^{-1} J_H R_0^{-T},   J_H = [[0, I_k],[I_k, 0]]
```

where `J` is itself a monomial matrix. This lets a signer answer dual challenges
`-i` (response involves `J` and the secret `Q_i`), while the verifier only needs
`dual(C_i)`.

## Two variants

Both keep `n = 2k`, `q = 127`, and store few keys; they differ in what is public:

- **Variant A (J public).** `C_0` is regenerated from a public seed; `J` is
  public. Nonzero challenges are `{+1, -1}` per round (cheating prob 1/2). The
  dual of keypair 0 (`C_{-0}`) is excluded. Public key = seed + `s-1` matrices
  (same size as stock LESS).
- **Variant B (J secret).** `C_0` has hidden structure and is stored as a matrix
  (so `R_0`/`J` stay secret). Nonzero challenges are `{+1, -1, -0}` per round
  (cheating prob 1/3), including the dual of keypair 0. Public key = 2 stored
  matrices; the two extra codes `C_{-1}, C_{-0}` are derived on the fly.

The dual augmentation lets a smaller number of rounds `t` reach the same
soundness, which reduces signature size at an unchanged public-key size.

## Building and running

A convenience runner is provided in `Reference_Implementation/run.sh`:

```bash
cd Reference_Implementation
./run.sh <level> <variant> [action]
```

- `level`   : `1 | 3 | 5`   (NIST level -> CATEGORY 252 / 400 / 548)
- `variant` : `A | B`
- `action`  :
  - `run`    - keygen + sign + verify roundtrip (+ tamper check) [default]
  - `real`   - one keypair, sign 10 random 80-byte messages, report sizes
  - `size`   - average signature size (fast, no signing)
  - `time`   - wall-clock time per op + estimated cycles (no sudo)
  - `cycles` - true CPU cycles via the PMU (uses sudo on Apple Silicon)

Examples:
```bash
./run.sh 1 A run       # NIST-1, variant A, roundtrip
./run.sh 1 B size      # NIST-1, variant B, average signature size
./run.sh 5 A cycles    # NIST-5, variant A, true cycle counts
```

Selection is done at compile time via `-DCATEGORY=<252|400|548>` and
`-DTARGET=<id>`; the runner maps `level`/`variant` to the right pair (variant-B
parameter sets define the `DUAL_HIDDEN_C0` macro internally).

---



NOTE: If you are on a apple system: make sure that you use clang, by appending
    `-DCMAKE_C_COMPILER=clang`. Otherwise `LESS` will most likely not build in 
    debug mode, due to missing support for the address sanitizer.
</content>
