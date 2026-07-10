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
original code is in the public domain. The original README follows below.

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

# Original LESS README

The submission for LESS contains the following:

• Reference_Implementation

A reference implementation of the signature LESS as a C99 library. The 
reference implementation library does not provide a main() function, and is
intended to be compiled and linked to a binary. The required NIST API is 
present in `Reference_Implementation/include/api.h`. The implementation employ 
a provided generic keccak implementation.

• Optimized_Implementation

We provide multiple different optimized versions of the LESS signature scheme.
In total we provide two different optimized implementation: an AVX2, NEON.
The AVX2 version is optimized for modern Intel CPUs from the Haswell generation.
The NEON version is optimized for ARM CPUs like Apple M1. 

The library is organized in the same fashion as the reference one, except there 
is no support for using libkeccak. All implementations come with their own 
optimized SHA3 and SHAKE implementation.

The following libraries/tools are needed:
- `cmake`
- `make`
- `gcc`/`clang`
- `openssl`
- `pkg-config`


Utilities
===========

This directory provides CMake based building facilities to generate executable 
files either performing a benchmark of LESS, or generating the Known Answer 
Test files in the KAT folder, as well as a script used for parameter generation.

Benchmarking:
=============

To build the benchmarking binaries, run the following:
```bash
cd Utilities/Benchmarking
mkdir build && cd build
cmake .. 
make 
```
1 - Enter Utilities/Benchmarking
2 - create a "build" directory and enter it
3 - type cmake ../ to generate the makefiles
4 - type make to compile the codebase

By default, the optimized AVX2 implementation will be compiled. To select the
reference implementation for building, add `-DUSE_REFERENCE=1` to the `cmake`
command in step 3. To enable the ARM neon implementation you need to add a 
`-DUSE_NEON=1`.

Once build you can either run each binary like:
```bash
./LESS_benchmark_cat_252_45
```
or you can use the `bench.sh` script, which will automatically generate a markdown
table with the results. Additionally you can pass the flag `-DUSE_SANITIZER=1` to 
the cmake command to check for memory errors. Note, this slows the program down.

NOTE: If you run the benchmarks on an ARM based Apple computer, make sure that
    you run the binaries/scripts with root rights.

KAT Generation:
--------------

The KAT_Generation directory is organized in the same fashion as the
Benchmarking one. The same compilation procedure enacted for the benchmarking 
binary will generate all the executable files needed to re-generate the Known 
Answer Tests files. Specifically,
```bash
cd Utilities/KAT_Generation
mkdir build && cd build
cmake .. 
make 
```

By default, the reference implementation will be compiled. To select the 
optimized implementation for building, add either 
```
-DUSE_AVX2=1
-DUSE_NEON=1
-DUSE_REFERENCE=1
```

to the command in step 3. Only ever add one of the targets. The standard is to 
use the reference implementation. Additionally, you can also enable a `debug` 
build by adding `-DCMAKE_BUILD_TYPE=Debug` to the command in step 3. Furthermore
you can add `-DUSE_SANITIZE=1` to enable memory/pointer sanitation.

A commodity script generating all KATs is provided: `gen_all_kat.sh`. It can be 
run without parameters. KATs will be generated in the KAT directory

NOTE: If you are on a apple system: make sure that you use clang, by appending
    `-DCMAKE_C_COMPILER=clang`. Otherwise `LESS` will most likely not build in 
    debug mode, due to missing support for the address sanitizer.
</content>
