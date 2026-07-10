#!/usr/bin/env bash
# Dual-LESS runner.
#
# Usage:
#   ./run.sh <level> <variant> [action]
#
#   level    : 1 | 3 | 5         (NIST level: maps to CATEGORY 252 / 400 / 548)
#   variant  : A | B             (A = J public, s_eff=3 ; B = J secret, s_eff=4)
#   action   : run  -> keygen+sign+verify roundtrip (+ tamper check)  [default]
#              real -> ACTUAL execution: 1 keypair, sign 10 random 80-byte
#                      messages, verify each, report key + signature sizes
#              size -> average signature size (fast, no signing)
#              time -> wall-clock time per op + estimated cycles (no sudo)
#              cycles -> TRUE CPU cycles via PMU (uses sudo on Apple Silicon)
#
# Examples:
#   ./run.sh 1 A          # NIST-1, variant A, roundtrip test
#   ./run.sh 5 B size     # NIST-5, variant B, average signature size
#   ./run.sh 1 B cycles   # NIST-1, variant B, true cycle counts (sudo)
set -e

LEVEL="${1:?level required (1|3|5)}"
VARIANT="${2:?variant required (A|B)}"
ACTION="${3:-run}"

case "$LEVEL" in
  1) CAT=252; A=110; B=168 ;;
  3) CAT=400; A=165; B=119 ;;
  5) CAT=548; A=225; B=162 ;;
  *) echo "level must be 1, 3 or 5"; exit 1 ;;
esac

case "$VARIANT" in
  A|a) TGT=$A ;;
  B|b) TGT=$B ;;
  *) echo "variant must be A or B"; exit 1 ;;
esac

case "$ACTION" in
  run)    TESTSRC=lib/test/test_dual_e2e.c ;;
  size)   TESTSRC=lib/test/test_fastsize.c ;;
  real)   TESTSRC=lib/test/test_real_sign.c ;;
  time)   TESTSRC=lib/test/test_cycles.c ;;
  cycles) TESTSRC=lib/test/test_truecycles.c ;;
  *) echo "action must be 'run', 'size', 'real', 'time' or 'cycles'"; exit 1 ;;
esac

HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="/tmp/dualless_${CAT}_${TGT}_${ACTION}"

LIBS="lib/codes.c lib/fips202.c lib/keccakf1600.c lib/LESS.c lib/monomial.c \
      lib/rng.c lib/seedtree.c lib/sign.c lib/utils.c lib/sort.c lib/canonical.c \
      lib/transpose.c lib/dual.c"

# true-cycle build needs m1cycles.h (pulled in by cycles.h) from lib/bench
EXTRA_INC=""
if [ "$ACTION" = "cycles" ]; then EXTRA_INC="-I$HERE/lib/bench"; fi

echo ">> building: NIST-$LEVEL  variant $VARIANT  (CATEGORY=$CAT TARGET=$TGT)  action=$ACTION"
# shellcheck disable=SC2086
gcc -O3 -march=native -DCATEGORY=$CAT -DTARGET=$TGT -I"$HERE/include" -I"$HERE/lib/test" $EXTRA_INC \
    "$HERE/$TESTSRC" $(for f in $LIBS; do echo "$HERE/$f"; done) \
    -lm -o "$BIN"

echo ">> running:"
if [ "$ACTION" = "cycles" ]; then
    echo "   (true cycle counting on Apple Silicon needs the PMU -> running with sudo)"
    sudo "$BIN"
else
    "$BIN"
fi
