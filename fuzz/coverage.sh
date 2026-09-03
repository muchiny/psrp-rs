#!/usr/bin/env bash
#
# Report how much of `psrp-rs` the fuzz corpora actually reach.
#
#   ./fuzz/coverage.sh                       # every target, merged, summary
#   TARGETS="clixml_decoder" ./fuzz/coverage.sh
#   FORMAT=html ./fuzz/coverage.sh           # HTML report in fuzz/coverage/report/
#   FORMAT=lines ./fuzz/coverage.sh          # per-line annotated source
#
# A target whose corpus covers 20% of its module is a target that is not
# doing its job — usually the corpus needs better seeds, or the input
# grammar in `fuzz/src/lib.rs` is too narrow.
#
# Requires nightly, `cargo install cargo-fuzz` and the `llvm-tools`
# component (`rustup component add llvm-tools --toolchain nightly`).

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
FORMAT="${FORMAT:-summary}"

die() { echo "error: $*" >&2; exit 1; }

command -v cargo-fuzz >/dev/null 2>&1 \
  || die "cargo-fuzz not installed. Run: cargo install cargo-fuzz"

# `cargo fuzz coverage` needs the llvm-tools that ship with the nightly
# toolchain; find the matching llvm-cov rather than whatever is on PATH,
# since a mismatched version refuses to read the profdata.
SYSROOT="$(rustc +nightly --print sysroot)"
LLVM_COV="$(find "$SYSROOT" -name 'llvm-cov' -type f 2>/dev/null | head -n1)"
[ -n "$LLVM_COV" ] \
  || die "llvm-cov not found. Run: rustup component add llvm-tools --toolchain nightly"

TARGETS="${TARGETS:-$(cargo +nightly fuzz list)}"
TRIPLE="$(rustc -vV | awk '/^host:/ {print $2}')"

# `cargo fuzz coverage` and `cargo fuzz run` both build into
# `fuzz/target/<triple>/release/`, so whichever ran last wins and
# llvm-cov ends up reading a binary with no coverage instrumentation.
# Give the coverage build its own directory to keep the two apart.
COVERAGE_TARGET_DIR="fuzz/coverage-target"

objects=()
for target in $TARGETS; do
  echo "=== collecting coverage for $target ==="
  cargo +nightly fuzz coverage --target-dir "$COVERAGE_TARGET_DIR" "$target"
  object="$COVERAGE_TARGET_DIR/$TRIPLE/release/$target"
  [ -x "$object" ] || die "instrumented binary not found: $object"
  objects+=(-object "$object")
done

# `cargo fuzz coverage` writes one .profdata per target; merge them so
# the report answers "what do ALL the targets together reach?".
PROFDATA_DIR="fuzz/coverage"
merged="$PROFDATA_DIR/merged.profdata"
LLVM_PROFDATA="$(dirname "$LLVM_COV")/llvm-profdata"
# shellcheck disable=SC2046
"$LLVM_PROFDATA" merge -sparse -o "$merged" $(find "$PROFDATA_DIR" -name 'coverage.profdata')

common=(
  -instr-profile="$merged"
  -ignore-filename-regex='(\.cargo|rustc|fuzz/|/library/)'
  "${objects[@]}"
)

case "$FORMAT" in
  summary)
    "$LLVM_COV" report "${common[@]}"
    ;;
  lines)
    "$LLVM_COV" show "${common[@]}" --show-line-counts-or-regions "$ROOT/src"
    ;;
  html)
    out="$PROFDATA_DIR/report"
    "$LLVM_COV" show "${common[@]}" \
      --format=html --show-line-counts-or-regions \
      --output-dir="$out" "$ROOT/src"
    echo "HTML report: $out/index.html"
    ;;
  *)
    die "unknown FORMAT '$FORMAT' (summary | lines | html)"
    ;;
esac
