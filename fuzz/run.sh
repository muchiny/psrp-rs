#!/usr/bin/env bash
# psrp-rs fuzz runner.
#
# Usage:
#   ./fuzz/run.sh                       # run each target for 60 seconds
#   DURATION=300 ./fuzz/run.sh          # 5 minutes per target
#   TARGETS="clixml_decoder" \
#     ./fuzz/run.sh                     # only run one target
#
# Requires the nightly toolchain (`rustup toolchain install nightly`)
# and `cargo install cargo-fuzz`.

set -euo pipefail

TARGETS="${TARGETS:-fragment_reassembler clixml_decoder message_decode}"
DURATION="${DURATION:-60}"
JOBS="${JOBS:-1}"

cd "$(dirname "$0")/.."

if ! command -v cargo-fuzz >/dev/null 2>&1; then
  echo "error: cargo-fuzz not installed. Run: cargo install cargo-fuzz" >&2
  exit 1
fi

if ! rustup toolchain list | grep -q nightly; then
  echo "error: nightly toolchain not installed. Run: rustup toolchain install nightly" >&2
  exit 1
fi

for t in $TARGETS; do
  echo "============================================================"
  echo " fuzzing $t for ${DURATION}s (jobs=$JOBS)"
  echo "============================================================"
  cargo +nightly fuzz run "$t" \
    --jobs "$JOBS" \
    -- -max_total_time="$DURATION"
done

echo
echo "All fuzz targets survived ${DURATION}s each."
