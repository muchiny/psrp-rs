#!/usr/bin/env bash
#
# psrp-rs fuzz driver.
#
#   ./fuzz/run.sh                       # every target, 60s each
#   DURATION=900 ./fuzz/run.sh          # 15 minutes per target
#   TARGETS="clixml_decoder" ./fuzz/run.sh
#   JOBS=4 ./fuzz/run.sh                # 4 libFuzzer workers per target
#   MODE=smoke ./fuzz/run.sh            # 10s each, for CI on a pull request
#   MODE=cmin ./fuzz/run.sh             # minimise the corpora, no fuzzing
#   MODE=list ./fuzz/run.sh             # print the target list and exit
#   SANITIZER=none ./fuzz/run.sh        # no ASan (much faster, less coverage)
#
# Targets are discovered from `cargo fuzz list`, so adding a `[[bin]]` to
# fuzz/Cargo.toml is enough — this script needs no edit.
#
# Requires the nightly toolchain (`rustup toolchain install nightly`) and
# `cargo install cargo-fuzz`.

set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"

MODE="${MODE:-run}"
DURATION="${DURATION:-60}"
JOBS="${JOBS:-1}"
SANITIZER="${SANITIZER:-address}"
# libFuzzer defaults to 4096, which is too small to reach the deeply
# nested CLIXML documents that used to overflow the stack.
MAX_LEN="${MAX_LEN:-16384}"
# One input must never take longer than this. The `known_hosts` matcher
# regression was found exactly here.
UNIT_TIMEOUT="${UNIT_TIMEOUT:-10}"
RSS_LIMIT_MB="${RSS_LIMIT_MB:-2048}"

if [ "$MODE" = "smoke" ]; then
  DURATION="${SMOKE_DURATION:-10}"
fi

# ---------------------------------------------------------------------

die() { echo "error: $*" >&2; exit 1; }

command -v cargo-fuzz >/dev/null 2>&1 \
  || die "cargo-fuzz not installed. Run: cargo install cargo-fuzz"
rustup toolchain list | grep -q nightly \
  || die "nightly toolchain missing. Run: rustup toolchain install nightly"

ALL_TARGETS="$(cargo +nightly fuzz list)"
TARGETS="${TARGETS:-$ALL_TARGETS}"

if [ "$MODE" = "list" ]; then
  echo "$ALL_TARGETS"
  exit 0
fi

# Map a target onto the libFuzzer dictionary that matches its input.
dict_for() {
  case "$1" in
    clixml_*|records_decode|metadata_decode|host_dispatch)
      echo "fuzz/dictionaries/clixml.dict" ;;
    fragment_*|message_*|psrp_stream|pool_receive|runspace_state_machine)
      echo "fuzz/dictionaries/psrp.dict" ;;
    known_hosts_match)
      echo "fuzz/dictionaries/known_hosts.dict" ;;
    *)
      echo "" ;;
  esac
}

# Seed a target's working corpus from the version-controlled seeds.
seed_corpus() {
  local target="$1"
  mkdir -p "fuzz/corpus/$target"
  if [ -d "fuzz/seeds/$target" ]; then
    cp -n "fuzz/seeds/$target"/* "fuzz/corpus/$target/" 2>/dev/null || true
  fi
}

failed=()

for target in $TARGETS; do
  echo "$ALL_TARGETS" | grep -qx "$target" \
    || die "unknown target '$target' (see: MODE=list ./fuzz/run.sh)"

  seed_corpus "$target"
  dict="$(dict_for "$target")"

  args=(--sanitizer "$SANITIZER" --jobs "$JOBS")
  libfuzzer_args=(
    "-rss_limit_mb=$RSS_LIMIT_MB"
    "-timeout=$UNIT_TIMEOUT"
    "-max_len=$MAX_LEN"
    "-print_final_stats=1"
  )
  [ -n "$dict" ] && libfuzzer_args+=("-dict=$ROOT/$dict")

  case "$MODE" in
    cmin)
      echo "=== minimising corpus for $target ==="
      # `cmin` keeps the smallest set of inputs with the same coverage.
      cargo +nightly fuzz cmin "$target" -- "${libfuzzer_args[@]}" || failed+=("$target")
      continue
      ;;
    run|smoke)
      echo "============================================================"
      echo " fuzzing $target for ${DURATION}s"
      echo "   sanitizer=$SANITIZER jobs=$JOBS max_len=$MAX_LEN${dict:+ dict=$(basename "$dict")}"
      echo "============================================================"
      libfuzzer_args+=("-max_total_time=$DURATION")
      ;;
    *)
      die "unknown MODE '$MODE' (run | smoke | cmin | list)"
      ;;
  esac

  if ! cargo +nightly fuzz run "${args[@]}" "$target" -- "${libfuzzer_args[@]}"; then
    failed+=("$target")
    echo "!!! $target FAILED — artifacts in fuzz/artifacts/$target/" >&2
  fi
done

echo
if [ ${#failed[@]} -ne 0 ]; then
  echo "FAILED targets: ${failed[*]}" >&2
  echo "Reproduce with: cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>" >&2
  exit 1
fi
echo "All targets survived (${MODE}, ${DURATION}s each)."
