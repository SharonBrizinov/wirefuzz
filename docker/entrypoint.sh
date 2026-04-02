#!/bin/bash
set -euo pipefail

# wirefuzz entrypoint - builds wireshark (if needed) and runs fuzzshark
# Commands: fuzz (default), build, minimize, reproduce, prepare-corpus

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[wirefuzz]${NC} $*"; }
log_ok() { echo -e "${GREEN}[wirefuzz]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[wirefuzz]${NC} $*"; }
log_err() { echo -e "${RED}[wirefuzz]${NC} $*" >&2; }

# Configuration from environment
ENCAP="${WIREFUZZ_ENCAP:-32767}"
WORKERS="${WIREFUZZ_WORKERS:-4}"
MAX_LEN="${WIREFUZZ_MAX_LEN:-65535}"
TIMEOUT="${WIREFUZZ_TIMEOUT:-5}"
RSS_LIMIT="${WIREFUZZ_RSS_LIMIT:-4096}"
DURATION="${WIREFUZZ_DURATION:-0}"

# Paths
WIRESHARK_SRC="${WIREFUZZ_WIRESHARK_SRC:-/opt/wireshark}"
BUILD_DIR="${WIRESHARK_SRC}/build"
FUZZSHARK="${BUILD_DIR}/run/fuzzshark"

# If host source is mounted at /src/wireshark, use it
if [ -d "/src/wireshark" ] && [ -f "/src/wireshark/CMakeLists.txt" ]; then
    WIRESHARK_SRC="/src/wireshark"
    BUILD_DIR="/build/wireshark"
    FUZZSHARK="${BUILD_DIR}/run/fuzzshark"
    log "Using host-mounted Wireshark source: /src/wireshark"

    # Build if needed (incremental)
    if [ ! -f "$FUZZSHARK" ]; then
        log "Building fuzzshark (first run with host source)..."
        mkdir -p "$BUILD_DIR" && cd "$BUILD_DIR"
        cmake -G Ninja "$WIRESHARK_SRC" \
            -DCMAKE_C_COMPILER=clang \
            -DCMAKE_CXX_COMPILER=clang++ \
            -DENABLE_FUZZER=ON \
            -DENABLE_ASAN=ON \
            -DENABLE_UBSAN=ON \
            -DBUILD_fuzzshark=ON \
            -DCMAKE_BUILD_TYPE=Release \
            -DBUILD_wireshark=OFF \
            -DBUILD_stratoshark=OFF \
            -DENABLE_LUA=OFF
        ninja -j4 fuzzshark editcap tshark
        log_ok "Build complete."
    fi
fi

# Verify fuzzshark exists
if [ ! -f "$FUZZSHARK" ]; then
    log_err "fuzzshark binary not found at: $FUZZSHARK"
    exit 1
fi

COMMAND="${1:-fuzz}"
shift || true

case "$COMMAND" in
    build)
        log "Building fuzzshark..."
        cd "$BUILD_DIR"
        ninja -j4 fuzzshark editcap tshark
        log_ok "Build complete."
        ;;

    fuzz)
        log "=== wirefuzz fuzzing session ==="
        log "  Encap type:  $ENCAP"
        log "  Workers:     $WORKERS"
        log "  Max length:  $MAX_LEN"
        log "  Timeout:     ${TIMEOUT}s"
        log "  RSS limit:   ${RSS_LIMIT}MB"
        log "  Fuzzshark:   $FUZZSHARK"

        export WIREFUZZ_ENCAP="$ENCAP"
        export FUZZSHARK_TARGET="${FUZZSHARK_TARGET:-frame}"

        # Ensure corpus directory exists and has at least one seed
        if [ -z "$(ls -A /corpus/ 2>/dev/null)" ]; then
            log_warn "Empty corpus directory, creating minimal seed..."
            printf '\x00\x00\x00\x00' > /corpus/seed_minimal
        fi

        # Pre-fuzz corpus minimization pass
        # Uses libfuzzer -merge=1 to keep only coverage-unique inputs.
        # Avoids shell glob expansion (ARG_MAX) by using find+xargs for
        # the corpus swap — safe with millions of files.
        CORPUS_MIN="/tmp/corpus_min"
        mkdir -p "$CORPUS_MIN"
        BEFORE=$(find /corpus/ -maxdepth 1 -type f | wc -l)
        log "  Corpus before minimization: $BEFORE files"
        log "  Running minimization pass (this may take a while)..."

        # Suppress the benign "fr_data" assertion warning that fires during
        # merge mode — it's a GLib g_warning(), not a crash, and spams output.
        WS_LOG_LEVEL=critical "$FUZZSHARK" \
            -merge=1 \
            -max_len="$MAX_LEN" \
            -timeout="$TIMEOUT" \
            -rss_limit_mb="$RSS_LIMIT" \
            "$CORPUS_MIN/" /corpus/ 2>&1 | tee /logs/minimize.log

        AFTER=$(find "$CORPUS_MIN" -maxdepth 1 -type f | wc -l)
        log_ok "  Minimization complete: $BEFORE -> $AFTER files"

        # Swap corpus: delete old files without glob, move new ones in
        find /corpus/ -maxdepth 1 -type f -delete
        find "$CORPUS_MIN" -maxdepth 1 -type f -print0 | xargs -0 -P4 mv -t /corpus/
        rmdir "$CORPUS_MIN" 2>/dev/null || true

        # Build libfuzzer arguments
        FUZZ_ARGS=(
            "-fork=$WORKERS"
            "-max_len=$MAX_LEN"
            "-timeout=$TIMEOUT"
            "-rss_limit_mb=$RSS_LIMIT"
            "-artifact_prefix=/crashes/"
            "-print_final_stats=1"
            "-detect_leaks=0"
        )

        # Optional duration limit
        if [ "$DURATION" -gt 0 ] 2>/dev/null; then
            FUZZ_ARGS+=("-max_total_time=$DURATION")
        fi

        # Optional dictionary
        if [ -f /dict/fuzz.dict ]; then
            FUZZ_ARGS+=("-dict=/dict/fuzz.dict")
            log "  Dictionary:  /dict/fuzz.dict"
        fi

        log "  Command: $FUZZSHARK ${FUZZ_ARGS[*]} /corpus/"
        log "---"

        # Run fuzzshark with libfuzzer, tee output to log file
        exec "$FUZZSHARK" "${FUZZ_ARGS[@]}" /corpus/ 2>&1 | tee /logs/fuzz.log
        ;;

    minimize)
        log "Minimizing corpus..."
        export WIREFUZZ_ENCAP="$ENCAP"
        export FUZZSHARK_TARGET="${FUZZSHARK_TARGET:-frame}"

        mkdir -p /corpus_minimized
        WS_LOG_LEVEL=critical "$FUZZSHARK" \
            -merge=1 \
            -max_len="$MAX_LEN" \
            -timeout="$TIMEOUT" \
            -rss_limit_mb="$RSS_LIMIT" \
            /corpus_minimized/ /corpus/ 2>&1 | tee /logs/minimize.log

        BEFORE=$(find /corpus/ -maxdepth 1 -type f | wc -l)
        AFTER=$(find /corpus_minimized/ -maxdepth 1 -type f | wc -l)
        log_ok "Minimization complete: $BEFORE -> $AFTER corpus entries"

        # Swap without glob expansion (safe for millions of files)
        find /corpus/ -maxdepth 1 -type f -delete
        find /corpus_minimized/ -maxdepth 1 -type f -print0 | xargs -0 -P4 mv -t /corpus/
        rmdir /corpus_minimized 2>/dev/null || true
        ;;

    reproduce)
        CRASH_FILE="${1:-}"
        if [ -z "$CRASH_FILE" ]; then
            log_err "Usage: reproduce <crash_file>"
            exit 1
        fi

        log "Reproducing crash: $CRASH_FILE"
        export WIREFUZZ_ENCAP="$ENCAP"
        export FUZZSHARK_TARGET="${FUZZSHARK_TARGET:-frame}"

        {
            "$FUZZSHARK" "$CRASH_FILE" 2>&1
            EXIT_CODE=$?
            if [ $EXIT_CODE -ne 0 ]; then
                log_ok "Crash reproduced (exit code: $EXIT_CODE)"
            else
                log_warn "Crash did NOT reproduce (exit code: 0)"
            fi
        } | tee /logs/reproduce.log
        ;;

    minimize-crash)
        CRASH_FILE="${1:-}"
        if [ -z "$CRASH_FILE" ]; then
            log_err "Usage: minimize-crash <crash_file>"
            exit 1
        fi

        log "Minimizing crash: $CRASH_FILE"
        export WIREFUZZ_ENCAP="$ENCAP"
        export FUZZSHARK_TARGET="${FUZZSHARK_TARGET:-frame}"

        CRASH_BASE=$(basename "$CRASH_FILE")
        "$FUZZSHARK" \
            -minimize_crash=1 \
            -max_total_time=60 \
            -exact_artifact_path="/crashes/minimized_${CRASH_BASE}" \
            "$CRASH_FILE" 2>&1 | tee /logs/minimize_crash.log

        log_ok "Minimized crash saved to: /crashes/minimized_${CRASH_BASE}"
        ;;

    prepare-corpus)
        # Extract packets by encap type from pcap files
        # Input pcaps should be mounted at /input/
        log "Preparing corpus from pcap files..."
        log "  Target encap: $ENCAP"

        INPUT_DIR="${1:-/input}"
        if [ ! -d "$INPUT_DIR" ]; then
            log_err "Input directory not found: $INPUT_DIR"
            exit 1
        fi

        WORK="/tmp/corpus_prep"
        mkdir -p "$WORK"/{split,filtered}

        # Split all pcaps into single-packet files
        SPLIT_COUNT=0
        for pcap in "$INPUT_DIR"/*.pcap "$INPUT_DIR"/*.pcapng "$INPUT_DIR"/*.cap; do
            [ -f "$pcap" ] || continue
            log "  Splitting: $(basename "$pcap")"
            editcap -c 1 -F pcapng "$pcap" "$WORK/split/pkt_${SPLIT_COUNT}_" 2>/dev/null || {
                log_warn "  Failed to split: $(basename "$pcap"), skipping"
                continue
            }
            SPLIT_COUNT=$((SPLIT_COUNT + 1))
        done

        TOTAL_SPLIT=$(find "$WORK/split" -type f | wc -l)
        log "  Total split packets: $TOTAL_SPLIT"

        # Filter by encap type and extract raw payloads
        KEPT=0
        SKIPPED=0
        for pkt in "$WORK/split"/*; do
            [ -f "$pkt" ] || continue
            # Get the link-type from capinfos
            LINK_TYPE=$(capinfos -E "$pkt" 2>/dev/null | grep -oP 'Encapsulation:\s+\K\S+' || echo "unknown")

            # Use tshark to extract raw bytes - write to raw file
            # The raw payload is what fuzzshark expects
            HASH=$(sha256sum "$pkt" | cut -c1-16)
            tshark -r "$pkt" -w - -F raw 2>/dev/null > "/corpus/pkt_${HASH}.raw" || {
                # Fallback: just strip pcap header (24 bytes global + 16 bytes per-packet)
                tail -c +41 "$pkt" > "/corpus/pkt_${HASH}.raw" 2>/dev/null || true
            }

            # Remove empty files
            if [ ! -s "/corpus/pkt_${HASH}.raw" ]; then
                rm -f "/corpus/pkt_${HASH}.raw"
                SKIPPED=$((SKIPPED + 1))
            else
                KEPT=$((KEPT + 1))
            fi
        done

        # Dedup by content hash
        BEFORE_DEDUP=$KEPT
        cd /corpus
        declare -A SEEN_HASHES
        for f in *.raw; do
            [ -f "$f" ] || continue
            H=$(sha256sum "$f" | cut -c1-64)
            if [ -n "${SEEN_HASHES[$H]:-}" ]; then
                rm -f "$f"
                KEPT=$((KEPT - 1))
            else
                SEEN_HASHES[$H]=1
            fi
        done

        log_ok "Corpus preparation complete:"
        log "  Split packets:  $TOTAL_SPLIT"
        log "  Before dedup:   $BEFORE_DEDUP"
        log "  After dedup:    $KEPT"
        log "  Skipped:        $SKIPPED"

        # Clean up
        rm -rf "$WORK"
        ;;

    *)
        log_err "Unknown command: $COMMAND"
        log "Available commands: fuzz, build, minimize, reproduce, minimize-crash, prepare-corpus"
        exit 1
        ;;
esac
