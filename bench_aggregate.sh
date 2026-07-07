#!/bin/bash
#
# Driver: aggregate vs sequential FAEST-128s benchmark.
#
# 1. Sets up build_release with catch2+benchmarks+valgrind enabled.
# 2. Builds faest_128s_bench_aggregate.
# 3. Runs Catch2 benchmarks per N with capped sample counts (so N=1000 finishes
#    in minutes, not hours).
# 4. Runs the Massif memory targets for each (mode, N).
# 5. Emits JSON Lines to stdout. One record per (mode, N, op) for timing rows
#    and one record per (mode, N) for memory rows; size rows are also emitted.
#
# Output schema (selected fields):
#   timing  : {kind:"timing",  variant, mode, n, op, samples, iterations,
#              mean_us, low_mean_us, high_mean_us, std_dev_us}
#   size    : {kind:"size",    variant, n, agg_sig_bytes, seq_sig_bytes, ratio}
#   memory  : {kind:"memory",  variant, mode, n,
#              peak_heap_bytes, peak_extra_heap_bytes, peak_stacks_bytes}

set -euo pipefail

BUILD_DIR="build_release"
VARIANT="faest_128s"
EXE_RELATIVE="${VARIANT}/${VARIANT}_bench_aggregate"
N_VALUES=(1 10 100 1000)

# Per-N catch2 sample caps. Heavy N -> fewer samples.
declare -A SAMPLES
SAMPLES[1]=30
SAMPLES[10]=20
SAMPLES[100]=10
SAMPLES[1000]=3

setup_build () {
    if [ -d "${BUILD_DIR}" ]; then
        meson setup --reconfigure "${BUILD_DIR}" .. \
            --buildtype release \
            -Dbenchmarks=enabled -Dcatch2=enabled -Dvalgrind=enabled \
            -Dmarch-native=enabled >&2 || true
    else
        mkdir -p "${BUILD_DIR}"
        pushd "${BUILD_DIR}" >/dev/null
        meson setup .. \
            --buildtype release \
            -Dbenchmarks=enabled -Dcatch2=enabled -Dvalgrind=enabled \
            -Dmarch-native=enabled >&2
        popd >/dev/null
    fi
    ninja -C "${BUILD_DIR}" "${EXE_RELATIVE}" >&2
}

# Convert a Catch2 time string like "4.5 ms" / "120 us" / "950 ns" to microseconds.
convert_to_us () {
    local input="$1"
    if ! echo "${input}" | grep -Pq '^[0-9]+(\.[0-9]+)? (u|m|n)?s$'; then
        echo "0"
        return
    fi
    local num
    local unit
    num="$(echo "${input}" | awk '{print $1}')"
    unit="$(echo "${input}" | awk '{print $2}')"
    case "${unit}" in
        ns) echo "scale=10; ${num} / 1000"      | bc ;;
        us) echo "${num}" ;;
        ms) echo "scale=10; ${num} * 1000"      | bc ;;
        s)  echo "scale=10; ${num} * 1000000"   | bc ;;
    esac
}

# Parse a single Catch2 benchmark block (3 lines after the header) into JSON.
# Args: file_with_block, op_name, n_value, mode_value
parse_benchmark_block () {
    local block="$1"
    local op="$2"
    local n="$3"
    local mode="$4"
    local line1 line2 line3
    line1="$(echo "${block}" | sed -e '1q;d' | tr -s ' ')"
    line2="$(echo "${block}" | sed -e '2q;d' | tr -s ' ')"
    line3="$(echo "${block}" | sed -e '3q;d' | tr -s ' ')"
    local samples iterations mean low_mean high_mean std_dev low_std_dev high_std_dev
    samples="$(echo "${line1}" | cut -d ' ' -f 2)"
    iterations="$(echo "${line1}" | cut -d ' ' -f 3)"
    mean="$(echo "${line2}" | cut -d ' ' -f 1-2)"
    low_mean="$(echo "${line2}" | cut -d ' ' -f 3-4)"
    high_mean="$(echo "${line2}" | cut -d ' ' -f 5-6)"
    std_dev="$(echo "${line3}" | cut -d ' ' -f 1-2)"
    low_std_dev="$(echo "${line3}" | cut -d ' ' -f 3-4)"
    high_std_dev="$(echo "${line3}" | cut -d ' ' -f 5-6)"

    jq -c -n \
        --arg "kind" "timing" \
        --arg "variant" "${VARIANT}" \
        --arg "mode" "${mode}" \
        --argjson "n" "${n}" \
        --arg "op" "${op}" \
        --argjson "samples" "${samples}" \
        --argjson "iterations" "${iterations}" \
        --argjson "mean_us" "$(convert_to_us "${mean}")" \
        --argjson "low_mean_us" "$(convert_to_us "${low_mean}")" \
        --argjson "high_mean_us" "$(convert_to_us "${high_mean}")" \
        --argjson "std_dev_us" "$(convert_to_us "${std_dev}")" \
        --argjson "low_std_dev_us" "$(convert_to_us "${low_std_dev}")" \
        --argjson "high_std_dev_us" "$(convert_to_us "${high_std_dev}")" \
        '$ARGS.named'
}

run_timing_for_n () {
    local n="$1"
    local samples="${SAMPLES[$n]}"
    echo "# Timing: n=${n} samples=${samples}" >&2

    local out
    out="$( \
        "./${BUILD_DIR}/${EXE_RELATIVE}" \
            "[bench_n${n}]" \
            --benchmark-samples "${samples}" \
            --benchmark-no-analysis 2>/dev/null )"

    # Capture size report (single line: "SIZES n=N agg_sig_bytes=X seq_sig_bytes=Y ratio=Z")
    local size_line
    size_line="$(echo "${out}" | grep "^SIZES n=${n} " || true)"
    if [ -n "${size_line}" ]; then
        local agg_bytes seq_bytes ratio
        agg_bytes="$(echo "${size_line}" | sed -E 's/.*agg_sig_bytes=([0-9]+).*/\1/')"
        seq_bytes="$(echo "${size_line}" | sed -E 's/.*seq_sig_bytes=([0-9]+).*/\1/')"
        ratio="$(echo "${size_line}"     | sed -E 's/.*ratio=([0-9.]+).*/\1/')"
        jq -c -n \
            --arg "kind" "size" \
            --arg "variant" "${VARIANT}" \
            --argjson "n" "${n}" \
            --argjson "agg_sig_bytes" "${agg_bytes}" \
            --argjson "seq_sig_bytes" "${seq_bytes}" \
            --argjson "ratio" "${ratio}" \
            '$ARGS.named'
    fi

    # Catch2 prints, for each BENCHMARK, a "name" line then 3 stat lines.
    # Names we emit are agg_sign_nN, agg_verify_nN, seq_sign_nN, seq_verify_nN.
    for op_full in "agg_sign_n${n}" "agg_verify_n${n}" "seq_sign_n${n}" "seq_verify_n${n}"; do
        local mode op
        mode="$(echo "${op_full}" | cut -d '_' -f 1)"          # agg | seq
        op="$(echo  "${op_full}"  | cut -d '_' -f 2)"          # sign | verify
        local block
        block="$(echo "${out}" | grep -A 3 -E "^${op_full}\b" | tail -n 3 || true)"
        if [ -z "${block}" ]; then
            echo "# WARN: no catch2 block found for ${op_full}" >&2
            continue
        fi
        parse_benchmark_block "${block}" "${op}" "${n}" "${mode}"
    done
}

run_memory_for_n_mode () {
    local n="$1"
    local mode="$2"
    local target="${VARIANT}/bench_aggregate_memory_usage_${mode}_n${n}"
    local massif_file="${BUILD_DIR}/${VARIANT}/bench_aggregate_${mode}_n${n}.massif"
    echo "# Memory: mode=${mode} n=${n}" >&2
    ninja -C "${BUILD_DIR}" "${target}" >&2

    # Find global peak snapshot (the one marked with #-----) and pull
    # peak heap / extra-heap / stacks bytes.
    local peak
    peak="$(ms_print "${massif_file}" 2>/dev/null \
        | grep -E '^\s+[0-9]+\s+[0-9,]+\s+[0-9,]+\s+[0-9,]+\s+[0-9,]+\s+[0-9,]+' \
        | sort -k 3 -h -r | head -n 1 || true)"
    if [ -z "${peak}" ]; then
        echo "# WARN: could not parse ${massif_file}" >&2
        return
    fi
    # ms_print columns: n   time  total  useful-heap  extra-heap  stacks
    local heap extra stacks
    heap="$(  echo "${peak}" | awk '{gsub(",","",$4); print $4}')"
    extra="$( echo "${peak}" | awk '{gsub(",","",$5); print $5}')"
    stacks="$(echo "${peak}" | awk '{gsub(",","",$6); print $6}')"
    jq -c -n \
        --arg "kind" "memory" \
        --arg "variant" "${VARIANT}" \
        --arg "mode" "${mode}" \
        --argjson "n" "${n}" \
        --argjson "peak_heap_bytes" "${heap}" \
        --argjson "peak_extra_heap_bytes" "${extra}" \
        --argjson "peak_stacks_bytes" "${stacks}" \
        '$ARGS.named'
}

main () {
    setup_build
    for n in "${N_VALUES[@]}"; do
        run_timing_for_n "${n}"
    done
    for n in "${N_VALUES[@]}"; do
        for mode in agg seq; do
            run_memory_for_n_mode "${n}" "${mode}"
        done
    done
}

main "$@"
