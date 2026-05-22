/*
 *  SPDX-License-Identifier: MIT
 *
 *  Benchmark for the 5-round aggregate signature on FAEST-128s, comparing
 *  against N independent (sequential) FAEST signatures across
 *  N in {1, 10, 100, 1000}.
 *
 *  Time: Catch2 BENCHMARK macros. The driver script (bench_aggregate.sh)
 *  caps sample counts for large N via --benchmark-samples.
 *
 *  Memory: when invoked with BENCH_MEMORY_MODE={agg,seq} and BENCH_MEMORY_N
 *  in the environment, the binary runs exactly one workload end-to-end and
 *  exits, so it can be profiled under `valgrind --tool=massif`. This pre-
 *  empts Catch2's main() via a global static initializer.
 */

extern "C" {
#include "faest_128s.h"
}

#include <catch_amalgamated.hpp>

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <sys/resource.h>

namespace {

constexpr const char* kBenchMessage =
    "This document describes and specifies the FAEST digital signature algorithm.";

// REQUIRE() is only valid inside a Catch2 TEST_CASE. AggSetup / SeqSetup are
// built both inside benchmarks and from the --memory-mode pre-empt, so we use
// a plain abort-on-failure check.
inline void check_or_die(bool cond, const char* msg) {
  if (!cond) {
    std::fprintf(stderr, "fatal: %s\n", msg);
    std::_Exit(1);
  }
}

// Per-signer keys and per-round message buffers for the aggregate protocol.
struct AggSetup {
  size_t signer_count = 0;
  std::vector<std::vector<uint8_t>> pks;
  std::vector<std::vector<uint8_t>> sks;
  std::vector<const uint8_t*> pk_ptrs;
  std::vector<void*> signer_states;
  void* aggregator_state = nullptr;
  std::vector<std::vector<uint8_t>> msg1_buf, msg2_buf, msg3_buf, msg5_buf;
  std::vector<const uint8_t*> msg1_ptrs, msg2_ptrs, msg3_ptrs, msg5_ptrs;
  std::vector<uint8_t> signature;
  size_t sig_size = 0;
  std::vector<uint8_t> message;

  static constexpr size_t kChall1Size = 5 * (128 / 8) + 8;
  static constexpr size_t kChall2Size = 3 * (128 / 8) + 8;
  static constexpr size_t kChall3Size = (128 / 8);

  uint8_t chall_1[kChall1Size]{};
  uint8_t chall_2[kChall2Size]{};
  uint8_t chall_3[kChall3Size]{};
  uint32_t ctr = 0;

  explicit AggSetup(size_t n) : signer_count(n) {
    const size_t signer_state_size     = faest_128s_agg_signer_state_size();
    const size_t aggregator_state_size = faest_128s_agg_aggregator_state_size(n);
    const size_t msg1_size             = faest_128s_agg_msg1_size();
    const size_t msg2_size             = faest_128s_agg_msg2_size();
    const size_t msg3_size             = faest_128s_agg_msg3_size();
    const size_t msg5_size             = faest_128s_agg_msg5_size();
    sig_size                           = faest_128s_aggregate_signature_size(n);
    check_or_die(sig_size > 0, "aggregate_signature_size returned 0");

    pks.resize(n);
    sks.resize(n);
    pk_ptrs.resize(n);
    signer_states.resize(n);
    msg1_buf.resize(n);
    msg2_buf.resize(n);
    msg3_buf.resize(n);
    msg5_buf.resize(n);
    msg1_ptrs.resize(n);
    msg2_ptrs.resize(n);
    msg3_ptrs.resize(n);
    msg5_ptrs.resize(n);

    for (size_t j = 0; j < n; ++j) {
      pks[j].resize(FAEST_128S_PUBLIC_KEY_SIZE);
      sks[j].resize(FAEST_128S_PRIVATE_KEY_SIZE);
      signer_states[j] = std::calloc(1, signer_state_size);
      check_or_die(signer_states[j] != nullptr, "calloc signer_state failed");
      msg1_buf[j].resize(msg1_size);
      msg2_buf[j].resize(msg2_size);
      msg3_buf[j].resize(msg3_size);
      msg5_buf[j].resize(msg5_size);
      check_or_die(faest_128s_keygen(pks[j].data(), sks[j].data()) == 0, "agg keygen failed");
      pk_ptrs[j]   = pks[j].data();
      msg1_ptrs[j] = msg1_buf[j].data();
      msg2_ptrs[j] = msg2_buf[j].data();
      msg3_ptrs[j] = msg3_buf[j].data();
      msg5_ptrs[j] = msg5_buf[j].data();
    }

    aggregator_state = std::calloc(1, aggregator_state_size);
    check_or_die(aggregator_state != nullptr, "calloc aggregator_state failed");
    signature.resize(sig_size);
    message.assign(reinterpret_cast<const uint8_t*>(kBenchMessage),
                   reinterpret_cast<const uint8_t*>(kBenchMessage) + std::strlen(kBenchMessage));
  }

  ~AggSetup() {
    for (size_t j = 0; j < signer_count; ++j) {
      if (signer_states[j]) {
        faest_128s_agg_signer_clear(signer_states[j]);
        std::free(signer_states[j]);
      }
    }
    if (aggregator_state) {
      faest_128s_agg_aggregator_clear(aggregator_state);
      std::free(aggregator_state);
    }
  }

  // Full 5-round sign producing this->signature. Re-initializes all state
  // each call so it can be invoked repeatedly inside a BENCHMARK.
  int sign_once() {
    for (size_t j = 0; j < signer_count; ++j) {
      faest_128s_agg_signer_clear(signer_states[j]);
      if (faest_128s_agg_signer_init(signer_states[j], sks[j].data(), j, signer_count) != 0)
        return -1;
    }
    faest_128s_agg_aggregator_clear(aggregator_state);
    if (faest_128s_agg_aggregator_init(aggregator_state, pk_ptrs.data(), signer_count,
                                       message.data(), message.size()) != 0)
      return -1;

    for (size_t j = 0; j < signer_count; ++j) {
      if (faest_128s_agg_signer_round1(signer_states[j], msg1_buf[j].data()) != 0) return -1;
    }
    if (faest_128s_agg_aggregator_round1(aggregator_state, msg1_ptrs.data(), chall_1) != 0)
      return -1;

    for (size_t j = 0; j < signer_count; ++j) {
      if (faest_128s_agg_signer_round2(signer_states[j], chall_1, message.data(), message.size(),
                                       msg2_buf[j].data()) != 0)
        return -1;
    }
    if (faest_128s_agg_aggregator_round2(aggregator_state, msg2_ptrs.data(), chall_2) != 0)
      return -1;

    for (size_t j = 0; j < signer_count; ++j) {
      if (faest_128s_agg_signer_round3(signer_states[j], chall_2, msg3_buf[j].data()) != 0)
        return -1;
    }
    if (faest_128s_agg_aggregator_round3(aggregator_state, msg3_ptrs.data()) != 0) return -1;

    if (faest_128s_agg_aggregator_round4(aggregator_state, chall_3, &ctr) != 0) return -1;

    for (size_t j = 0; j < signer_count; ++j) {
      if (faest_128s_agg_signer_round5(signer_states[j], chall_3, msg5_buf[j].data()) != 0)
        return -1;
    }
    size_t sig_len = sig_size;
    if (faest_128s_agg_aggregator_finalize(aggregator_state, msg5_ptrs.data(), signature.data(),
                                           &sig_len) != 0)
      return -1;
    return sig_len == sig_size ? 0 : -1;
  }

  int verify_once() const {
    return faest_128s_aggregate_verify(pk_ptrs.data(), signer_count, message.data(),
                                       message.size(), signature.data(), sig_size);
  }
};

struct SeqSetup {
  size_t signer_count = 0;
  std::vector<std::vector<uint8_t>> pks;
  std::vector<std::vector<uint8_t>> sks;
  std::vector<std::vector<uint8_t>> sigs;
  std::vector<size_t> sig_lens;
  std::vector<uint8_t> message;

  explicit SeqSetup(size_t n) : signer_count(n) {
    pks.resize(n);
    sks.resize(n);
    sigs.resize(n);
    sig_lens.assign(n, FAEST_128S_SIGNATURE_SIZE);
    for (size_t j = 0; j < n; ++j) {
      pks[j].resize(FAEST_128S_PUBLIC_KEY_SIZE);
      sks[j].resize(FAEST_128S_PRIVATE_KEY_SIZE);
      sigs[j].resize(FAEST_128S_SIGNATURE_SIZE);
      check_or_die(faest_128s_keygen(pks[j].data(), sks[j].data()) == 0, "seq keygen failed");
    }
    message.assign(reinterpret_cast<const uint8_t*>(kBenchMessage),
                   reinterpret_cast<const uint8_t*>(kBenchMessage) + std::strlen(kBenchMessage));
  }

  int sign_all() {
    for (size_t j = 0; j < signer_count; ++j) {
      sig_lens[j] = FAEST_128S_SIGNATURE_SIZE;
      if (faest_128s_sign(sks[j].data(), message.data(), message.size(), sigs[j].data(),
                          &sig_lens[j]) != 0)
        return -1;
    }
    return 0;
  }

  int verify_all() const {
    for (size_t j = 0; j < signer_count; ++j) {
      if (faest_128s_verify(pks[j].data(), message.data(), message.size(), sigs[j].data(),
                            sig_lens[j]) != 0)
        return -1;
    }
    return 0;
  }
};

long peak_rss_kb() {
  struct rusage ru{};
  if (getrusage(RUSAGE_SELF, &ru) != 0) return -1;
#if defined(__APPLE__)
  // macOS reports ru_maxrss in bytes, Linux in kilobytes.
  return ru.ru_maxrss / 1024;
#else
  return ru.ru_maxrss;
#endif
}

// === --memory mode pre-empt ============================================
//
// When BENCH_MEMORY_MODE is set in the environment, perform one workload
// end-to-end and exit before Catch2's main runs. Used by the
// `bench_aggregate_memory_usage_*` Massif targets.

void run_memory_mode(const std::string& mode, size_t n) {
  if (mode == "agg") {
    AggSetup s(n);
    if (s.sign_once() != 0) {
      std::fprintf(stderr, "agg sign_once failed (n=%zu)\n", n);
      std::_Exit(1);
    }
    if (s.verify_once() != 0) {
      std::fprintf(stderr, "agg verify_once failed (n=%zu)\n", n);
      std::_Exit(1);
    }
    std::fprintf(stderr, "agg n=%zu sig_bytes=%zu peak_rss_kb=%ld\n", n, s.sig_size,
                 peak_rss_kb());
  } else if (mode == "seq") {
    SeqSetup s(n);
    if (s.sign_all() != 0) {
      std::fprintf(stderr, "seq sign_all failed (n=%zu)\n", n);
      std::_Exit(1);
    }
    if (s.verify_all() != 0) {
      std::fprintf(stderr, "seq verify_all failed (n=%zu)\n", n);
      std::_Exit(1);
    }
    std::fprintf(stderr, "seq n=%zu sig_bytes_total=%zu peak_rss_kb=%ld\n", n,
                 n * static_cast<size_t>(FAEST_128S_SIGNATURE_SIZE), peak_rss_kb());
  } else {
    std::fprintf(stderr, "unknown BENCH_MEMORY_MODE=%s (expected agg|seq)\n", mode.c_str());
    std::_Exit(2);
  }
}

struct MemoryModePreEmpt {
  MemoryModePreEmpt() {
    const char* mm = std::getenv("BENCH_MEMORY_MODE");
    if (!mm) return;
    const char* nn = std::getenv("BENCH_MEMORY_N");
    size_t n       = nn ? std::strtoul(nn, nullptr, 10) : 1;
    run_memory_mode(std::string(mm), n);
    std::_Exit(0);
  }
};
const MemoryModePreEmpt _preempt;

}  // namespace

// === Catch2 benchmarks =================================================

#define AGG_SIGN_CASE(N)                                                                           \
  TEST_CASE("agg sign N=" #N, "[.][bench_agg][bench_n" #N "]") {                                   \
    AggSetup s(N);                                                                                 \
    BENCHMARK("agg_sign_n" #N) { return s.sign_once(); };                                          \
  }

#define AGG_VERIFY_CASE(N)                                                                         \
  TEST_CASE("agg verify N=" #N, "[.][bench_agg][bench_n" #N "]") {                                 \
    AggSetup s(N);                                                                                 \
    REQUIRE(s.sign_once() == 0);                                                                   \
    BENCHMARK("agg_verify_n" #N) { return s.verify_once(); };                                      \
  }

#define SEQ_SIGN_CASE(N)                                                                           \
  TEST_CASE("seq sign N=" #N, "[.][bench_agg][bench_n" #N "]") {                                   \
    SeqSetup s(N);                                                                                 \
    BENCHMARK("seq_sign_n" #N) { return s.sign_all(); };                                           \
  }

#define SEQ_VERIFY_CASE(N)                                                                         \
  TEST_CASE("seq verify N=" #N, "[.][bench_agg][bench_n" #N "]") {                                 \
    SeqSetup s(N);                                                                                 \
    REQUIRE(s.sign_all() == 0);                                                                    \
    BENCHMARK("seq_verify_n" #N) { return s.verify_all(); };                                       \
  }

#define SIZE_REPORT_CASE(N)                                                                        \
  TEST_CASE("report sizes N=" #N, "[bench_agg][bench_n" #N "][sizes]") {                           \
    const size_t agg_size = faest_128s_aggregate_signature_size(N);                                \
    const size_t seq_size = static_cast<size_t>(N) * FAEST_128S_SIGNATURE_SIZE;                    \
    std::printf("SIZES n=%d agg_sig_bytes=%zu seq_sig_bytes=%zu ratio=%.4f\n", N, agg_size,        \
                seq_size, static_cast<double>(agg_size) / static_cast<double>(seq_size));          \
    REQUIRE(agg_size > 0);                                                                         \
    REQUIRE(seq_size > 0);                                                                         \
  }

#define ALL_CASES_FOR(N)                                                                           \
  AGG_SIGN_CASE(N)                                                                                 \
  AGG_VERIFY_CASE(N)                                                                               \
  SEQ_SIGN_CASE(N)                                                                                 \
  SEQ_VERIFY_CASE(N)                                                                               \
  SIZE_REPORT_CASE(N)

ALL_CASES_FOR(1)
ALL_CASES_FOR(10)
ALL_CASES_FOR(100)
ALL_CASES_FOR(1000)
