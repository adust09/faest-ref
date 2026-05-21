/*
 *  SPDX-License-Identifier: MIT
 *
 *  Smoke test for the 5-round aggregate signature (route a) using the
 *  faest_128f parameter set. Drives signer round1-5 and aggregator
 *  round1-4 + finalize end-to-end for both n=1 and n=3, then verifies
 *  with faest_128f_aggregate_verify and exercises tamper / pk substitution.
 */

#include "faest_128f.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr)                                                                                \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      fprintf(stderr, "FAIL: %s (line %d)\n", #expr, __LINE__);                                    \
      return 0;                                                                                    \
    }                                                                                              \
  } while (0)

static int run_aggregate_test(size_t signer_count) {
  uint8_t** pks = (uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  uint8_t** sks = (uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  const uint8_t** pk_ptrs = (const uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  void** signer_states = (void**)calloc(signer_count, sizeof(void*));
  uint8_t** msg1s_buf = (uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  uint8_t** msg2s_buf = (uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  uint8_t** msg3s_buf = (uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  uint8_t** msg5s_buf = (uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  const uint8_t** msg1s = (const uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  const uint8_t** msg2s = (const uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  const uint8_t** msg3s = (const uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  const uint8_t** msg5s = (const uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  CHECK(pks && sks && pk_ptrs && signer_states && msg1s_buf && msg2s_buf && msg3s_buf &&
        msg5s_buf && msg1s && msg2s && msg3s && msg5s);

  const size_t signer_state_size     = faest_128f_agg_signer_state_size();
  const size_t aggregator_state_size = faest_128f_agg_aggregator_state_size(signer_count);
  const size_t msg1_size             = faest_128f_agg_msg1_size();
  const size_t msg2_size             = faest_128f_agg_msg2_size();
  const size_t msg3_size             = faest_128f_agg_msg3_size();
  const size_t msg5_size             = faest_128f_agg_msg5_size();
  const size_t sig_size              = faest_128f_aggregate_signature_size(signer_count);
  CHECK(sig_size > 0);

  for (size_t j = 0; j < signer_count; ++j) {
    pks[j]            = (uint8_t*)malloc(FAEST_128F_PUBLIC_KEY_SIZE);
    sks[j]            = (uint8_t*)malloc(FAEST_128F_PRIVATE_KEY_SIZE);
    signer_states[j]  = calloc(1, signer_state_size);
    msg1s_buf[j]      = (uint8_t*)malloc(msg1_size);
    msg2s_buf[j]      = (uint8_t*)malloc(msg2_size);
    msg3s_buf[j]      = (uint8_t*)malloc(msg3_size);
    msg5s_buf[j]      = (uint8_t*)malloc(msg5_size);
    CHECK(pks[j] && sks[j] && signer_states[j] && msg1s_buf[j] && msg2s_buf[j] && msg3s_buf[j] &&
          msg5s_buf[j]);
    CHECK(faest_128f_keygen(pks[j], sks[j]) == 0);
    pk_ptrs[j] = pks[j];
    msg1s[j]   = msg1s_buf[j];
    msg2s[j]   = msg2s_buf[j];
    msg3s[j]   = msg3s_buf[j];
    msg5s[j]   = msg5s_buf[j];
  }

  void* aggregator_state = calloc(1, aggregator_state_size);
  uint8_t* signature     = (uint8_t*)malloc(sig_size);
  CHECK(aggregator_state && signature);

  const uint8_t msg[] = "the quick brown fox jumps over the lazy dog";
  const size_t msg_len = sizeof(msg) - 1;

  uint8_t chall_1[5 * 16 + 8];
  uint8_t chall_2[3 * 16 + 8];
  uint8_t chall_3[16];
  uint32_t ctr = 0;

  for (size_t j = 0; j < signer_count; ++j) {
    CHECK(faest_128f_agg_signer_init(signer_states[j], sks[j], j, signer_count) == 0);
  }
  CHECK(faest_128f_agg_aggregator_init(aggregator_state, pk_ptrs, signer_count, msg, msg_len) ==
        0);

  // Round 1
  for (size_t j = 0; j < signer_count; ++j) {
    CHECK(faest_128f_agg_signer_round1(signer_states[j], msg1s_buf[j]) == 0);
  }
  CHECK(faest_128f_agg_aggregator_round1(aggregator_state, msg1s, chall_1) == 0);

  // Round 2
  for (size_t j = 0; j < signer_count; ++j) {
    CHECK(faest_128f_agg_signer_round2(signer_states[j], chall_1, msg, msg_len, msg2s_buf[j]) ==
          0);
  }
  CHECK(faest_128f_agg_aggregator_round2(aggregator_state, msg2s, chall_2) == 0);

  // Round 3
  for (size_t j = 0; j < signer_count; ++j) {
    CHECK(faest_128f_agg_signer_round3(signer_states[j], chall_2, msg3s_buf[j]) == 0);
  }
  CHECK(faest_128f_agg_aggregator_round3(aggregator_state, msg3s) == 0);

  // Round 4 (aggregator-only grinding)
  CHECK(faest_128f_agg_aggregator_round4(aggregator_state, chall_3, &ctr) == 0);

  // Round 5
  for (size_t j = 0; j < signer_count; ++j) {
    CHECK(faest_128f_agg_signer_round5(signer_states[j], chall_3, msg5s_buf[j]) == 0);
  }
  size_t sig_len = sig_size;
  CHECK(faest_128f_agg_aggregator_finalize(aggregator_state, msg5s, signature, &sig_len) == 0);
  CHECK(sig_len == sig_size);

  // Positive verify.
  CHECK(faest_128f_aggregate_verify(pk_ptrs, signer_count, msg, msg_len, signature, sig_len) ==
        0);

  // Negative: tampered message rejected.
  uint8_t tampered[sizeof(msg)];
  memcpy(tampered, msg, msg_len);
  tampered[0] ^= 1;
  CHECK(faest_128f_aggregate_verify(pk_ptrs, signer_count, tampered, msg_len, signature, sig_len) !=
        0);

  // Negative: substitute one public key rejected.
  if (signer_count > 0) {
    uint8_t other_pk[FAEST_128F_PUBLIC_KEY_SIZE];
    uint8_t other_sk[FAEST_128F_PRIVATE_KEY_SIZE];
    CHECK(faest_128f_keygen(other_pk, other_sk) == 0);
    const uint8_t** sub_pks = (const uint8_t**)calloc(signer_count, sizeof(uint8_t*));
    CHECK(sub_pks);
    for (size_t j = 0; j < signer_count; ++j) {
      sub_pks[j] = pk_ptrs[j];
    }
    sub_pks[0] = other_pk;
    CHECK(faest_128f_aggregate_verify(sub_pks, signer_count, msg, msg_len, signature, sig_len) !=
          0);
    free((void*)sub_pks);
  }

  printf("Aggregate (n=%zu) PASSED\n", signer_count);

  // Cleanup
  for (size_t j = 0; j < signer_count; ++j) {
    faest_128f_agg_signer_clear(signer_states[j]);
    free(signer_states[j]);
    free(pks[j]);
    free(sks[j]);
    free(msg1s_buf[j]);
    free(msg2s_buf[j]);
    free(msg3s_buf[j]);
    free(msg5s_buf[j]);
  }
  faest_128f_agg_aggregator_clear(aggregator_state);
  free(aggregator_state);
  free(signature);
  free(pks); free(sks); free(pk_ptrs);
  free(signer_states);
  free(msg1s_buf); free(msg2s_buf); free(msg3s_buf); free(msg5s_buf);
  free((void*)msg1s); free((void*)msg2s); free((void*)msg3s); free((void*)msg5s);
  return 1;
}

int main(void) {
  if (!run_aggregate_test(1)) return 1;
  if (!run_aggregate_test(3)) return 1;
  printf("ALL aggregate smoke tests PASSED\n");
  return 0;
}
