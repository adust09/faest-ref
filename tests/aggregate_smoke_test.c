/*
 *  SPDX-License-Identifier: MIT
 *
 *  Smoke test for the 5-round aggregate signature (route a) using the
 *  faest_128f parameter set with n=1. Drives signer round1-5 and aggregator
 *  round1-4 + finalize in a single process, then aggregate_verify.
 */

#include "faest_128f.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(expr)                                                                                \
  do {                                                                                             \
    if (!(expr)) {                                                                                 \
      fprintf(stderr, "FAIL: %s (line %d)\n", #expr, __LINE__);                                    \
      goto cleanup;                                                                                \
    }                                                                                              \
  } while (0)

int main(void) {
  int rc = 1;

  const size_t signer_count = 1;
  uint8_t pk[FAEST_128F_PUBLIC_KEY_SIZE];
  uint8_t sk[FAEST_128F_PRIVATE_KEY_SIZE];
  CHECK(faest_128f_keygen(pk, sk) == 0);

  const uint8_t* pks[1] = {pk};
  const uint8_t  msg[]  = "the quick brown fox jumps over the lazy dog";
  const size_t msg_len  = sizeof(msg) - 1;

  // --- Allocate state machines ---
  const size_t signer_state_size     = faest_128f_agg_signer_state_size();
  const size_t aggregator_state_size = faest_128f_agg_aggregator_state_size(signer_count);
  const size_t msg1_size             = faest_128f_agg_msg1_size();
  const size_t msg2_size             = faest_128f_agg_msg2_size();
  const size_t msg3_size             = faest_128f_agg_msg3_size();
  const size_t msg5_size             = faest_128f_agg_msg5_size();
  const size_t sig_size              = faest_128f_aggregate_signature_size(signer_count);

  void* signer_state     = calloc(1, signer_state_size);
  void* aggregator_state = calloc(1, aggregator_state_size);
  uint8_t* msg1          = malloc(msg1_size);
  uint8_t* msg2          = malloc(msg2_size);
  uint8_t* msg3          = malloc(msg3_size);
  uint8_t* msg5          = malloc(msg5_size);
  uint8_t* signature     = malloc(sig_size);
  CHECK(signer_state && aggregator_state && msg1 && msg2 && msg3 && msg5 && signature);

  const uint8_t* msg1s[1] = {msg1};
  const uint8_t* msg2s[1] = {msg2};
  const uint8_t* msg3s[1] = {msg3};
  const uint8_t* msg5s[1] = {msg5};

  // --- Run the 5-round protocol ---
  CHECK(faest_128f_agg_signer_init(signer_state, sk, 0, signer_count) == 0);
  CHECK(faest_128f_agg_aggregator_init(aggregator_state, pks, signer_count, msg, msg_len) == 0);

  uint8_t chall_1[5 * 16 + 8];
  uint8_t chall_2[3 * 16 + 8];
  uint8_t chall_3[16];
  uint32_t ctr = 0;

  // Round 1
  CHECK(faest_128f_agg_signer_round1(signer_state, msg1) == 0);
  CHECK(faest_128f_agg_aggregator_round1(aggregator_state, msg1s, chall_1) == 0);

  // Round 2
  CHECK(faest_128f_agg_signer_round2(signer_state, chall_1, msg, msg_len, msg2) == 0);
  CHECK(faest_128f_agg_aggregator_round2(aggregator_state, msg2s, chall_2) == 0);

  // Round 3
  CHECK(faest_128f_agg_signer_round3(signer_state, chall_2, msg3) == 0);
  CHECK(faest_128f_agg_aggregator_round3(aggregator_state, msg3s) == 0);

  // Round 4 — aggregator grinds chall_3 alone.
  CHECK(faest_128f_agg_aggregator_round4(aggregator_state, chall_3, &ctr) == 0);

  // Round 5
  CHECK(faest_128f_agg_signer_round5(signer_state, chall_3, msg5) == 0);

  // Finalize
  size_t sig_len = sig_size;
  CHECK(faest_128f_agg_aggregator_finalize(aggregator_state, msg5s, signature, &sig_len) == 0);
  CHECK(sig_len == sig_size);

  // --- Verify ---
  CHECK(faest_128f_aggregate_verify(pks, signer_count, msg, msg_len, signature, sig_len) == 0);

  // Negative: tampered message rejected.
  uint8_t tampered[sizeof(msg)];
  memcpy(tampered, msg, msg_len);
  tampered[0] ^= 1;
  CHECK(faest_128f_aggregate_verify(pks, signer_count, tampered, msg_len, signature, sig_len) !=
        0);

  // Negative: substitute public key rejected.
  uint8_t other_pk[FAEST_128F_PUBLIC_KEY_SIZE];
  uint8_t other_sk[FAEST_128F_PRIVATE_KEY_SIZE];
  CHECK(faest_128f_keygen(other_pk, other_sk) == 0);
  const uint8_t* other_pks[1] = {other_pk};
  CHECK(faest_128f_aggregate_verify(other_pks, signer_count, msg, msg_len, signature, sig_len) !=
        0);

  printf("Aggregate (n=1) smoke test PASSED\n");
  rc = 0;

cleanup:
  faest_128f_agg_signer_clear(signer_state);
  faest_128f_agg_aggregator_clear(aggregator_state);
  free(signer_state);
  free(aggregator_state);
  free(msg1);
  free(msg2);
  free(msg3);
  free(msg5);
  free(signature);
  return rc;
}
