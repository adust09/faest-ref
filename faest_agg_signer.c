/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "faest_agg_signer.h"
#include "faest_agg_layout.h"

#include <string.h>

// Phase 1 stub: API surface only. Internals materialize in Phase 2.
struct faest_agg_signer_state_t {
  size_t signer_index;
  size_t signer_count;
  uint16_t lambda;
  uint8_t initialized;
};

size_t faest_agg_signer_state_size(const faest_paramset_t* params) {
  (void)params;
  return sizeof(struct faest_agg_signer_state_t);
}

int faest_agg_signer_init(faest_agg_signer_state_t* state, const uint8_t* owf_key,
                          const uint8_t* owf_input, const uint8_t* owf_output,
                          size_t signer_index, size_t signer_count,
                          const faest_paramset_t* params) {
  if (!state || !owf_key || !owf_input || !owf_output || !params || signer_count == 0 ||
      signer_index >= signer_count) {
    return -1;
  }
  memset(state, 0, sizeof(*state));
  state->signer_index = signer_index;
  state->signer_count = signer_count;
  state->lambda       = params->lambda;
  state->initialized  = 1;
  return 0;
}

int faest_agg_signer_round1(faest_agg_signer_state_t* state, uint8_t* msg1_out,
                            const faest_paramset_t* params) {
  (void)msg1_out;
  if (!state || !state->initialized || !params) {
    return -1;
  }
  // Phase 1 stub.
  return -1;
}

int faest_agg_signer_round2(faest_agg_signer_state_t* state, const uint8_t* chall_1,
                            const uint8_t* msg, size_t msg_len, uint8_t* msg2_out,
                            const faest_paramset_t* params) {
  (void)chall_1; (void)msg; (void)msg_len; (void)msg2_out;
  if (!state || !state->initialized || !params) {
    return -1;
  }
  return -1;
}

int faest_agg_signer_round3(faest_agg_signer_state_t* state, const uint8_t* chall_2,
                            uint8_t* msg3_out, const faest_paramset_t* params) {
  (void)chall_2; (void)msg3_out;
  if (!state || !state->initialized || !params) {
    return -1;
  }
  return -1;
}

int faest_agg_signer_round5(faest_agg_signer_state_t* state, const uint8_t* chall_3,
                            uint8_t* msg5_out, const faest_paramset_t* params) {
  (void)chall_3; (void)msg5_out;
  if (!state || !state->initialized || !params) {
    return -1;
  }
  return -1;
}

void faest_agg_signer_clear(faest_agg_signer_state_t* state, const faest_paramset_t* params) {
  (void)params;
  if (state) {
    memset(state, 0, sizeof(*state));
  }
}
