/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "faest_agg_aggregator.h"
#include "faest_agg_layout.h"

#include <string.h>

// Phase 1 stub: API surface only. Real state will track per-round payloads,
// h_com_j list, chall_1..3, accumulated (a_0_agg, a_1_agg, a_2_agg), ctr.
struct faest_agg_aggregator_state_t {
  size_t signer_count;
  uint16_t lambda;
  uint8_t initialized;
};

size_t faest_agg_aggregator_state_size(size_t signer_count, const faest_paramset_t* params) {
  (void)signer_count;
  (void)params;
  return sizeof(struct faest_agg_aggregator_state_t);
}

int faest_agg_aggregator_init(faest_agg_aggregator_state_t* state,
                              const uint8_t* const* owf_inputs,
                              const uint8_t* const* owf_outputs, size_t signer_count,
                              const uint8_t* msg, size_t msg_len,
                              const faest_paramset_t* params) {
  if (!state || !owf_inputs || !owf_outputs || !params || signer_count == 0 ||
      (!msg && msg_len)) {
    return -1;
  }
  for (size_t j = 0; j < signer_count; ++j) {
    if (!owf_inputs[j] || !owf_outputs[j]) {
      return -1;
    }
  }
  memset(state, 0, sizeof(*state));
  state->signer_count = signer_count;
  state->lambda       = params->lambda;
  state->initialized  = 1;
  return 0;
}

int faest_agg_aggregator_round1(faest_agg_aggregator_state_t* state,
                                const uint8_t* const* msg1s, uint8_t* chall_1_out,
                                const faest_paramset_t* params) {
  (void)msg1s; (void)chall_1_out;
  if (!state || !state->initialized || !params) {
    return -1;
  }
  return -1;
}

int faest_agg_aggregator_round2(faest_agg_aggregator_state_t* state,
                                const uint8_t* const* msg2s, uint8_t* chall_2_out,
                                const faest_paramset_t* params) {
  (void)msg2s; (void)chall_2_out;
  if (!state || !state->initialized || !params) {
    return -1;
  }
  return -1;
}

int faest_agg_aggregator_round3(faest_agg_aggregator_state_t* state,
                                const uint8_t* const* msg3s,
                                const faest_paramset_t* params) {
  (void)msg3s;
  if (!state || !state->initialized || !params) {
    return -1;
  }
  return -1;
}

int faest_agg_aggregator_round4(faest_agg_aggregator_state_t* state, uint8_t* chall_3_out,
                                uint32_t* ctr_out, const faest_paramset_t* params) {
  (void)chall_3_out; (void)ctr_out;
  if (!state || !state->initialized || !params) {
    return -1;
  }
  return -1;
}

int faest_agg_aggregator_finalize(faest_agg_aggregator_state_t* state,
                                  const uint8_t* const* msg5s, uint8_t* signature,
                                  size_t* signature_len, const faest_paramset_t* params) {
  (void)msg5s; (void)signature; (void)signature_len;
  if (!state || !state->initialized || !params) {
    return -1;
  }
  return -1;
}

void faest_agg_aggregator_clear(faest_agg_aggregator_state_t* state,
                                const faest_paramset_t* params) {
  (void)params;
  if (state) {
    memset(state, 0, sizeof(*state));
  }
}
