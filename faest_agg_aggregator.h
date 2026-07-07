/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef FAEST_AGG_AGGREGATOR_H
#define FAEST_AGG_AGGREGATOR_H

#include <stddef.h>
#include <stdint.h>

#include "instances.h"

FAEST_BEGIN_C_DECL

// Opaque aggregator state.
typedef struct faest_agg_aggregator_state_t faest_agg_aggregator_state_t;

size_t faest_agg_aggregator_state_size(size_t signer_count, const faest_paramset_t* params);

// Initialize aggregator. owf_inputs[j], owf_outputs[j] form the per-signer public key.
int faest_agg_aggregator_init(faest_agg_aggregator_state_t* state,
                              const uint8_t* const* owf_inputs,
                              const uint8_t* const* owf_outputs, size_t signer_count,
                              const uint8_t* msg, size_t msg_len,
                              const faest_paramset_t* params);

// Round 1: consume the n msg1 messages, output chall_1.
int faest_agg_aggregator_round1(faest_agg_aggregator_state_t* state,
                                const uint8_t* const* msg1s, uint8_t* chall_1_out,
                                const faest_paramset_t* params);

// Round 2: consume the n msg2 messages, output chall_2.
int faest_agg_aggregator_round2(faest_agg_aggregator_state_t* state,
                                const uint8_t* const* msg2s, uint8_t* chall_2_out,
                                const faest_paramset_t* params);

// Round 3: consume the n msg3 messages (a_0_j, a_1_j, a_2_j). No outbound message.
int faest_agg_aggregator_round3(faest_agg_aggregator_state_t* state,
                                const uint8_t* const* msg3s,
                                const faest_paramset_t* params);

// Round 4: grind for chall_3, output chall_3 and ctr.
int faest_agg_aggregator_round4(faest_agg_aggregator_state_t* state, uint8_t* chall_3_out,
                                uint32_t* ctr_out, const faest_paramset_t* params);

// Round 5: consume the n msg5 messages, finalize signature.
// signature must be at least the layout total_bytes; *signature_len is updated to written bytes.
int faest_agg_aggregator_finalize(faest_agg_aggregator_state_t* state,
                                  const uint8_t* const* msg5s, uint8_t* signature,
                                  size_t* signature_len, const faest_paramset_t* params);

void faest_agg_aggregator_clear(faest_agg_aggregator_state_t* state,
                                const faest_paramset_t* params);

FAEST_END_C_DECL

#endif
