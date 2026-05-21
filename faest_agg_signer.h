/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef FAEST_AGG_SIGNER_H
#define FAEST_AGG_SIGNER_H

#include <stddef.h>
#include <stdint.h>

#include "instances.h"

FAEST_BEGIN_C_DECL

// Opaque per-signer state. Holds local secrets — never serialize.
typedef struct faest_agg_signer_state_t faest_agg_signer_state_t;

// Return the size in bytes of the per-signer state struct for the given params.
size_t faest_agg_signer_state_size(const faest_paramset_t* params);

// Initialize the state for a signer at position signer_index (0-indexed) out of signer_count.
// owf_key / owf_input / owf_output are the signer's secret material; the witness is computed
// internally from owf_key & owf_input. Returns 0 on success, nonzero on error.
int faest_agg_signer_init(faest_agg_signer_state_t* state, const uint8_t* owf_key,
                          const uint8_t* owf_input, const uint8_t* owf_output,
                          size_t signer_index, size_t signer_count,
                          const faest_paramset_t* params);

// Round 1: produce msg1 = (h_com_j, iv_pre_j, c_j). Output buffer must be at least msg1_bytes.
int faest_agg_signer_round1(faest_agg_signer_state_t* state, uint8_t* msg1_out,
                            const faest_paramset_t* params);

// Round 2: consume chall_1 and the message, produce msg2 = (d_j, ũ_j, V_tilde_j[0..λ-1]).
int faest_agg_signer_round2(faest_agg_signer_state_t* state, const uint8_t* chall_1,
                            const uint8_t* msg, size_t msg_len, uint8_t* msg2_out,
                            const faest_paramset_t* params);

// Round 3: consume chall_2, produce msg3 = (a_0_j, a_1_j, a_2_j).
int faest_agg_signer_round3(faest_agg_signer_state_t* state, const uint8_t* chall_2,
                            uint8_t* msg3_out, const faest_paramset_t* params);

// Round 5: consume chall_3, produce msg5 = pdecom_j.
int faest_agg_signer_round5(faest_agg_signer_state_t* state, const uint8_t* chall_3,
                            uint8_t* msg5_out, const faest_paramset_t* params);

// Zero / free internal state.
void faest_agg_signer_clear(faest_agg_signer_state_t* state, const faest_paramset_t* params);

FAEST_END_C_DECL

#endif
