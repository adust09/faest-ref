/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef FAEST_IMPL_H
#define FAEST_IMPL_H

#include <stdint.h>
#include <stddef.h>

#include "instances.h"

void faest_sign(uint8_t* sig, const uint8_t* msg, size_t msglen, const uint8_t* owf_key,
                const uint8_t* owf_input, const uint8_t* owf_output, const uint8_t* witness,
                const uint8_t* rho, size_t rholen, const faest_paramset_t* params);

int faest_verify(const uint8_t* msg, size_t msglen, const uint8_t* sig, const uint8_t* owf_input,
                 const uint8_t* owf_output, const faest_paramset_t* params);

// Aggregate (5-round multi-signer) verification.
// signature was produced by faest_agg_aggregator_finalize().
// owf_inputs[j] / owf_outputs[j] are the per-signer public keys, in the same order they were
// passed to faest_agg_aggregator_init.
int faest_aggregate_verify(const uint8_t* msg, size_t msg_len, const uint8_t* sig,
                           size_t sig_len, const uint8_t* const* owf_inputs,
                           const uint8_t* const* owf_outputs, size_t signer_count,
                           const faest_paramset_t* params);

// Aggregate signature byte length for a given signer count and parameter set.
// Returns 0 if signer_count is invalid (= 0 or overflows internal layout math).
size_t faest_aggregate_signature_size(size_t signer_count, const faest_paramset_t* params);

#endif
