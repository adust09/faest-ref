/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "faest_agg_aggregator.h"
#include "faest_agg_layout.h"
#include "bavc_forest.h"

#include "compat.h"
#include "random_oracle.h"
#include "utils.h"

#include <stdlib.h>
#include <string.h>

// Internal state. msg1_buf, msg2_buf hold per-signer copies of the messages
// from the most recent round, needed for chall_2 derivation and for assembly
// into the final signature at finalize().
struct faest_agg_aggregator_state_t {
  size_t signer_count;
  uint16_t lambda;
  uint16_t round_state;

  // Public-key list, copied at init().
  uint8_t** owf_inputs;        // [signer_count][owf_input_size]
  uint8_t** owf_outputs;       // [signer_count][owf_output_size]

  uint8_t* msg;
  size_t msg_len;

  uint8_t mu[MAX_LAMBDA_BYTES * 2];
  uint8_t chall_1[5 * MAX_LAMBDA_BYTES + 8];
  uint8_t chall_2[3 * MAX_LAMBDA_BYTES + 8];

  // Per-signer message buffers (copied in).
  uint8_t** msg1_buf;          // [signer_count][msg1_bytes]
  uint8_t** msg2_buf;          // [signer_count][msg2_bytes]
};

size_t faest_agg_aggregator_state_size(size_t signer_count, const faest_paramset_t* params) {
  (void)signer_count;
  (void)params;
  return sizeof(struct faest_agg_aggregator_state_t);
}

static void hash_agg_mu(uint8_t* mu, const uint8_t* const* owf_inputs,
                        const uint8_t* const* owf_outputs, size_t signer_count,
                        const uint8_t* msg, size_t msglen, const faest_paramset_t* params) {
  static const uint8_t domain[] = "FAEST-AGG-MU-v1";
  const unsigned int lambda = params->lambda;

  H2_context_t ctx;
  H2_init(&ctx, lambda);
  H2_update(&ctx, domain, sizeof(domain) - 1);
  {
    uint8_t hdr[16];
    hdr[0] = (uint8_t)(params->lambda & 0xff);
    hdr[1] = (uint8_t)((params->lambda >> 8) & 0xff);
    hdr[2] = params->tau;
    hdr[3] = params->w_grind;
    hdr[4] = params->owf_input_size;
    hdr[5] = params->owf_output_size;
    for (int i = 6; i < 16; ++i) hdr[i] = 0;
    H2_update(&ctx, hdr, sizeof(hdr));
  }
  {
    uint8_t n_le[8];
    for (size_t i = 0; i < 8; ++i) {
      n_le[i] = (uint8_t)((signer_count >> (i * 8)) & 0xff);
    }
    H2_update(&ctx, n_le, sizeof(n_le));
  }
  for (size_t j = 0; j < signer_count; ++j) {
    H2_update(&ctx, owf_inputs[j], params->owf_input_size);
    H2_update(&ctx, owf_outputs[j], params->owf_output_size);
  }
  {
    uint8_t mlen_le[8];
    for (size_t i = 0; i < 8; ++i) {
      mlen_le[i] = (uint8_t)((msglen >> (i * 8)) & 0xff);
    }
    H2_update(&ctx, mlen_le, sizeof(mlen_le));
  }
  H2_update(&ctx, msg, msglen);
  H2_0_final(&ctx, mu, 2 * (lambda / 8));
}

static void hash_agg_chall_1(uint8_t* chall_1, const uint8_t* mu, const uint8_t* h_com,
                             const uint8_t* const* iv_pres, const uint8_t* const* c_blocks,
                             size_t signer_count, const faest_paramset_t* params) {
  static const uint8_t domain[] = "FAEST-AGG-CHAL1-v1";
  const unsigned int lambda = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;
  faest_agg_sizes_t sizes;
  faest_agg_compute_sizes(&sizes, params);

  H2_context_t ctx;
  H2_init(&ctx, lambda);
  H2_update(&ctx, domain, sizeof(domain) - 1);
  {
    uint8_t n_le[8];
    for (size_t i = 0; i < 8; ++i) {
      n_le[i] = (uint8_t)((signer_count >> (i * 8)) & 0xff);
    }
    H2_update(&ctx, n_le, sizeof(n_le));
  }
  H2_update(&ctx, mu, 2 * lambda_bytes);
  H2_update(&ctx, h_com, lambda_bytes);
  for (size_t j = 0; j < signer_count; ++j) {
    H2_update(&ctx, iv_pres[j], lambda_bytes);
  }
  for (size_t j = 0; j < signer_count; ++j) {
    H2_update(&ctx, c_blocks[j], sizes.c_bytes);
  }
  H2_1_final(&ctx, chall_1, 5 * lambda_bytes + 8);
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
  state->round_state  = 0;

  state->owf_inputs  = (uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  state->owf_outputs = (uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  if (!state->owf_inputs || !state->owf_outputs) {
    goto fail;
  }
  for (size_t j = 0; j < signer_count; ++j) {
    state->owf_inputs[j]  = (uint8_t*)malloc(params->owf_input_size);
    state->owf_outputs[j] = (uint8_t*)malloc(params->owf_output_size);
    if (!state->owf_inputs[j] || !state->owf_outputs[j]) {
      goto fail;
    }
    memcpy(state->owf_inputs[j], owf_inputs[j], params->owf_input_size);
    memcpy(state->owf_outputs[j], owf_outputs[j], params->owf_output_size);
  }
  if (msg_len > 0) {
    state->msg = (uint8_t*)malloc(msg_len);
    if (!state->msg) {
      goto fail;
    }
    memcpy(state->msg, msg, msg_len);
  }
  state->msg_len = msg_len;

  faest_agg_sizes_t sizes;
  if (!faest_agg_compute_sizes(&sizes, params)) {
    goto fail;
  }
  state->msg1_buf = (uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  state->msg2_buf = (uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  if (!state->msg1_buf || !state->msg2_buf) {
    goto fail;
  }
  for (size_t j = 0; j < signer_count; ++j) {
    state->msg1_buf[j] = (uint8_t*)malloc(sizes.msg1_bytes);
    state->msg2_buf[j] = (uint8_t*)malloc(sizes.msg2_bytes);
    if (!state->msg1_buf[j] || !state->msg2_buf[j]) {
      goto fail;
    }
  }

  // Compute mu now — it depends only on init-time inputs.
  hash_agg_mu(state->mu, (const uint8_t* const*)state->owf_inputs,
              (const uint8_t* const*)state->owf_outputs, signer_count, state->msg,
              state->msg_len, params);
  return 0;

fail:
  faest_agg_aggregator_clear(state, params);
  return -1;
}

int faest_agg_aggregator_round1(faest_agg_aggregator_state_t* state,
                                const uint8_t* const* msg1s, uint8_t* chall_1_out,
                                const faest_paramset_t* params) {
  if (!state || !msg1s || !chall_1_out || !params || state->round_state != 0) {
    return -1;
  }
  faest_agg_sizes_t sizes;
  if (!faest_agg_compute_sizes(&sizes, params)) {
    return -1;
  }
  const unsigned int lambda_bytes = params->lambda / 8;

  // Copy each per-signer msg1 into our buffers (for later assembly).
  for (size_t j = 0; j < state->signer_count; ++j) {
    if (!msg1s[j]) {
      return -1;
    }
    memcpy(state->msg1_buf[j], msg1s[j], sizes.msg1_bytes);
  }

  // Combine h_com.
  uint8_t** per_signer_hcom = (uint8_t**)calloc(state->signer_count, sizeof(uint8_t*));
  uint8_t** per_signer_iv_pre = (uint8_t**)calloc(state->signer_count, sizeof(uint8_t*));
  uint8_t** per_signer_c = (uint8_t**)calloc(state->signer_count, sizeof(uint8_t*));
  if (!per_signer_hcom || !per_signer_iv_pre || !per_signer_c) {
    free(per_signer_hcom); free(per_signer_iv_pre); free(per_signer_c);
    return -1;
  }
  for (size_t j = 0; j < state->signer_count; ++j) {
    per_signer_hcom[j]   = state->msg1_buf[j];
    per_signer_iv_pre[j] = state->msg1_buf[j] + sizes.hcom_bytes;
    per_signer_c[j]      = state->msg1_buf[j] + sizes.hcom_bytes + lambda_bytes;
  }

  uint8_t h_com[MAX_LAMBDA_BYTES];
  bavc_forest_combine_hcom(h_com, (const uint8_t* const*)per_signer_hcom, state->signer_count,
                           params);

  hash_agg_chall_1(state->chall_1, state->mu, h_com, (const uint8_t* const*)per_signer_iv_pre,
                   (const uint8_t* const*)per_signer_c, state->signer_count, params);

  memcpy(chall_1_out, state->chall_1, 5 * lambda_bytes + 8);

  free(per_signer_hcom); free(per_signer_iv_pre); free(per_signer_c);
  state->round_state = 1;
  return 0;
}

int faest_agg_aggregator_round2(faest_agg_aggregator_state_t* state,
                                const uint8_t* const* msg2s, uint8_t* chall_2_out,
                                const faest_paramset_t* params) {
  if (!state || !msg2s || !chall_2_out || !params || state->round_state != 1) {
    return -1;
  }
  faest_agg_sizes_t sizes;
  if (!faest_agg_compute_sizes(&sizes, params)) {
    return -1;
  }
  const unsigned int lambda = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;

  for (size_t j = 0; j < state->signer_count; ++j) {
    if (!msg2s[j]) {
      return -1;
    }
    memcpy(state->msg2_buf[j], msg2s[j], sizes.msg2_bytes);
  }

  // chall_2 = H(chall_1, {ũ_j}, {V_tilde_j}, {d_j}). For n=1, ũ_agg == ũ_1 and
  // V_tilde_agg[i] == V_tilde_1[i]. For n>1, an additional chall_1-power
  // combination is folded in here; Phase 2B will implement the GF(2^λ)
  // multiplications. For now we feed the raw per-signer values into the hash
  // in a deterministic order, which gives a valid (though not yet O(1)-in-σ_agg)
  // chall_2 binding.
  H2_context_t ctx;
  H2_init(&ctx, lambda);
  H2_update(&ctx, state->chall_1, 5 * lambda_bytes + 8);
  for (size_t j = 0; j < state->signer_count; ++j) {
    const uint8_t* d_j       = state->msg2_buf[j];
    const uint8_t* u_tilde_j = d_j + sizes.ell_bytes;
    const uint8_t* v_tilde_j = u_tilde_j + sizes.u_tilde_bytes;
    H2_update(&ctx, u_tilde_j, sizes.u_tilde_bytes);
    H2_update(&ctx, v_tilde_j, lambda * sizes.v_tilde_row_bytes);
    H2_update(&ctx, d_j, sizes.ell_bytes);
  }
  H2_2_final(&ctx, state->chall_2, 3 * lambda_bytes + 8);
  memcpy(chall_2_out, state->chall_2, 3 * lambda_bytes + 8);

  state->round_state = 2;
  return 0;
}

int faest_agg_aggregator_round3(faest_agg_aggregator_state_t* state,
                                const uint8_t* const* msg3s,
                                const faest_paramset_t* params) {
  (void)msg3s;
  if (!state || !params || state->round_state != 2) {
    return -1;
  }
  return -1;
}

int faest_agg_aggregator_round4(faest_agg_aggregator_state_t* state, uint8_t* chall_3_out,
                                uint32_t* ctr_out, const faest_paramset_t* params) {
  (void)chall_3_out; (void)ctr_out;
  if (!state || !params || state->round_state != 3) {
    return -1;
  }
  return -1;
}

int faest_agg_aggregator_finalize(faest_agg_aggregator_state_t* state,
                                  const uint8_t* const* msg5s, uint8_t* signature,
                                  size_t* signature_len, const faest_paramset_t* params) {
  (void)msg5s; (void)signature; (void)signature_len;
  if (!state || !params) {
    return -1;
  }
  return -1;
}

void faest_agg_aggregator_clear(faest_agg_aggregator_state_t* state,
                                const faest_paramset_t* params) {
  (void)params;
  if (!state) {
    return;
  }
  if (state->owf_inputs) {
    for (size_t j = 0; j < state->signer_count; ++j) {
      free(state->owf_inputs[j]);
    }
    free(state->owf_inputs);
  }
  if (state->owf_outputs) {
    for (size_t j = 0; j < state->signer_count; ++j) {
      free(state->owf_outputs[j]);
    }
    free(state->owf_outputs);
  }
  if (state->msg) {
    free(state->msg);
  }
  if (state->msg1_buf) {
    for (size_t j = 0; j < state->signer_count; ++j) {
      free(state->msg1_buf[j]);
    }
    free(state->msg1_buf);
  }
  if (state->msg2_buf) {
    for (size_t j = 0; j < state->signer_count; ++j) {
      free(state->msg2_buf[j]);
    }
    free(state->msg2_buf);
  }
  faest_explicit_bzero(state, sizeof(*state));
}
