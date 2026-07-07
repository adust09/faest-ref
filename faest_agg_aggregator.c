/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "faest_agg_aggregator.h"
#include "faest_agg_layout.h"
#include "bavc_forest.h"

#include "bavc.h"
#include "compat.h"
#include "random_oracle.h"
#include "utils.h"
#include "universal_hashing.h"

#include <stdlib.h>
#include <string.h>

struct faest_agg_aggregator_state_t {
  size_t signer_count;
  uint16_t lambda;
  uint16_t round_state; // 0=init, 1=after R1, 2=R2, 3=R3, 4=R4, 5=finalized

  // Public-key list, copied at init().
  uint8_t** owf_inputs;        // [signer_count][owf_input_size]
  uint8_t** owf_outputs;       // [signer_count][owf_output_size]

  uint8_t* msg;
  size_t msg_len;

  uint8_t mu[MAX_LAMBDA_BYTES * 2];
  uint8_t chall_1[5 * MAX_LAMBDA_BYTES + 8];
  uint8_t chall_2[3 * MAX_LAMBDA_BYTES + 8];
  uint8_t chall_3[MAX_LAMBDA_BYTES];
  uint32_t ctr;

  // Combined / aggregated values.
  uint8_t h_com[MAX_LAMBDA_BYTES];
  uint8_t u_tilde_agg[MAX_LAMBDA_BYTES + UNIVERSAL_HASH_B];
  uint8_t a0_agg[MAX_LAMBDA_BYTES];
  uint8_t a1_agg[MAX_LAMBDA_BYTES];
  uint8_t a2_agg[MAX_LAMBDA_BYTES];

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

  for (size_t j = 0; j < state->signer_count; ++j) {
    if (!msg1s[j]) {
      return -1;
    }
    memcpy(state->msg1_buf[j], msg1s[j], sizes.msg1_bytes);
  }

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

  bavc_forest_combine_hcom(state->h_com, (const uint8_t* const*)per_signer_hcom,
                           state->signer_count, params);

  hash_agg_chall_1(state->chall_1, state->mu, state->h_com,
                   (const uint8_t* const*)per_signer_iv_pre,
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

  // Combine per-signer ũ_j into ũ_agg via XOR, and V_tilde_j[i] into
  // V_tilde_agg[i] via XOR. The XOR-combine is linear and preserves the
  // verifier's reconstruction identity
  //   V_tilde_agg[i] = (XOR_j Q_tilde_j[i]) XOR (chall_3_bit_i · ũ_agg)
  // because vole_hash is linear in its data input. Each signer's ũ_j /
  // V_tilde_j is already pinned by the BAVC commitment bound into chall_1, so
  // a collusion that cancels contributions in the XOR is no easier than a
  // BAVC opening collision.
  memset(state->u_tilde_agg, 0, sizes.u_tilde_bytes);
  for (size_t j = 0; j < state->signer_count; ++j) {
    xor_u8_array(state->u_tilde_agg, state->msg2_buf[j] + sizes.ell_bytes, state->u_tilde_agg,
                 sizes.u_tilde_bytes);
  }

  H2_context_t ctx;
  H2_init(&ctx, lambda);
  H2_update(&ctx, state->chall_1, 5 * lambda_bytes + 8);
  H2_update(&ctx, state->u_tilde_agg, sizes.u_tilde_bytes);

  // V_tilde_agg[i] = XOR_j V_tilde_j[i], hashed row-by-row.
  {
    uint8_t v_tilde_agg_row[MAX_LAMBDA_BYTES + UNIVERSAL_HASH_B];
    for (unsigned int i = 0; i < lambda; ++i) {
      memset(v_tilde_agg_row, 0, sizes.v_tilde_row_bytes);
      for (size_t j = 0; j < state->signer_count; ++j) {
        const uint8_t* v_tilde_j_i = state->msg2_buf[j] + sizes.ell_bytes + sizes.u_tilde_bytes +
                                     i * sizes.v_tilde_row_bytes;
        xor_u8_array(v_tilde_agg_row, v_tilde_j_i, v_tilde_agg_row, sizes.v_tilde_row_bytes);
      }
      H2_update(&ctx, v_tilde_agg_row, sizes.v_tilde_row_bytes);
    }
  }

  // Then {d_j} for j = 0..n-1.
  for (size_t j = 0; j < state->signer_count; ++j) {
    H2_update(&ctx, state->msg2_buf[j], sizes.ell_bytes);
  }
  H2_2_final(&ctx, state->chall_2, 3 * lambda_bytes + 8);
  memcpy(chall_2_out, state->chall_2, 3 * lambda_bytes + 8);

  state->round_state = 2;
  return 0;
}

int faest_agg_aggregator_round3(faest_agg_aggregator_state_t* state,
                                const uint8_t* const* msg3s,
                                const faest_paramset_t* params) {
  if (!state || !msg3s || !params || state->round_state != 2) {
    return -1;
  }
  const unsigned int lambda_bytes = params->lambda / 8;

  memset(state->a0_agg, 0, lambda_bytes);
  memset(state->a1_agg, 0, lambda_bytes);
  memset(state->a2_agg, 0, lambda_bytes);
  for (size_t j = 0; j < state->signer_count; ++j) {
    if (!msg3s[j]) {
      return -1;
    }
    xor_u8_array(state->a0_agg, msg3s[j], state->a0_agg, lambda_bytes);
    xor_u8_array(state->a1_agg, msg3s[j] + lambda_bytes, state->a1_agg, lambda_bytes);
    xor_u8_array(state->a2_agg, msg3s[j] + 2 * lambda_bytes, state->a2_agg, lambda_bytes);
  }
  state->round_state = 3;
  return 0;
}

// Mirror of bavc.c::pos_in_tree (static inline there). Determines whether a
// given chall_3-decoded i_delta vector produces an opening that fits in
// T_open. Since this depends only on tree structure (not on seeds), the
// aggregator can grind without any signer's BAVC state.
static unsigned int agg_pos_in_tree(unsigned int i, unsigned int j,
                                    const faest_paramset_t* params) {
  const unsigned int tmp = 1u << (params->k - 1u);
  if (j < tmp) {
    return params->L - 1u + params->tau * j + i;
  }
  const unsigned int mask = tmp - 1u;
  return params->L - 1u + params->tau * tmp + params->tau1 * (j & mask) + i;
}

static bool agg_bavc_open_predicate(const uint16_t* i_delta, const faest_paramset_t* params) {
  const unsigned int tau = params->tau;
  const unsigned int L   = params->L;

  uint8_t* s = (uint8_t*)calloc((2u * L - 1u + 7u) / 8u, 1);
  if (!s) {
    return false;
  }
  unsigned int nh = 0;
  for (unsigned int i = 0; i < tau; ++i) {
    unsigned int alpha = agg_pos_in_tree(i, i_delta[i], params);
    if ((s[alpha / 8] >> (alpha % 8)) & 1) {
      // Already marked — duplicate position. Should not happen with valid input.
    } else {
      s[alpha / 8] |= (uint8_t)(1u << (alpha % 8));
      ++nh;
    }
    while (alpha > 0) {
      const unsigned int parent = (alpha - 1u) / 2u;
      if ((s[parent / 8] >> (parent % 8)) & 1) {
        break;
      }
      alpha = parent;
      s[alpha / 8] |= (uint8_t)(1u << (alpha % 8));
      ++nh;
    }
  }
  free(s);
  return (nh >= 2u * tau - 1u) && ((nh - 2u * tau + 1u) <= params->T_open);
}

static inline bool agg_check_challenge_3(const uint8_t* chall_3, unsigned int start,
                                         unsigned int lambda) {
  const unsigned int lambda_bytes = lambda / 8;
  uint8_t res = (start % 8) ? (chall_3[start / 8] >> (start % 8)) : 0;
  for (unsigned int bytes = (start + 7) / 8; bytes != lambda_bytes; ++bytes) {
    res |= chall_3[bytes];
  }
  return !res;
}

int faest_agg_aggregator_round4(faest_agg_aggregator_state_t* state, uint8_t* chall_3_out,
                                uint32_t* ctr_out, const faest_paramset_t* params) {
  if (!state || !chall_3_out || !ctr_out || !params || state->round_state != 3) {
    return -1;
  }
  const unsigned int lambda       = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int w_grind      = params->w_grind;

  // Pre-init H(chall_2 || a0_agg || a1_agg || a2_agg) so we only stir ctr per
  // attempt.
  H2_context_t prefix;
  H2_init(&prefix, lambda);
  H2_update(&prefix, state->chall_2, 3 * lambda_bytes + 8);
  H2_update(&prefix, state->a0_agg, lambda_bytes);
  H2_update(&prefix, state->a1_agg, lambda_bytes);
  H2_update(&prefix, state->a2_agg, lambda_bytes);

  uint32_t ctr = 0;
  for (;; ++ctr) {
    H2_context_t attempt;
    H2_copy(&attempt, &prefix);
    H2_update_u32_le(&attempt, ctr);
    H2_3_final(&attempt, state->chall_3, lambda_bytes);

    if (!agg_check_challenge_3(state->chall_3, lambda - w_grind, lambda)) {
      continue;
    }
    uint16_t decoded[MAX_TAU];
    if (!decode_all_chall_3(decoded, state->chall_3, params)) {
      continue;
    }
    if (!agg_bavc_open_predicate(decoded, params)) {
      continue;
    }
    break;
  }

  state->ctr = ctr;
  memcpy(chall_3_out, state->chall_3, lambda_bytes);
  *ctr_out = ctr;
  state->round_state = 4;
  return 0;
}

int faest_agg_aggregator_finalize(faest_agg_aggregator_state_t* state,
                                  const uint8_t* const* msg5s, uint8_t* signature,
                                  size_t* signature_len, const faest_paramset_t* params) {
  if (!state || !msg5s || !signature || !signature_len || !params || state->round_state != 4) {
    return -1;
  }

  faest_agg_signature_layout_t layout;
  if (!faest_agg_compute_signature_layout(&layout, state->signer_count, params)) {
    return -1;
  }
  if (*signature_len < layout.total_bytes) {
    *signature_len = layout.total_bytes;
    return -1;
  }
  const unsigned int lambda_bytes = params->lambda / 8;

  memcpy(faest_agg_sig_hcom(signature, &layout), state->h_com, layout.sizes.hcom_bytes);
  memcpy(faest_agg_sig_u_tilde_agg(signature, &layout), state->u_tilde_agg,
         layout.sizes.u_tilde_bytes);
  memcpy(faest_agg_sig_a1(signature, &layout), state->a1_agg, lambda_bytes);
  memcpy(faest_agg_sig_a2(signature, &layout), state->a2_agg, lambda_bytes);
  memcpy(faest_agg_sig_chall_3(signature, &layout), state->chall_3, lambda_bytes);

  uint32_t ctr_le = htole32(state->ctr);
  memcpy(faest_agg_sig_ctr(signature, &layout), &ctr_le, sizeof(ctr_le));

  for (size_t j = 0; j < state->signer_count; ++j) {
    if (!msg5s[j]) {
      return -1;
    }
    memcpy(faest_agg_sig_iv_pre(signature, &layout, j),
           state->msg1_buf[j] + layout.sizes.hcom_bytes, lambda_bytes);
    memcpy(faest_agg_sig_c(signature, &layout, j),
           state->msg1_buf[j] + layout.sizes.hcom_bytes + lambda_bytes, layout.sizes.c_bytes);
    memcpy(faest_agg_sig_d(signature, &layout, j), state->msg2_buf[j], layout.sizes.ell_bytes);
    memcpy(faest_agg_sig_pdecom(signature, &layout, j), msg5s[j], layout.sizes.pdecom_bytes);
  }

  *signature_len = layout.total_bytes;
  state->round_state = 5;
  return 0;
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
