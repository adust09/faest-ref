/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "faest_agg_signer.h"
#include "faest_agg_layout.h"

#include "aes.h"
#include "bavc.h"
#include "compat.h"
#include "faest_aes.h"
#include "randomness.h"
#include "random_oracle.h"
#include "utils.h"
#include "vole.h"
#include "universal_hashing.h"

#include <stdlib.h>
#include <string.h>

static inline void aes_prove_dispatch(uint8_t* a0, uint8_t* a1, uint8_t* a2, const uint8_t* w,
                                      const uint8_t* u, uint8_t** V, const uint8_t* owf_in,
                                      const uint8_t* owf_out, const uint8_t* chall_2,
                                      const faest_paramset_t* params) {
  switch (params->lambda) {
  case 256:
    aes_256_prover(a0, a1, a2, w, u, V, owf_in, owf_out, chall_2, params);
    break;
  case 192:
    aes_192_prover(a0, a1, a2, w, u, V, owf_in, owf_out, chall_2, params);
    break;
  default:
    aes_128_prover(a0, a1, a2, w, u, V, owf_in, owf_out, chall_2, params);
  }
}

// Internal state. Inline-sized fields use MAX_LAMBDA bounds; large per-VOLE
// buffers (witness, u, V) are heap-allocated in round1 and freed in clear.
struct faest_agg_signer_state_t {
  size_t signer_index;
  size_t signer_count;
  uint16_t lambda;
  uint16_t round_state; // 0=init, 1=after R1, 2=after R2, 3=after R3

  uint8_t owf_key[MAX_LAMBDA_BYTES];
  uint8_t owf_input[32];
  uint8_t owf_output[32];

  uint8_t iv_pre[MAX_LAMBDA_BYTES];
  uint8_t iv[IV_SIZE];

  uint8_t chall_1[5 * MAX_LAMBDA_BYTES + 8];
  uint8_t chall_2[3 * MAX_LAMBDA_BYTES + 8];
  uint8_t chall_3[MAX_LAMBDA_BYTES];

  // dynamically allocated in round1, freed in clear
  uint8_t* witness;     // ell / 8 bytes
  uint8_t* u;           // ell_hat / 8 bytes
  uint8_t** V;          // [lambda][ell_hat / 8]
  bavc_t bavc;
  uint8_t bavc_live;
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
  if (params->owf_input_size > sizeof(state->owf_input) ||
      params->owf_output_size > sizeof(state->owf_output) ||
      params->lambda / 8 > sizeof(state->owf_key)) {
    return -1;
  }

  memset(state, 0, sizeof(*state));
  state->signer_index = signer_index;
  state->signer_count = signer_count;
  state->lambda       = params->lambda;
  state->round_state  = 0;

  memcpy(state->owf_key, owf_key, params->lambda / 8);
  memcpy(state->owf_input, owf_input, params->owf_input_size);
  memcpy(state->owf_output, owf_output, params->owf_output_size);
  return 0;
}

// R1: vole_commit, output (h_com_j, iv_pre_j, c_j).
int faest_agg_signer_round1(faest_agg_signer_state_t* state, uint8_t* msg1_out,
                            const faest_paramset_t* params) {
  if (!state || !msg1_out || !params || state->round_state != 0) {
    return -1;
  }

  faest_agg_sizes_t sizes;
  if (!faest_agg_compute_sizes(&sizes, params)) {
    return -1;
  }

  const unsigned int lambda       = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int ell_bytes    = sizes.ell_bytes;
  const unsigned int ell_hat      = (unsigned int)sizes.ell_hat;
  const unsigned int ell_hat_bytes = (unsigned int)sizes.ell_hat_bytes;

  // Compute witness from sk.
  state->witness = (uint8_t*)malloc(ell_bytes);
  if (!state->witness) {
    return -1;
  }
  aes_extend_witness(state->witness, state->owf_key, state->owf_input, params);

  // Sample root seed and iv_pre. The aggregator-side derivation of rootkey
  // requires per-signer iv_pre, so we sample it locally.
  uint8_t rootkey[MAX_LAMBDA_BYTES];
  rand_bytes(rootkey, lambda_bytes);
  rand_bytes(state->iv_pre, lambda_bytes);
  H4(state->iv, state->iv_pre, lambda);

  // Allocate u and V.
  state->u = (uint8_t*)malloc(ell_hat_bytes);
  state->V = (uint8_t**)malloc(lambda * sizeof(uint8_t*));
  if (!state->u || !state->V) {
    free(state->witness);
    state->witness = NULL;
    free(state->u);
    state->u = NULL;
    free(state->V);
    state->V = NULL;
    return -1;
  }
  state->V[0] = (uint8_t*)calloc(lambda, ell_hat_bytes);
  if (!state->V[0]) {
    free(state->witness);
    state->witness = NULL;
    free(state->u);
    state->u = NULL;
    free(state->V);
    state->V = NULL;
    return -1;
  }
  for (unsigned int i = 1; i < lambda; ++i) {
    state->V[i] = state->V[0] + i * ell_hat_bytes;
  }

  // c_j lives directly inside the output buffer to avoid copies.
  uint8_t* c_out = msg1_out + sizes.hcom_bytes + lambda_bytes;
  vole_commit(rootkey, state->iv, ell_hat, params, &state->bavc, c_out, state->u, state->V);
  state->bavc_live = 1;

  // h_com_j = bavc.h
  memcpy(msg1_out, state->bavc.h, sizes.hcom_bytes);
  // iv_pre_j
  memcpy(msg1_out + sizes.hcom_bytes, state->iv_pre, lambda_bytes);

  faest_explicit_bzero(rootkey, sizeof(rootkey));
  state->round_state = 1;
  return 0;
}

// R2: consume chall_1, output (d_j, ũ_j, V_tilde_j[0..λ-1]).
int faest_agg_signer_round2(faest_agg_signer_state_t* state, const uint8_t* chall_1,
                            const uint8_t* msg, size_t msg_len, uint8_t* msg2_out,
                            const faest_paramset_t* params) {
  (void)msg; (void)msg_len;
  if (!state || !chall_1 || !msg2_out || !params || state->round_state != 1) {
    return -1;
  }

  faest_agg_sizes_t sizes;
  if (!faest_agg_compute_sizes(&sizes, params)) {
    return -1;
  }

  const unsigned int lambda = params->lambda;
  const unsigned int ell    = params->l;

  // Save chall_1 for later rounds.
  memcpy(state->chall_1, chall_1, 5 * (lambda / 8) + 8);

  // d_j = w_j ⊕ u_j (first ell bytes of u).
  uint8_t* d_out = msg2_out;
  xor_u8_array(state->witness, state->u, d_out, sizes.ell_bytes);

  // ũ_j = vole_hash(chall_1, u_j, ell, lambda)
  uint8_t* u_tilde_out = d_out + sizes.ell_bytes;
  vole_hash(u_tilde_out, chall_1, state->u, ell, lambda);

  // V_tilde_j[i] for i in 0..lambda-1
  uint8_t* v_tilde_out = u_tilde_out + sizes.u_tilde_bytes;
  for (unsigned int i = 0; i < lambda; ++i) {
    vole_hash(v_tilde_out + i * sizes.v_tilde_row_bytes, chall_1, state->V[i], ell, lambda);
  }

  state->round_state = 2;
  return 0;
}

// R3: chall_2-weighted polynomial coefficients via aes_<λ>_prover.
int faest_agg_signer_round3(faest_agg_signer_state_t* state, const uint8_t* chall_2,
                            uint8_t* msg3_out, const faest_paramset_t* params) {
  if (!state || !chall_2 || !msg3_out || !params || state->round_state != 2) {
    return -1;
  }
  const unsigned int lambda       = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;

  memcpy(state->chall_2, chall_2, 3 * lambda_bytes + 8);

  faest_agg_sizes_t sizes;
  if (!faest_agg_compute_sizes(&sizes, params)) {
    return -1;
  }

  uint8_t* a0_out = msg3_out;
  uint8_t* a1_out = msg3_out + lambda_bytes;
  uint8_t* a2_out = msg3_out + 2 * lambda_bytes;
  aes_prove_dispatch(a0_out, a1_out, a2_out, state->witness, state->u + sizes.ell_bytes, state->V,
                     state->owf_input, state->owf_output, chall_2, params);

  state->round_state = 3;
  return 0;
}

// R5: decode chall_3, run bavc_open against this signer's subtree.
int faest_agg_signer_round5(faest_agg_signer_state_t* state, const uint8_t* chall_3,
                            uint8_t* msg5_out, const faest_paramset_t* params) {
  if (!state || !chall_3 || !msg5_out || !params || state->round_state != 3) {
    return -1;
  }
  const unsigned int lambda_bytes = params->lambda / 8;
  memcpy(state->chall_3, chall_3, lambda_bytes);

  uint16_t decoded[MAX_TAU];
  if (!decode_all_chall_3(decoded, chall_3, params)) {
    return -1;
  }
  if (!bavc_open(msg5_out, &state->bavc, decoded, params)) {
    return -1;
  }
  state->round_state = 5;
  return 0;
}

void faest_agg_signer_clear(faest_agg_signer_state_t* state, const faest_paramset_t* params) {
  (void)params;
  if (!state) {
    return;
  }
  if (state->witness) {
    faest_explicit_bzero(state->witness, params ? (params->l / 8) : 0);
    free(state->witness);
  }
  if (state->u) {
    free(state->u);
  }
  if (state->V) {
    if (state->V[0]) {
      free(state->V[0]);
    }
    free(state->V);
  }
  if (state->bavc_live) {
    bavc_clear(&state->bavc);
  }
  faest_explicit_bzero(state, sizeof(*state));
}

