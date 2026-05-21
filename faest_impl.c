/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "faest_impl.h"
#include "aes.h"
#include "bavc_forest.h"
#include "faest_agg_layout.h"
#include "faest_aes.h"
#include "fields.h"
#include "randomness.h"
#include "random_oracle.h"
#include "utils.h"
#include "vole.h"
#include "universal_hashing.h"

#include <string.h>

// helpers to compute position in signature (sign)

ATTR_PURE static inline uint8_t* signature_c(uint8_t* base_ptr, unsigned int index,
                                             const faest_paramset_t* params) {
  const unsigned int lambda_bytes  = params->lambda / 8;
  const unsigned int ell_bytes     = params->l / 8;
  const unsigned int ell_hat_bytes = ell_bytes + 3 * lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + index * ell_hat_bytes;
}

ATTR_PURE static inline uint8_t* signature_u_tilde(uint8_t* base_ptr,
                                                   const faest_paramset_t* params) {
  const unsigned int lambda_bytes  = params->lambda / 8;
  const unsigned int ell_bytes     = params->l / 8;
  const unsigned int ell_hat_bytes = ell_bytes + 3 * lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + (params->tau - 1) * ell_hat_bytes;
}

ATTR_PURE static inline uint8_t* signature_d(uint8_t* base_ptr, const faest_paramset_t* params) {
  const unsigned int lambda_bytes  = params->lambda / 8;
  const unsigned int ell_bytes     = params->l / 8;
  const unsigned int ell_hat_bytes = ell_bytes + 3 * lambda_bytes + UNIVERSAL_HASH_B;
  const unsigned int utilde_bytes  = lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + (params->tau - 1) * ell_hat_bytes + utilde_bytes;
}

ATTR_PURE static inline uint8_t* signature_a1_tilde(uint8_t* base_ptr,
                                                    const faest_paramset_t* params) {
  const unsigned int lambda_bytes  = params->lambda / 8;
  const unsigned int ell_bytes     = params->l / 8;
  const unsigned int ell_hat_bytes = ell_bytes + 3 * lambda_bytes + UNIVERSAL_HASH_B;
  const unsigned int utilde_bytes  = lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + (params->tau - 1) * ell_hat_bytes + utilde_bytes + ell_bytes;
}

ATTR_PURE static inline uint8_t* signature_a2_tilde(uint8_t* base_ptr,
                                                    const faest_paramset_t* params) {
  const unsigned int lambda_bytes  = params->lambda / 8;
  const unsigned int ell_bytes     = params->l / 8;
  const unsigned int ell_hat_bytes = ell_bytes + 3 * lambda_bytes + UNIVERSAL_HASH_B;
  const unsigned int utilde_bytes  = lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + (params->tau - 1) * ell_hat_bytes + utilde_bytes + ell_bytes + lambda_bytes;
}

ATTR_PURE static inline uint8_t* signature_decom_i(uint8_t* base_ptr,
                                                   const faest_paramset_t* params) {
  const unsigned int lambda_bytes  = params->lambda / 8;
  const unsigned int ell_bytes     = params->l / 8;
  const unsigned int ell_hat_bytes = ell_bytes + 3 * lambda_bytes + UNIVERSAL_HASH_B;
  const unsigned int utilde_bytes  = lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + (params->tau - 1) * ell_hat_bytes + utilde_bytes + ell_bytes + 2 * lambda_bytes;
}

ATTR_PURE static inline uint8_t* signature_chall_3(uint8_t* base_ptr,
                                                   const faest_paramset_t* params) {
  const unsigned int lambda_bytes = params->lambda / 8;
  return base_ptr + params->sig_size - sizeof(uint32_t) - IV_SIZE - lambda_bytes;
}

ATTR_PURE static inline uint8_t* signature_iv_pre(uint8_t* base_ptr,
                                                  const faest_paramset_t* params) {
  return base_ptr + params->sig_size - sizeof(uint32_t) - IV_SIZE;
}

ATTR_PURE static inline uint8_t* signature_ctr(uint8_t* base_ptr, const faest_paramset_t* params) {
  return base_ptr + params->sig_size - sizeof(uint32_t);
}

// helpers to compute position in signature (verify)

ATTR_PURE static inline const uint8_t* dsignature_c(const uint8_t* base_ptr, unsigned int index,
                                                    const faest_paramset_t* params) {
  const unsigned int lambda_bytes  = params->lambda / 8;
  const unsigned int ell_bytes     = params->l / 8;
  const unsigned int ell_hat_bytes = ell_bytes + 3 * lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + index * ell_hat_bytes;
}

ATTR_PURE static inline const uint8_t* dsignature_u_tilde(const uint8_t* base_ptr,
                                                          const faest_paramset_t* params) {
  const unsigned int lambda_bytes  = params->lambda / 8;
  const unsigned int ell_bytes     = params->l / 8;
  const unsigned int ell_hat_bytes = ell_bytes + 3 * lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + (params->tau - 1) * ell_hat_bytes;
}

ATTR_PURE static inline const uint8_t* dsignature_d(const uint8_t* base_ptr,
                                                    const faest_paramset_t* params) {
  const unsigned int lambda_bytes  = params->lambda / 8;
  const unsigned int ell_bytes     = params->l / 8;
  const unsigned int ell_hat_bytes = ell_bytes + 3 * lambda_bytes + UNIVERSAL_HASH_B;
  const unsigned int utilde_bytes  = lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + (params->tau - 1) * ell_hat_bytes + utilde_bytes;
}

ATTR_PURE static inline const uint8_t* dsignature_a1_tilde(const uint8_t* base_ptr,
                                                           const faest_paramset_t* params) {
  const unsigned int lambda_bytes  = params->lambda / 8;
  const unsigned int ell_bytes     = params->l / 8;
  const unsigned int ell_hat_bytes = ell_bytes + 3 * lambda_bytes + UNIVERSAL_HASH_B;
  const unsigned int utilde_bytes  = lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + (params->tau - 1) * ell_hat_bytes + utilde_bytes + ell_bytes;
}

ATTR_PURE static inline const uint8_t* dsignature_a2_tilde(const uint8_t* base_ptr,
                                                           const faest_paramset_t* params) {
  const unsigned int lambda_bytes  = params->lambda / 8;
  const unsigned int ell_bytes     = params->l / 8;
  const unsigned int ell_hat_bytes = ell_bytes + 3 * lambda_bytes + UNIVERSAL_HASH_B;
  const unsigned int utilde_bytes  = lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + (params->tau - 1) * ell_hat_bytes + utilde_bytes + ell_bytes + lambda_bytes;
}

ATTR_PURE static inline const uint8_t* dsignature_decom_i(const uint8_t* base_ptr,
                                                          const faest_paramset_t* params) {
  const unsigned int lambda_bytes  = params->lambda / 8;
  const unsigned int ell_bytes     = params->l / 8;
  const unsigned int ell_hat_bytes = ell_bytes + 3 * lambda_bytes + UNIVERSAL_HASH_B;
  const unsigned int utilde_bytes  = lambda_bytes + UNIVERSAL_HASH_B;

  return base_ptr + (params->tau - 1) * ell_hat_bytes + utilde_bytes + ell_bytes + 2 * lambda_bytes;
}

ATTR_PURE static inline const uint8_t* dsignature_chall_3(const uint8_t* base_ptr,
                                                          const faest_paramset_t* params) {
  const unsigned int lambda_bytes = params->lambda / 8;
  return base_ptr + params->sig_size - sizeof(uint32_t) - IV_SIZE - lambda_bytes;
}

ATTR_PURE static inline const uint8_t* dsignature_iv_pre(const uint8_t* base_ptr,
                                                         const faest_paramset_t* params) {
  return base_ptr + params->sig_size - sizeof(uint32_t) - IV_SIZE;
}

ATTR_PURE static inline const uint8_t* dsignature_ctr(const uint8_t* base_ptr,
                                                      const faest_paramset_t* params) {
  return base_ptr + params->sig_size - sizeof(uint32_t);
}

// FAEST.Sign: line 3
static void hash_mu(uint8_t* mu, const uint8_t* owf_input, size_t owf_input_size,
                    const uint8_t* owf_output, size_t owf_output_size, const uint8_t* msg,
                    size_t msglen, unsigned int lambda) {
  H2_context_t h1_ctx;
  H2_init(&h1_ctx, lambda);
  H2_update(&h1_ctx, owf_input, owf_input_size);
  H2_update(&h1_ctx, owf_output, owf_output_size);
  H2_update(&h1_ctx, msg, msglen);
  H2_0_final(&h1_ctx, mu, 2 * lambda / 8);
}

ATTR_ALWAYS_INLINE ATTR_ARTIFICIAL static inline void hash_iv(uint8_t* iv, const uint8_t* iv_pre,
                                                              unsigned int lambda) {
  H4(iv, iv_pre, lambda);
}

// FAEST.Sign: line 4 + line 5
static void hash_r_iv(uint8_t* root_key, uint8_t* iv_pre, uint8_t* iv, const uint8_t* owf_key,
                      const uint8_t* mu, const uint8_t* rho, size_t rho_size, unsigned int lambda) {
  const unsigned int lambda_bytes = lambda / 8;

  {
    H3_context_t h3_ctx;
    H3_init(&h3_ctx, lambda);
    H3_update(&h3_ctx, owf_key, lambda_bytes);
    H3_update(&h3_ctx, mu, lambda_bytes * 2);
    if (rho && rho_size) {
      H3_update(&h3_ctx, rho, rho_size);
    }
    H3_final(&h3_ctx, root_key, lambda_bytes, iv_pre);
  }

  hash_iv(iv, iv_pre, lambda);
}

static void hash_challenge_1(uint8_t* chall_1, const uint8_t* mu, const uint8_t* hcom,
                             const uint8_t* c, const uint8_t* iv, unsigned int lambda,
                             unsigned int ell, unsigned int tau) {
  const unsigned int lambda_bytes  = lambda / 8;
  const unsigned int ell_hat_bytes = ell / 8 + lambda_bytes * 3 + UNIVERSAL_HASH_B;

  H2_context_t h2_ctx;
  H2_init(&h2_ctx, lambda);
  H2_update(&h2_ctx, mu, lambda_bytes * 2);
  H2_update(&h2_ctx, hcom, lambda_bytes * 2);
  H2_update(&h2_ctx, c, ell_hat_bytes * (tau - 1));
  H2_update(&h2_ctx, iv, IV_SIZE);
  H2_1_final(&h2_ctx, chall_1, 5 * lambda_bytes + 8);
}

static void hash_challenge_2_init(H2_context_t* h2_ctx, const uint8_t* chall_1,
                                  const uint8_t* u_tilde, unsigned int lambda) {
  const unsigned int lambda_bytes  = lambda / 8;
  const unsigned int u_tilde_bytes = lambda_bytes + UNIVERSAL_HASH_B;

  H2_init(h2_ctx, lambda);
  H2_update(h2_ctx, chall_1, 5 * lambda_bytes + 8);
  H2_update(h2_ctx, u_tilde, u_tilde_bytes);
}

static void hash_challenge_2_update_v_tilde(H2_context_t* h2_ctx, const uint8_t* v_tilde,
                                            unsigned int lambda) {
  const unsigned int lambda_bytes  = lambda / 8;
  const unsigned int v_tilde_bytes = lambda_bytes + UNIVERSAL_HASH_B;

  H2_update(h2_ctx, v_tilde, v_tilde_bytes);
}

static void hash_challenge_2_finalize(uint8_t* chall_2, H2_context_t* h2_ctx, const uint8_t* d,
                                      const unsigned lambda, unsigned int ell) {
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int ell_bytes    = ell / 8;

  H2_update(h2_ctx, d, ell_bytes);
  H2_2_final(h2_ctx, chall_2, 3 * lambda_bytes + 8);
}

static void hash_challenge_3_init(H2_context_t* h2_ctx, const uint8_t* chall_2,
                                  const uint8_t* a0_tilde, const uint8_t* a1_tilde,
                                  const uint8_t* a2_tilde, unsigned int lambda) {
  const unsigned int lambda_bytes = lambda / 8;

  H2_init(h2_ctx, lambda);
  H2_update(h2_ctx, chall_2, 3 * lambda_bytes + 8);
  H2_update(h2_ctx, a0_tilde, lambda_bytes);
  H2_update(h2_ctx, a1_tilde, lambda_bytes);
  H2_update(h2_ctx, a2_tilde, lambda_bytes);
}

static void hash_challenge_3_final(uint8_t* chall_3, const H2_context_t* ctx, uint32_t ctr,
                                   unsigned int lambda) {
  const unsigned int lambda_bytes = lambda / 8;

  H2_context_t ctx_copy;
  H2_copy(&ctx_copy, ctx);
  H2_update_u32_le(&ctx_copy, ctr);
  H2_3_final(&ctx_copy, chall_3, lambda_bytes);
}

static void hash_challenge_3(uint8_t* chall_3, const uint8_t* chall_2, const uint8_t* a0_tilde,
                             const uint8_t* a1_tilde, const uint8_t* a2_tilde, const uint8_t* ctr,
                             unsigned int lambda) {
  H2_context_t h2_ctx;
  hash_challenge_3_init(&h2_ctx, chall_2, a0_tilde, a1_tilde, a2_tilde, lambda);
  H2_update(&h2_ctx, ctr, sizeof(uint32_t));
  H2_3_final(&h2_ctx, chall_3, lambda / 8);
}

static inline bool check_challenge_3(const uint8_t* chall_3, unsigned int start,
                                     unsigned int lambda) {
  const unsigned int lambda_bytes = lambda / 8;

  uint8_t res = (start % 8) ? (chall_3[start / 8] >> (start % 8)) : 0;
  for (unsigned int bytes = (start + 7) / 8; bytes != lambda_bytes; ++bytes) {
    res |= chall_3[bytes];
  }
  return !res;
}

static inline void free_pointer_array(uint8_t*** ptr) {
  free((*ptr)[0]);
  free(*ptr);
  *ptr = NULL;
}

// AES(-EM) OWF dispatchers
static inline void aes_prove(uint8_t* a0_tilde, uint8_t* a1_tilde, uint8_t* a2_tilde,
                             const uint8_t* w, const uint8_t* u, uint8_t** V, const uint8_t* owf_in,
                             const uint8_t* owf_out, const uint8_t* chall_2,
                             const faest_paramset_t* params) {
  switch (params->lambda) {
  case 256:
    aes_256_prover(a0_tilde, a1_tilde, a2_tilde, w, u, V, owf_in, owf_out, chall_2, params);
    break;
  case 192:
    aes_192_prover(a0_tilde, a1_tilde, a2_tilde, w, u, V, owf_in, owf_out, chall_2, params);
    break;
  default:
    aes_128_prover(a0_tilde, a1_tilde, a2_tilde, w, u, V, owf_in, owf_out, chall_2, params);
  }
}

static inline void aes_verify(uint8_t* a0_tilde, const uint8_t* d, uint8_t** Q,
                              const uint8_t* chall_2, const uint8_t* chall_3,
                              const uint8_t* a1_tilde, const uint8_t* a2_tilde,
                              const uint8_t* owf_in, const uint8_t* owf_out,
                              const faest_paramset_t* params) {
  switch (params->lambda) {
  case 256:
    aes_256_verifier(a0_tilde, d, Q, owf_in, owf_out, chall_2, chall_3, a1_tilde, a2_tilde, params);
    break;
  case 192:
    aes_192_verifier(a0_tilde, d, Q, owf_in, owf_out, chall_2, chall_3, a1_tilde, a2_tilde, params);
    break;
  default:
    aes_128_verifier(a0_tilde, d, Q, owf_in, owf_out, chall_2, chall_3, a1_tilde, a2_tilde, params);
  }
}

// FAEST.Sign()
void faest_sign(uint8_t* sig, const uint8_t* msg, size_t msg_len, const uint8_t* owf_key,
                const uint8_t* owf_input, const uint8_t* owf_output, const uint8_t* witness,
                const uint8_t* rho, size_t rholen, const faest_paramset_t* params) {
  const unsigned int ell           = params->l;
  const unsigned int ell_bytes     = ell / 8;
  const unsigned int lambda        = params->lambda;
  const unsigned int tau           = params->tau;
  const unsigned int ell_hat       = ell + lambda * 3 + UNIVERSAL_HASH_B_BITS;
  const unsigned int ell_hat_bytes = ell_hat / 8;
  const unsigned int w_grind       = params->w_grind;

  // ::3
  uint8_t mu[MAX_LAMBDA_BYTES * 2];
  hash_mu(mu, owf_input, params->owf_input_size, owf_output, params->owf_output_size, msg, msg_len,
          lambda);

  // ::4-5
  uint8_t rootkey[MAX_LAMBDA_BYTES], iv[IV_SIZE];
  hash_r_iv(rootkey, signature_iv_pre(sig, params), iv, owf_key, mu, rho, rholen, lambda);

  // ::6-7
  bavc_t bavc;
  uint8_t* u = malloc(ell_hat_bytes);
  assert(u);
  // v has \hat \ell rows, \lambda columns, storing in column-major order
  uint8_t** V = malloc(lambda * sizeof(uint8_t*));
  assert(V);
  V[0] = calloc(lambda, ell_hat_bytes);
  assert(V[0]);
  for (unsigned int i = 1; i < lambda; ++i) {
    V[i] = V[0] + i * ell_hat_bytes;
  }
  vole_commit(rootkey, iv, ell_hat, params, &bavc, signature_c(sig, 0, params), u, V);

  H2_context_t h2_ctx;
  {
    // ::8
    uint8_t chall_1[(5 * MAX_LAMBDA_BYTES) + 8];
    hash_challenge_1(chall_1, mu, bavc.h, signature_c(sig, 0, params), iv, lambda, ell, tau);

    // ::9-10
    vole_hash(signature_u_tilde(sig, params), chall_1, u, ell, lambda);

    // ::11-12
    // To save memory consumption, the chall_2 is computed in an
    // Init-Update-Finalize style as V_tilde is only fed into to the hash and not
    // used elsewhere.
    hash_challenge_2_init(&h2_ctx, chall_1, signature_u_tilde(sig, params), lambda);
    {
      uint8_t V_tilde[MAX_LAMBDA_BYTES + UNIVERSAL_HASH_B];
      for (unsigned int i = 0; i != lambda; ++i) {
        // Step 11
        vole_hash(V_tilde, chall_1, V[i], ell, lambda);
        // Step 14
        hash_challenge_2_update_v_tilde(&h2_ctx, V_tilde, lambda);
      }
    }
  }

  // ::13 witness provided by caller
  // ::14
  xor_u8_array(witness, u, signature_d(sig, params), ell_bytes);

  {
    // :15
    uint8_t chall_2[3 * MAX_LAMBDA_BYTES + 8];
    hash_challenge_2_finalize(chall_2, &h2_ctx, signature_d(sig, params), lambda, ell);

    // ::16-20
    uint8_t a0_tilde[MAX_LAMBDA_BYTES];
    aes_prove(a0_tilde, signature_a1_tilde(sig, params), signature_a2_tilde(sig, params), witness,
              u + ell_bytes, V, owf_input, owf_output, chall_2, params);

    free_pointer_array(&V);
    free(u);
    u = NULL;

    // ::21-22
    hash_challenge_3_init(&h2_ctx, chall_2, a0_tilde, signature_a1_tilde(sig, params),
                          signature_a2_tilde(sig, params), lambda);
  }

  uint32_t ctr = 0;
  for (; true; ++ctr) {
    uint8_t* chall_3 = signature_chall_3(sig, params);
    hash_challenge_3_final(chall_3, &h2_ctx, ctr, lambda);
    // declassify chall_3 which is put into the signature
    faest_declassify(chall_3, lambda / 8);

    // ::23
    if (!check_challenge_3(chall_3, lambda - w_grind, lambda)) {
      continue;
    }

    // ::26
    uint16_t decoded_chall_3[MAX_TAU];
    if (!decode_all_chall_3(decoded_chall_3, chall_3, params)) {
      continue;
    }

    // :27
    if (bavc_open(signature_decom_i(sig, params), &bavc, decoded_chall_3, params)) {
      break;
    }
  }
  hash_clear(&h2_ctx);
  bavc_clear(&bavc);

  // copy counter to signature
  ctr = htole32(ctr);
  memcpy(signature_ctr(sig, params), &ctr, sizeof(ctr));
}

int faest_verify(const uint8_t* msg, size_t msglen, const uint8_t* sig, const uint8_t* owf_input,
                 const uint8_t* owf_output, const faest_paramset_t* params) {
  const unsigned int ell           = params->l;
  const unsigned int lambda        = params->lambda;
  const unsigned int lambda_bytes  = lambda / 8;
  const unsigned int tau           = params->tau;
  const unsigned int ell_hat       = ell + lambda * 3 + UNIVERSAL_HASH_B_BITS;
  const unsigned int ell_hat_bytes = ell_hat / 8;
  const unsigned int utilde_bytes  = lambda_bytes + UNIVERSAL_HASH_B;

  // ::4-5
  if (!check_challenge_3(dsignature_chall_3(sig, params), lambda - params->w_grind, lambda)) {
    return -1;
  }

  // ::2
  uint8_t mu[MAX_LAMBDA_BYTES * 2];
  hash_mu(mu, owf_input, params->owf_input_size, owf_output, params->owf_output_size, msg, msglen,
          lambda);

  // ::3
  uint8_t iv[IV_SIZE];
  hash_iv(iv, dsignature_iv_pre(sig, params), lambda);

  // Step: 6-7
  // q is a \hat \ell \times \lambda matrix
  uint8_t** q = malloc(lambda * sizeof(uint8_t*));
  assert(q);
  q[0] = calloc(lambda, ell_hat_bytes);
  assert(q[0]);
  for (unsigned int i = 1; i < lambda; ++i) {
    q[i] = q[0] + i * ell_hat_bytes;
  }
  uint8_t hcom[MAX_LAMBDA_BYTES * 2];

  if (!vole_reconstruct(hcom, q, iv, dsignature_chall_3(sig, params),
                        dsignature_decom_i(sig, params), dsignature_c(sig, 0, params), ell_hat,
                        params)) {
    free_pointer_array(&q);
    return -1;
  }

  // ::10
  uint8_t chall_1[5 * MAX_LAMBDA_BYTES + 8];
  hash_challenge_1(chall_1, mu, hcom, dsignature_c(sig, 0, params), iv, lambda, ell, tau);

  // Step 12, 14 and 15
  H2_context_t chall_2_ctx;
  hash_challenge_2_init(&chall_2_ctx, chall_1, dsignature_u_tilde(sig, params), lambda);
  {
    const uint8_t* chall_3 = dsignature_chall_3(sig, params);
    uint8_t Q_tilde[MAX_LAMBDA_BYTES + UNIVERSAL_HASH_B];
    for (unsigned int i = 0; i != lambda; ++i) {
      // Step 12
      vole_hash(Q_tilde, chall_1, q[i], ell, lambda);
      // Step 14
      if (ptr_get_bit(chall_3, i)) {
        xor_u8_array(Q_tilde, dsignature_u_tilde(sig, params), Q_tilde, utilde_bytes);
      }

      // Step 15
      hash_challenge_2_update_v_tilde(&chall_2_ctx, Q_tilde, lambda);
    }
  }

  // Step 15
  uint8_t chall_2[3 * MAX_LAMBDA_BYTES + 8];
  hash_challenge_2_finalize(chall_2, &chall_2_ctx, dsignature_d(sig, params), lambda, ell);

  // Step 18
  const uint8_t* d = dsignature_d(sig, params);
  uint8_t a0_tilde[MAX_LAMBDA_BYTES];
  aes_verify(a0_tilde, d, q, chall_2, dsignature_chall_3(sig, params),
             dsignature_a1_tilde(sig, params), dsignature_a2_tilde(sig, params), owf_input,
             owf_output, params);
  free_pointer_array(&q);

  // Step: 20
  uint8_t chall_3[MAX_LAMBDA_BYTES];
  hash_challenge_3(chall_3, chall_2, a0_tilde, dsignature_a1_tilde(sig, params),
                   dsignature_a2_tilde(sig, params), dsignature_ctr(sig, params), lambda);

  // Step 21
  return memcmp(chall_3, dsignature_chall_3(sig, params), lambda_bytes) == 0 ? 0 : -1;
}

// === Aggregate (5-round multi-signer) ===
// Phase 1 stub. Round-by-round implementation lives in faest_agg_signer.c and
// faest_agg_aggregator.c; this verifier consumes the finalized transcript.

size_t faest_aggregate_signature_size(size_t signer_count, const faest_paramset_t* params) {
  faest_agg_signature_layout_t layout;
  if (!faest_agg_compute_signature_layout(&layout, signer_count, params)) {
    return 0;
  }
  return layout.total_bytes;
}

// Recompute the aggregator's chall_1 derivation. Mirror of
// hash_agg_chall_1 in faest_agg_aggregator.c.
static void faest_agg_verify_hash_chall_1(uint8_t* chall_1, const uint8_t* mu,
                                          const uint8_t* h_com, const uint8_t* sig,
                                          const faest_agg_signature_layout_t* layout,
                                          const faest_paramset_t* params) {
  static const uint8_t domain[] = "FAEST-AGG-CHAL1-v1";
  const unsigned int lambda       = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;

  H2_context_t ctx;
  H2_init(&ctx, lambda);
  H2_update(&ctx, domain, sizeof(domain) - 1);
  {
    uint8_t n_le[8];
    for (size_t i = 0; i < 8; ++i) {
      n_le[i] = (uint8_t)((layout->signer_count >> (i * 8)) & 0xff);
    }
    H2_update(&ctx, n_le, sizeof(n_le));
  }
  H2_update(&ctx, mu, 2 * lambda_bytes);
  H2_update(&ctx, h_com, lambda_bytes);
  for (size_t j = 0; j < layout->signer_count; ++j) {
    H2_update(&ctx, faest_agg_sig_iv_pre_const(sig, layout, j), lambda_bytes);
  }
  for (size_t j = 0; j < layout->signer_count; ++j) {
    H2_update(&ctx, faest_agg_sig_c_const(sig, layout, j), layout->sizes.c_bytes);
  }
  H2_1_final(&ctx, chall_1, 5 * lambda_bytes + 8);
}

// Recompute the aggregator's mu derivation. Mirror of hash_agg_mu.
static void faest_agg_verify_hash_mu(uint8_t* mu, const uint8_t* const* owf_inputs,
                                     const uint8_t* const* owf_outputs, size_t signer_count,
                                     const uint8_t* msg, size_t msglen,
                                     const faest_paramset_t* params) {
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

// Compute a0_hat = sum_q_tilde + δ·a1_agg + δ²·a2_agg over GF(2^λ),
// where δ is loaded from chall_3.
static void faest_agg_verify_combine_a0(uint8_t* a0_hat, const uint8_t* sum_q_tilde,
                                        const uint8_t* a1_agg, const uint8_t* a2_agg,
                                        const uint8_t* chall_3,
                                        const faest_paramset_t* params) {
  const unsigned int lambda_bytes = params->lambda / 8;
  switch (params->lambda) {
  case 256: {
    bf256_t delta, delta_sq, a1, a2, sum, tmp;
    bf256_load(&delta, chall_3);
    bf256_mul(&delta_sq, &delta, &delta);
    bf256_load(&a1, a1_agg);
    bf256_load(&a2, a2_agg);
    bf256_load(&sum, sum_q_tilde);
    bf256_mul(&tmp, &delta, &a1);
    bf256_add_inplace(&sum, &tmp);
    bf256_mul(&tmp, &delta_sq, &a2);
    bf256_add_inplace(&sum, &tmp);
    bf256_store(a0_hat, &sum);
    break;
  }
  case 192: {
    bf192_t delta, delta_sq, a1, a2, sum, tmp;
    bf192_load(&delta, chall_3);
    bf192_mul(&delta_sq, &delta, &delta);
    bf192_load(&a1, a1_agg);
    bf192_load(&a2, a2_agg);
    bf192_load(&sum, sum_q_tilde);
    bf192_mul(&tmp, &delta, &a1);
    bf192_add_inplace(&sum, &tmp);
    bf192_mul(&tmp, &delta_sq, &a2);
    bf192_add_inplace(&sum, &tmp);
    bf192_store(a0_hat, &sum);
    break;
  }
  default: {
    bf128_t delta, delta_sq, a1, a2, sum, tmp;
    bf128_load(&delta, chall_3);
    bf128_mul(&delta_sq, &delta, &delta);
    bf128_load(&a1, a1_agg);
    bf128_load(&a2, a2_agg);
    bf128_load(&sum, sum_q_tilde);
    bf128_mul(&tmp, &delta, &a1);
    bf128_add_inplace(&sum, &tmp);
    bf128_mul(&tmp, &delta_sq, &a2);
    bf128_add_inplace(&sum, &tmp);
    bf128_store(a0_hat, &sum);
    break;
  }
  }
  (void)lambda_bytes;
}

int faest_aggregate_verify(const uint8_t* msg, size_t msg_len, const uint8_t* sig,
                           size_t sig_len, const uint8_t* const* owf_inputs,
                           const uint8_t* const* owf_outputs, size_t signer_count,
                           const faest_paramset_t* params) {
  if (!sig || !owf_inputs || !owf_outputs || !params || (!msg && msg_len) || signer_count == 0) {
    return -1;
  }
  // Phase 2B implements only n=1. n>1 requires chall_1-power combination of
  // ũ_j and V_tilde_j (Phase 2C).
  if (signer_count != 1) {
    return -1;
  }

  faest_agg_signature_layout_t layout;
  if (!faest_agg_compute_signature_layout(&layout, signer_count, params) ||
      sig_len != layout.total_bytes) {
    return -1;
  }
  for (size_t j = 0; j < signer_count; ++j) {
    if (!owf_inputs[j] || !owf_outputs[j]) {
      return -1;
    }
  }

  const unsigned int lambda       = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;
  const unsigned int ell          = params->l;
  const unsigned int ell_hat      = ell + 3 * lambda + UNIVERSAL_HASH_B_BITS;
  const unsigned int ell_hat_bytes = ell_hat / 8;
  const unsigned int u_tilde_bytes = lambda_bytes + UNIVERSAL_HASH_B;

  const uint8_t* sig_chall_3 = faest_agg_sig_chall_3_const(sig, &layout);
  if (!check_challenge_3(sig_chall_3, lambda - params->w_grind, lambda)) {
    return -1;
  }

  uint8_t mu[MAX_LAMBDA_BYTES * 2];
  faest_agg_verify_hash_mu(mu, owf_inputs, owf_outputs, signer_count, msg, msg_len, params);

  int ret = -1;
  uint8_t** q = NULL;
  uint8_t** per_signer_hcom = NULL;
  uint8_t* hcom_recon_buffer = NULL;
  uint8_t* q_storage = NULL;

  // Allocate per-signer reconstructed h_com_j and Q_j matrices.
  per_signer_hcom = (uint8_t**)calloc(signer_count, sizeof(uint8_t*));
  hcom_recon_buffer = (uint8_t*)calloc(signer_count, MAX_LAMBDA_BYTES * 2);
  if (!per_signer_hcom || !hcom_recon_buffer) {
    goto cleanup;
  }
  for (size_t j = 0; j < signer_count; ++j) {
    per_signer_hcom[j] = hcom_recon_buffer + j * MAX_LAMBDA_BYTES * 2;
  }

  // For n=1 we reconstruct a single Q matrix. For n>1 (Phase 2C) we would
  // allocate signer_count of them.
  q = (uint8_t**)malloc(lambda * sizeof(uint8_t*));
  if (!q) {
    goto cleanup;
  }
  q_storage = (uint8_t*)calloc(lambda, ell_hat_bytes);
  if (!q_storage) {
    goto cleanup;
  }
  for (unsigned int i = 0; i < lambda; ++i) {
    q[i] = q_storage + i * ell_hat_bytes;
  }

  // Per-signer VOLE reconstruction.
  for (size_t j = 0; j < signer_count; ++j) {
    uint8_t iv_j[IV_SIZE];
    hash_iv(iv_j, faest_agg_sig_iv_pre_const(sig, &layout, j), lambda);

    if (!vole_reconstruct(per_signer_hcom[j], q, iv_j, sig_chall_3,
                          faest_agg_sig_pdecom_const(sig, &layout, j),
                          faest_agg_sig_c_const(sig, &layout, j), ell_hat, params)) {
      goto cleanup;
    }
  }

  // Verify combined h_com.
  uint8_t hcom_combined[MAX_LAMBDA_BYTES];
  bavc_forest_combine_hcom(hcom_combined, (const uint8_t* const*)per_signer_hcom, signer_count,
                           params);
  if (memcmp(hcom_combined, faest_agg_sig_hcom_const(sig, &layout), lambda_bytes) != 0) {
    goto cleanup;
  }

  // Recompute chall_1.
  uint8_t chall_1[5 * MAX_LAMBDA_BYTES + 8];
  faest_agg_verify_hash_chall_1(chall_1, mu, hcom_combined, sig, &layout, params);

  // Recompute chall_2. For n=1, V_tilde_agg[i] = vole_hash(chall_1, q[i], ell)
  // XOR (chall_3 bit i ? ũ_agg : 0).
  const uint8_t* u_tilde_agg = faest_agg_sig_u_tilde_agg_const(sig, &layout);

  H2_context_t chall_2_ctx;
  H2_init(&chall_2_ctx, lambda);
  H2_update(&chall_2_ctx, chall_1, 5 * lambda_bytes + 8);
  H2_update(&chall_2_ctx, u_tilde_agg, u_tilde_bytes);
  {
    uint8_t v_tilde_agg[MAX_LAMBDA_BYTES + UNIVERSAL_HASH_B];
    for (unsigned int i = 0; i < lambda; ++i) {
      vole_hash(v_tilde_agg, chall_1, q[i], ell, lambda);
      if (ptr_get_bit(sig_chall_3, i)) {
        xor_u8_array(v_tilde_agg, u_tilde_agg, v_tilde_agg, u_tilde_bytes);
      }
      H2_update(&chall_2_ctx, v_tilde_agg, u_tilde_bytes);
    }
  }
  for (size_t j = 0; j < signer_count; ++j) {
    H2_update(&chall_2_ctx, faest_agg_sig_d_const(sig, &layout, j), layout.sizes.ell_bytes);
  }
  uint8_t chall_2[3 * MAX_LAMBDA_BYTES + 8];
  H2_2_final(&chall_2_ctx, chall_2, 3 * lambda_bytes + 8);

  // Per-signer aes_<λ>_verifier with zero a1/a2 yields per-signer q_tilde.
  // For n=1 this is the only signer.
  uint8_t zero_a1[MAX_LAMBDA_BYTES] = {0};
  uint8_t zero_a2[MAX_LAMBDA_BYTES] = {0};
  uint8_t sum_q_tilde[MAX_LAMBDA_BYTES] = {0};

  for (size_t j = 0; j < signer_count; ++j) {
    uint8_t partial[MAX_LAMBDA_BYTES];
    aes_verify(partial, faest_agg_sig_d_const(sig, &layout, j), q, chall_2, sig_chall_3, zero_a1,
               zero_a2, owf_inputs[j], owf_outputs[j], params);
    xor_u8_array(sum_q_tilde, partial, sum_q_tilde, lambda_bytes);
  }

  // a0_hat = sum_q_tilde + δ·ã_1 + δ²·ã_2
  uint8_t a0_hat[MAX_LAMBDA_BYTES];
  faest_agg_verify_combine_a0(a0_hat, sum_q_tilde, faest_agg_sig_a1_const(sig, &layout),
                              faest_agg_sig_a2_const(sig, &layout), sig_chall_3, params);

  // Recompute chall_3.
  uint8_t chall_3_check[MAX_LAMBDA_BYTES];
  hash_challenge_3(chall_3_check, chall_2, a0_hat, faest_agg_sig_a1_const(sig, &layout),
                   faest_agg_sig_a2_const(sig, &layout),
                   faest_agg_sig_ctr_const(sig, &layout), lambda);

  ret = memcmp(chall_3_check, sig_chall_3, lambda_bytes) == 0 ? 0 : -1;

cleanup:
  free(per_signer_hcom);
  free(hcom_recon_buffer);
  free(q);
  free(q_storage);
  return ret;
}
