/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "faest_agg_layout.h"

#include <limits.h>

static bool checked_add(size_t lhs, size_t rhs, size_t* out) {
  if (lhs > SIZE_MAX - rhs) {
    return false;
  }
  *out = lhs + rhs;
  return true;
}

static bool checked_mul(size_t lhs, size_t rhs, size_t* out) {
  if (lhs != 0 && rhs > SIZE_MAX / lhs) {
    return false;
  }
  *out = lhs * rhs;
  return true;
}

bool faest_agg_compute_sizes(faest_agg_sizes_t* out, const faest_paramset_t* params) {
  if (!out || !params) {
    return false;
  }

  const size_t lambda_bytes = params->lambda / 8;
  const size_t ell_bytes    = params->l / 8;
  const size_t ell_hat      = (size_t)params->l + 3u * (size_t)params->lambda + UNIVERSAL_HASH_B_BITS;
  const size_t ell_hat_bytes = ell_bytes + 3u * lambda_bytes + UNIVERSAL_HASH_B;
  const size_t com_bytes_per_leaf = (faest_is_em(params) ? 2u : 3u) * lambda_bytes;

  size_t c_bytes;
  if (!checked_mul((size_t)(params->tau - 1u), ell_hat_bytes, &c_bytes)) {
    return false;
  }

  const size_t u_tilde_bytes     = lambda_bytes + UNIVERSAL_HASH_B;
  const size_t v_tilde_row_bytes = lambda_bytes + UNIVERSAL_HASH_B;

  size_t v_tilde_all_bytes;
  if (!checked_mul((size_t)params->lambda, v_tilde_row_bytes, &v_tilde_all_bytes)) {
    return false;
  }

  size_t pdecom_bytes;
  size_t tmp;
  if (!checked_mul(com_bytes_per_leaf, (size_t)params->tau, &tmp) ||
      !checked_mul((size_t)params->T_open, lambda_bytes, &pdecom_bytes) ||
      !checked_add(tmp, pdecom_bytes, &pdecom_bytes)) {
    return false;
  }

  // msg1 = h_com_j (lambda_bytes) || iv_pre_j (lambda_bytes) || c_j (c_bytes)
  size_t msg1_bytes;
  if (!checked_add(lambda_bytes, lambda_bytes, &msg1_bytes) ||
      !checked_add(msg1_bytes, c_bytes, &msg1_bytes)) {
    return false;
  }

  // msg2 = d_j (ell_bytes) || u_tilde_j (u_tilde_bytes) || V_tilde_j[0..lambda-1] (lambda * row)
  size_t msg2_bytes;
  if (!checked_add(ell_bytes, u_tilde_bytes, &msg2_bytes) ||
      !checked_add(msg2_bytes, v_tilde_all_bytes, &msg2_bytes)) {
    return false;
  }

  // msg3 = a_0_j (lambda_bytes) || a_1_j (lambda_bytes) || a_2_j (lambda_bytes)
  size_t msg3_bytes;
  if (!checked_mul(3u, lambda_bytes, &msg3_bytes)) {
    return false;
  }

  // msg5 = pdecom_j
  const size_t msg5_bytes = pdecom_bytes;

  out->lambda_bytes      = lambda_bytes;
  out->ell_bytes         = ell_bytes;
  out->ell_hat           = ell_hat;
  out->ell_hat_bytes     = ell_hat_bytes;
  out->hcom_bytes        = lambda_bytes;
  out->c_bytes           = c_bytes;
  out->u_tilde_bytes     = u_tilde_bytes;
  out->v_tilde_row_bytes = v_tilde_row_bytes;
  out->pdecom_bytes      = pdecom_bytes;
  out->msg1_bytes        = msg1_bytes;
  out->msg2_bytes        = msg2_bytes;
  out->msg3_bytes        = msg3_bytes;
  out->msg5_bytes        = msg5_bytes;
  return true;
}

bool faest_agg_compute_signature_layout(faest_agg_signature_layout_t* out, size_t signer_count,
                                        const faest_paramset_t* params) {
  if (!out || !params || signer_count == 0) {
    return false;
  }

  if (!faest_agg_compute_sizes(&out->sizes, params)) {
    return false;
  }
  out->signer_count = signer_count;

  const faest_agg_sizes_t* sz = &out->sizes;
  size_t cursor = 0;

  out->off_hcom = cursor;
  if (!checked_add(cursor, sz->hcom_bytes, &cursor)) return false;

  out->off_u_tilde_agg = cursor;
  if (!checked_add(cursor, sz->u_tilde_bytes, &cursor)) return false;

  out->off_a1 = cursor;
  if (!checked_add(cursor, sz->lambda_bytes, &cursor)) return false;

  out->off_a2 = cursor;
  if (!checked_add(cursor, sz->lambda_bytes, &cursor)) return false;

  out->off_chall_3 = cursor;
  if (!checked_add(cursor, sz->lambda_bytes, &cursor)) return false;

  out->off_ctr = cursor;
  if (!checked_add(cursor, sizeof(uint32_t), &cursor)) return false;

  out->off_iv_pre = cursor;
  {
    size_t block;
    if (!checked_mul(signer_count, sz->lambda_bytes, &block) ||
        !checked_add(cursor, block, &cursor)) return false;
  }

  out->off_c = cursor;
  {
    size_t block;
    if (!checked_mul(signer_count, sz->c_bytes, &block) ||
        !checked_add(cursor, block, &cursor)) return false;
  }

  out->off_d = cursor;
  {
    size_t block;
    if (!checked_mul(signer_count, sz->ell_bytes, &block) ||
        !checked_add(cursor, block, &cursor)) return false;
  }

  out->off_pdecom = cursor;
  {
    size_t block;
    if (!checked_mul(signer_count, sz->pdecom_bytes, &block) ||
        !checked_add(cursor, block, &cursor)) return false;
  }

  out->total_bytes = cursor;
  return true;
}

#define ACCESSOR(name, off_field, j_offset_expr)                                         \
  uint8_t* faest_agg_sig_##name(uint8_t* sig, const faest_agg_signature_layout_t* l) {   \
    return sig + l->off_field + (j_offset_expr);                                         \
  }                                                                                      \
  const uint8_t* faest_agg_sig_##name##_const(const uint8_t* sig,                        \
                                              const faest_agg_signature_layout_t* l) {   \
    return sig + l->off_field + (j_offset_expr);                                         \
  }

#define ACCESSOR_J(name, off_field, stride_field)                                        \
  uint8_t* faest_agg_sig_##name(uint8_t* sig, const faest_agg_signature_layout_t* l,     \
                                size_t j) {                                              \
    return sig + l->off_field + j * l->sizes.stride_field;                               \
  }                                                                                      \
  const uint8_t* faest_agg_sig_##name##_const(const uint8_t* sig,                        \
                                              const faest_agg_signature_layout_t* l,     \
                                              size_t j) {                                \
    return sig + l->off_field + j * l->sizes.stride_field;                               \
  }

ACCESSOR(hcom,         off_hcom,         0)
ACCESSOR(u_tilde_agg,  off_u_tilde_agg,  0)
ACCESSOR(a1,           off_a1,           0)
ACCESSOR(a2,           off_a2,           0)
ACCESSOR(chall_3,      off_chall_3,      0)
ACCESSOR(ctr,          off_ctr,          0)

ACCESSOR_J(iv_pre, off_iv_pre, lambda_bytes)
ACCESSOR_J(c,      off_c,      c_bytes)
ACCESSOR_J(d,      off_d,      ell_bytes)
ACCESSOR_J(pdecom, off_pdecom, pdecom_bytes)
