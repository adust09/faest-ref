/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef FAEST_AGG_LAYOUT_H
#define FAEST_AGG_LAYOUT_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "instances.h"

FAEST_BEGIN_C_DECL

// Per-signer fixed sizes for messages between signer and aggregator,
// derived from the parameter set. Sizes are returned in bytes.
typedef struct faest_agg_sizes_t {
  size_t lambda_bytes;
  size_t ell_bytes;
  size_t ell_hat;         // bits
  size_t ell_hat_bytes;
  size_t hcom_bytes;
  size_t c_bytes;
  size_t u_tilde_bytes;
  size_t v_tilde_row_bytes;
  size_t pdecom_bytes;

  size_t msg1_bytes;      // (h_com_j, iv_pre_j, c_j)
  size_t msg2_bytes;      // (d_j, ũ_j, V_tilde_j[0..λ-1])
  size_t msg3_bytes;      // (a_0_j, a_1_j, a_2_j)
  size_t msg5_bytes;      // pdecom_j
} faest_agg_sizes_t;

bool faest_agg_compute_sizes(faest_agg_sizes_t* out, const faest_paramset_t* params);

// Signature byte layout:
//   h_com (λ bytes — flat hash of per-signer h_com_j)
//   ũ_agg (λ + UNIVERSAL_HASH_B bytes — aggregated VOLE u-hash)
//   ã_1 (λ bytes)
//   ã_2 (λ bytes)
//   chall_3 (λ bytes)
//   ctr (4 bytes, little-endian uint32)
//   for j in 0..n-1: iv_pre_j (λ bytes)
//   for j in 0..n-1: c_j ((τ-1) × ell_hat_bytes)
//   for j in 0..n-1: d_j (ell bytes)
//   for j in 0..n-1: pdecom_j (T_open + τ × com_bytes)
typedef struct faest_agg_signature_layout_t {
  faest_agg_sizes_t sizes;
  size_t signer_count;

  // Offsets (in bytes from signature start).
  size_t off_hcom;
  size_t off_u_tilde_agg;
  size_t off_a1;
  size_t off_a2;
  size_t off_chall_3;
  size_t off_ctr;
  size_t off_iv_pre;        // start of per-signer iv_pre block (each lambda_bytes)
  size_t off_c;             // start of per-signer c block (each c_bytes)
  size_t off_d;             // start of per-signer d block (each ell_bytes)
  size_t off_pdecom;        // start of per-signer pdecom block (each pdecom_bytes)

  size_t total_bytes;
} faest_agg_signature_layout_t;

bool faest_agg_compute_signature_layout(faest_agg_signature_layout_t* out, size_t signer_count,
                                        const faest_paramset_t* params);

// Accessor helpers — return mutable / const pointers into the signature buffer.
uint8_t* faest_agg_sig_hcom(uint8_t* sig, const faest_agg_signature_layout_t* layout);
uint8_t* faest_agg_sig_u_tilde_agg(uint8_t* sig, const faest_agg_signature_layout_t* layout);
uint8_t* faest_agg_sig_a1(uint8_t* sig, const faest_agg_signature_layout_t* layout);
uint8_t* faest_agg_sig_a2(uint8_t* sig, const faest_agg_signature_layout_t* layout);
uint8_t* faest_agg_sig_chall_3(uint8_t* sig, const faest_agg_signature_layout_t* layout);
uint8_t* faest_agg_sig_ctr(uint8_t* sig, const faest_agg_signature_layout_t* layout);
uint8_t* faest_agg_sig_iv_pre(uint8_t* sig, const faest_agg_signature_layout_t* layout, size_t j);
uint8_t* faest_agg_sig_c(uint8_t* sig, const faest_agg_signature_layout_t* layout, size_t j);
uint8_t* faest_agg_sig_d(uint8_t* sig, const faest_agg_signature_layout_t* layout, size_t j);
uint8_t* faest_agg_sig_pdecom(uint8_t* sig, const faest_agg_signature_layout_t* layout, size_t j);

const uint8_t* faest_agg_sig_hcom_const(const uint8_t* sig, const faest_agg_signature_layout_t* layout);
const uint8_t* faest_agg_sig_u_tilde_agg_const(const uint8_t* sig, const faest_agg_signature_layout_t* layout);
const uint8_t* faest_agg_sig_a1_const(const uint8_t* sig, const faest_agg_signature_layout_t* layout);
const uint8_t* faest_agg_sig_a2_const(const uint8_t* sig, const faest_agg_signature_layout_t* layout);
const uint8_t* faest_agg_sig_chall_3_const(const uint8_t* sig, const faest_agg_signature_layout_t* layout);
const uint8_t* faest_agg_sig_ctr_const(const uint8_t* sig, const faest_agg_signature_layout_t* layout);
const uint8_t* faest_agg_sig_iv_pre_const(const uint8_t* sig, const faest_agg_signature_layout_t* layout, size_t j);
const uint8_t* faest_agg_sig_c_const(const uint8_t* sig, const faest_agg_signature_layout_t* layout, size_t j);
const uint8_t* faest_agg_sig_d_const(const uint8_t* sig, const faest_agg_signature_layout_t* layout, size_t j);
const uint8_t* faest_agg_sig_pdecom_const(const uint8_t* sig, const faest_agg_signature_layout_t* layout, size_t j);

FAEST_END_C_DECL

#endif
