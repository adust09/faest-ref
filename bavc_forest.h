/*
 *  SPDX-License-Identifier: MIT
 */

#ifndef BAVC_FOREST_H
#define BAVC_FOREST_H

#include <stddef.h>
#include <stdint.h>

#include "instances.h"

FAEST_BEGIN_C_DECL

// Flat-hash combination of per-signer BAVC roots into a single h_com.
// h_com_out := H1(domain || paramset || n || h_com_1 || ... || h_com_n)
// length of h_com_out is lambda_bytes.
void bavc_forest_combine_hcom(uint8_t* h_com_out, const uint8_t* const* per_signer_hcom,
                              size_t signer_count, const faest_paramset_t* params);

FAEST_END_C_DECL

#endif
