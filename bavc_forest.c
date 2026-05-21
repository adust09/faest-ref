/*
 *  SPDX-License-Identifier: MIT
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "bavc_forest.h"
#include "random_oracle.h"

#include <stdint.h>
#include <string.h>

void bavc_forest_combine_hcom(uint8_t* h_com_out, const uint8_t* const* per_signer_hcom,
                              size_t signer_count, const faest_paramset_t* params) {
  static const uint8_t domain[] = "FAEST-AGG-FOREST-HCOM-v1";
  const unsigned int lambda       = params->lambda;
  const unsigned int lambda_bytes = lambda / 8;

  H1_context_t ctx;
  H1_init(&ctx, lambda);
  H1_update(&ctx, domain, sizeof(domain) - 1);
  {
    const uint8_t lambda_byte = (uint8_t)lambda_bytes;
    H1_update(&ctx, &lambda_byte, 1);
  }
  {
    uint8_t n_le[8];
    for (size_t i = 0; i < 8; ++i) {
      n_le[i] = (uint8_t)((signer_count >> (i * 8)) & 0xff);
    }
    H1_update(&ctx, n_le, sizeof(n_le));
  }
  for (size_t j = 0; j < signer_count; ++j) {
    H1_update(&ctx, per_signer_hcom[j], lambda_bytes);
  }
  H1_final(&ctx, h_com_out, lambda_bytes);
}
