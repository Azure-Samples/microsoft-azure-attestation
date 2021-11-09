// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H
#define OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H

#include <openenclave/enclave.h>
#include "crypto.h"

#define ENCLAVE_SECRET_DATA_SIZE 16
class Attestation
{
  private:
    Crypto* m_crypto;

  public:
    Attestation(Crypto* crypto);

    // Generate a remote report for the given data. The SHA256 digest of the
    // data is stored in the report_data field of the generated remote report.
    bool generate_remote_report(
        const uint8_t* data,
        size_t data_size,
        uint8_t** remote_report_buf,
        size_t* remote_report_buf_size);
};

#endif // OE_SAMPLES_ATTESTATION_ENC_ATTESTATION_H
