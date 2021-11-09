// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include <common/dispatcher.h>
#include <common/remoteattestation_t.h>
#include <openenclave/enclave.h>

// Declare a static dispatcher object for enabling
// for better organizing enclave-wise global variables
static ecall_dispatcher dispatcher("Enclave1");
const char* enclave_name = "Enclave1";

/**
 * Return the public key of this enclave along with the enclave's remote report.
 * Another enclave can use the remote report to attest the enclave and verify
 * the integrity of the public key.
 */
int get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size)
{
    TRACE_ENCLAVE("enter get_remote_report_with_pubkey");
    return dispatcher.get_remote_report_with_pubkey(
        pem_key, key_size, remote_report, remote_report_size);
}
