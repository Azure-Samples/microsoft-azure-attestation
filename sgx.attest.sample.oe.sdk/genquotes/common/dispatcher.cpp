// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "dispatcher.h"
#include <openenclave/enclave.h>

ecall_dispatcher::ecall_dispatcher(
    const char* name)
    : m_crypto(NULL), m_attestation(NULL)
{
    m_initialized = initialize(name);
}

ecall_dispatcher::~ecall_dispatcher()
{
    if (m_crypto)
        delete m_crypto;

    if (m_attestation)
        delete m_attestation;
}

bool ecall_dispatcher::initialize(const char* name)
{
    bool ret = false;

    m_name = name;
    m_crypto = new Crypto();
    if (m_crypto == NULL)
    {
        goto exit;
    }

    m_attestation = new Attestation(m_crypto);
    if (m_attestation == NULL)
    {
        goto exit;
    }
    ret = true;

exit:
    return ret;
}

/**
 * Return the public key of this enclave along with the enclave's remote report.
 * The enclave that receives the key will use the remote report to attest this
 * enclave.
 */
int ecall_dispatcher::get_remote_report_with_pubkey(
    uint8_t** pem_key,
    size_t* key_size,
    uint8_t** remote_report,
    size_t* remote_report_size)
{
    uint8_t pem_public_key[512];
    uint8_t* report = NULL;
    size_t report_size = 0;
    uint8_t* key_buf = NULL;
    int ret = 1;

    TRACE_ENCLAVE("get_remote_report_with_pubkey");
    if (m_initialized == false)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed.");
        goto exit;
    }

    m_crypto->retrieve_public_key(pem_public_key);

    // Generate a remote report for the public key so that the enclave that
    // receives the key can attest this enclave.
    if (m_attestation->generate_remote_report(
            pem_public_key, sizeof(pem_public_key), &report, &report_size))
    {
        // Allocate memory on the host and copy the report over.
        *remote_report = (uint8_t*)oe_host_malloc(report_size);
        if (*remote_report == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(*remote_report, report, report_size);
        *remote_report_size = report_size;
        oe_free_report(report);

        key_buf = (uint8_t*)oe_host_malloc(512);
        if (key_buf == NULL)
        {
            ret = OE_OUT_OF_MEMORY;
            goto exit;
        }
        memcpy(key_buf, pem_public_key, sizeof(pem_public_key));

        *pem_key = key_buf;
        *key_size = sizeof(pem_public_key);

        ret = 0;
        TRACE_ENCLAVE("get_remote_report_with_pubkey succeeded");
    }
    else
    {
        TRACE_ENCLAVE("get_remote_report_with_pubkey failed.");
    }

exit:
    if (ret != 0)
    {
        if (report)
            oe_free_report(report);
        if (key_buf)
            oe_host_free(key_buf);
        if (*remote_report)
            oe_host_free(*remote_report);
    }
    return ret;
}


