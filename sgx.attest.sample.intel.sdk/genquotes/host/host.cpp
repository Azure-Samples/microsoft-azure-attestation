/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <openssl/sha.h>

#include "sgx_error.h"   /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "sgx_urts.h"
#include "enclave_u.h"
#include "sgx_quote_3.h"
#include "sgx_dcap_ql_wrapper.h"

using namespace std;

void sha256sum(const uint8_t *data, uint32_t data_size, uint8_t *hash)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, data_size);
    SHA256_Final(hash, &sha256);
}

void printh(uint8_t *hash, size_t sz)
{
    stringstream ss;
    for(int i = 0; i < sz; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    cout << ss.str() << endl;
}

bool create_app_enclave_report(const char* enclave_path,
                               sgx_target_info_t qe_target_info,
                               sgx_report_t *app_report,
			       const sgx_report_data_t* p_data);

const char *format_hex_buffer (char *buffer, uint maxSize, uint8_t *data, size_t size);
const char *uint16_to_buffer (char *buffer, uint maxSize, uint16_t data, size_t size);

int SGX_CDECL main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("\nUsage: genquote_sgx_host <path-to-enclave-binary> <json-file-name>\n");
        printf("  - generates remote quote for the enclave\n");
        printf("  - writes remote quote, parsed data and enclave held data to a json file\n\n");
        return 1;
    }

    int ret = 0;

    printf("\nStep1: Call sgx_qe_get_target_info: ");
    sgx_target_info_t qe_target_info;
    quote3_error_t qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf("Error in sgx_qe_get_target_info. 0x%04x\n", qe3_ret);
        return -1;
    }
    printf("succeed!\n");

    uint8_t enclave_held_data[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    sgx_report_data_t hash;
    sha256sum(enclave_held_data, 6, hash.d);
    //printh(hash.d, sizeof(hash.d));

    printf("\nStep2: Call create_app_report: ");
    sgx_report_t app_report;
    if(true != create_app_enclave_report(argv[1], qe_target_info, &app_report, &hash)) {
        printf("Call to create_app_report() failed\n");
        return -1;
    }
    printf("succeed!\n");

    printf("\nStep3: Call sgx_qe_get_quote_size: ");
    uint32_t quote_size = 0;
    qe3_ret = sgx_qe_get_quote_size(&quote_size);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf("Error in sgx_qe_get_quote_size. 0x%04x\n", qe3_ret);
        return -1;
    }
    printf("succeed!\n");

    uint8_t* p_quote_buffer = (uint8_t*)malloc(quote_size);
    if (NULL == p_quote_buffer) {
        printf("\nCouldn't allocate quote_buffer\n");
        if (NULL != p_quote_buffer) {
            free(p_quote_buffer);
        }
        return -1;
    }
    memset(p_quote_buffer, 0, quote_size);

    printf("\nStep4: Call sgx_qe_get_quote: ");
    qe3_ret = sgx_qe_get_quote(&app_report,
                               quote_size,
                               p_quote_buffer);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf( "Error in sgx_qe_get_quote. 0x%04x\n", qe3_ret);
        if (NULL != p_quote_buffer) {
            free(p_quote_buffer);
        }
        return -1;
    }
    printf("succeed!\n");

    sgx_quote3_t *p_quote = (_sgx_quote3_t*)p_quote_buffer;
    sgx_ql_ecdsa_sig_data_t *p_sig_data = (sgx_ql_ecdsa_sig_data_t *)p_quote->signature_data;
    sgx_ql_auth_data_t *p_auth_data = (sgx_ql_auth_data_t*)p_sig_data->auth_certification_data;
    sgx_ql_certification_data_t *p_cert_data =
            (sgx_ql_certification_data_t *)((uint8_t *)p_auth_data + sizeof(*p_auth_data) + p_auth_data->size);

    const int hex_buffer_size = 1024*64;
    char hex_buffer[hex_buffer_size];

    std::string output_dir("./out/");
    std::string cmd("mkdir -p " + output_dir);
    std::string file(output_dir + std::string(argv[2]));
    int result = system(cmd.c_str());
	printf("\nExecuted command '%s' with the result:%u", cmd.c_str(), result);
    printf("\nStep5: Saving quote to JSON file, cert_key_type = 0x%x, output file name = %s\n", p_cert_data->cert_key_type, file.c_str());
    FILE *fp = fopen(file.c_str(), "w");
    fprintf(fp, "%s\n", "{");
    fprintf(fp, "  \"Type\": %d,\n", (int)2);
    // In open-enclave sdk enclave type 2 means OE_ENCLAVE_TYPE_SGX: 
    // https://github.com/openenclave/openenclave/blob/3e15573418caed43f9094ff8aec36cdde4f278f7/include/openenclave/bits/types.h#L127
    fprintf(fp, "  \"MrEnclaveHex\": \"%s\",\n", format_hex_buffer(hex_buffer, hex_buffer_size, app_report.body.mr_enclave.m, SGX_HASH_SIZE));
    fprintf(fp, "  \"MrSignerHex\": \"%s\",\n", format_hex_buffer(hex_buffer, hex_buffer_size, app_report.body.mr_signer.m, SGX_HASH_SIZE));
    fprintf(fp, "  \"ProductIdHex\": \"%s\",\n", uint16_to_buffer(hex_buffer, hex_buffer_size,(uint16_t)app_report.body.isv_prod_id, 16));
    fprintf(fp, "  \"SecurityVersion\": %u,\n", (int)app_report.body.isv_svn);
    fprintf(fp, "  \"Attributes\": %lu,\n", (uint64_t)app_report.body.attributes.flags);
    fprintf(fp, "  \"QuoteHex\": \"%s\",\n", format_hex_buffer(hex_buffer, hex_buffer_size, p_quote_buffer, quote_size));
    fprintf(fp, "  \"EnclaveHeldDataHex\": \"%s\"\n", format_hex_buffer(hex_buffer, hex_buffer_size, enclave_held_data, sizeof( enclave_held_data)));
    fprintf(fp, "%s\n", "}");
    fclose(fp);

    if (NULL != p_quote_buffer) {
        free(p_quote_buffer);
    }
    return ret;
}

const char *uint16_to_buffer (char *buffer, uint maxSize, uint16_t n, size_t size)
{
    if (size * 2 >= maxSize || size < 2)
        return "DEADBEEF";
    sprintf(&buffer[0], "%02X", uint8_t(n));
    sprintf(&buffer[2], "%02X", uint8_t(n >> 8));

    for (int i=2; i < size; i++)
    {
        sprintf(&buffer[i*2], "%02X", 0);
    }
    buffer[size*2+1] = '\0';
    return buffer;
}

const char *format_hex_buffer (char *buffer, uint maxSize, uint8_t *data, size_t size)
{
    if (size * 2 >= maxSize)
        return "DEADBEEF";

    for (int i=0; i < size; i++)
    {
        sprintf(&buffer[i*2], "%02X", data[i]);
    }
    buffer[size*2+1] = '\0';
    return buffer;
}

bool create_app_enclave_report(const char* enclave_path,
                               sgx_target_info_t qe_target_info,
                               sgx_report_t *app_report,
			       const sgx_report_data_t* p_data)
{
    bool ret = true;
    uint32_t retval = 0;
    sgx_status_t sgx_status = SGX_SUCCESS;
    sgx_enclave_id_t eid = 0;
    int launch_token_updated = 0;
    sgx_launch_token_t launch_token = { 0 };

    sgx_status = sgx_create_enclave(enclave_path,
                                    SGX_DEBUG_FLAG,
                                    &launch_token,
                                    &launch_token_updated,
                                    &eid,
                                    NULL);
    if (SGX_SUCCESS != sgx_status) {
        printf("Error, call sgx_create_enclave fail [%s], SGXError:%04x.\n", __FUNCTION__, sgx_status);
        ret = false;
        sgx_destroy_enclave(eid);
        return ret;
    }

    sgx_status = enclave_create_report(eid,
                                       &retval,
                                       &qe_target_info,
                                       p_data,
				       app_report);
    if ((SGX_SUCCESS != sgx_status) || (0 != retval)) {
        printf("\nCall to get_app_enclave_report() failed\n");
        ret = false;
        sgx_destroy_enclave(eid);
        return ret;
    }

    sgx_destroy_enclave(eid);
    return ret;
}
