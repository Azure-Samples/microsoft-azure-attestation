#include <x509.hpp>

#include <iostream>
#include <vector>
#include <cstring>
#include <algorithm>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/ts.h>

#include <context.hpp>

namespace jwtverifier {

    void X509QuoteExt::init() {
        // Adds all algorithms to the table (digests and ciphers).
        // In versions prior to 1.1.0 EVP_cleanup() removed all ciphers and digests from the table.
        // It no longer has any effect in OpenSSL 1.1.0.
        OpenSSL_add_all_algorithms();

        // ERR_load_crypto_strings() Registers the error strings for all libcrypto functions.
        // ERR_free_strings() frees all previously loaded error strings.
        ERR_load_crypto_strings();

        // Disables configuration. If called before OPENSSL_config() no configuration takes place.
        OPENSSL_no_config();
    }


    X509QuoteExt::X509QuoteExt() {
    }

    X509QuoteExt::X509QuoteExt(const std::string& cert_str) {
        if (!this->deserialize(cert_str)) {
            Context::always_log("ERROR - Failed to deserialize x509 cert");
        }
    }

    X509QuoteExt::~X509QuoteExt() {
        clear();
    }

    std::vector<uint8_t> X509QuoteExt::find_extension(const std::string& extension_oid) const {
        std::vector<uint8_t> res;
        auto it = this->extensions_.find(extension_oid);
        if (it != this->extensions_.end()) {
            res = it->second;
        }
        return res;
    }

    void output_certificate(const uint8_t* data, size_t data_len)
    {
        X509* x509;
        BIO* input = BIO_new_mem_buf(data, (int)data_len);
        x509 = d2i_X509_bio(input, nullptr);
        if (x509)
            X509_print_ex_fp(
                stdout,
                x509,
                XN_FLAG_COMPAT,
                XN_FLAG_SEP_CPLUS_SPC | XN_FLAG_DUMP_UNKNOWN_FIELDS);
        BIO_free_all(input);
    }

    bool X509QuoteExt::parse_extension(const STACK_OF(X509_EXTENSION) *exts, int n) {
        // Create a BIO to hold info from the cert.
        BIO_ptr output_bio(BIO_new(BIO_s_mem()), BIO_free);

        X509_EXTENSION *ex = X509v3_get_ext(exts, n);
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);
        if (i2a_ASN1_OBJECT(output_bio.get(), obj) < 0) {
            Context::log("Failed to write X509 extension into BIO, extension # " + std::to_string(n));
            return false;
        }

        // Magic number 80 is a constance used within OpenSSL library.
        // See: https://git.happyzh.com/github/openssl/-/blob/master/crypto/asn1/a_object.c#L187
        const int sz = 80;
        char obj_buffer[sz];
        memset(obj_buffer, 0, sz);
        BIO_read(output_bio.get(), obj_buffer, sz - 1);
        std::string ext_string(obj_buffer);

        BIO_reset(output_bio.get());
        if (!X509V3_EXT_print(output_bio.get(), ex, 0, 0)) {
            ASN1_STRING_print(output_bio.get(), X509_EXTENSION_get_data(ex));
        }
        const int large_sz = 32768;
        char value_buffer[large_sz];
        memset(value_buffer, 0, large_sz);
        BIO_read(output_bio.get(), value_buffer, large_sz - 1);
        std::vector<uint8_t> value(large_sz);
        std::transform(value_buffer, value_buffer + large_sz, value.begin(), [](char v) {return static_cast<uint8_t>(v);});

        this->extensions_.insert({ext_string, value});
        return true;
    }

    bool X509QuoteExt::deserialize(const std::string& cert_str) {
        clear();
        init();

        Context::log("Raw cert string value:");
        Context::log(cert_str);

        std::string cert_content = "-----BEGIN CERTIFICATE-----\n" + cert_str + "\n-----END CERTIFICATE-----";
        output_certificate(reinterpret_cast<const uint8_t*>(&cert_content[0]), cert_content.size());
        
        // Put the certificate contents into an openssl IO stream (BIO)
        BIO_ptr bio = BIO_ptr(BIO_new(BIO_s_mem()), BIO_free);
        BIO_write(bio.get(), cert_content.c_str(), (int)cert_content.size());

        // Create an openssl certificate from the BIO
        X509_ptr cert(PEM_read_bio_X509_AUX(bio.get(), NULL, NULL, NULL), X509_free);

        const STACK_OF(X509_EXTENSION) *exts = X509_get0_extensions(cert.get());
        const int ext_count = X509_get_ext_count(cert.get());
        for (int i = 0; i < ext_count; ++i) {
            if (!parse_extension(exts, i)) {
                Context::log("Failed to deserialize one of the extensions");
                return false;
            }
        }

        for (auto ext: this->extensions_) {
            Context::log(ext.first);
            std::string ext_value(ext.second.begin(), ext.second.end());
            Context::log(ext_value);
            Context::log("========================================");
        }
        return true;
    }

    void X509QuoteExt::clear() {
        CONF_modules_unload(1);
        CONF_modules_free();
        ERR_free_strings();
        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data(); // CRYPTO_cleanup_all_ex_data and ERR_remove_state should be called on each thread, and not just the main thread.
    }
}
