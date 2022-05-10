#pragma once
#include <windows.h>
#include <wincrypt.h>
#pragma warning(push)
#pragma warning(disable: 6319)
#include <wil\resource.h>
#include <wil\result.h>
#pragma warning(pop)

#include <memory>
#include <string>
#include <assert.h>
#include "PublicKey.h"
#include "base64.h"

//  RAII Wrapper for a CryptoAPI HCERTSTORE structure.
namespace details
{
    inline void __stdcall CertCloseStoreNoParam(_Pre_opt_valid_ _Frees_ptr_opt_ HCERTSTORE hCertStore)
    {
        ::CertCloseStore(hCertStore, 0);
    }
}
typedef wil::unique_any<HCERTSTORE, decltype(details::CertCloseStoreNoParam), details::CertCloseStoreNoParam> CertificateStore;

class X509Cert
{
public:
    static std::unique_ptr<X509Cert> Deserialize(const std::string& serializedCertificate)
    {
        DWORD encodingType;
        CertificateStore certificateStore;

        CERT_BLOB inputBlob;
        inputBlob.pbData = const_cast<BYTE*>(reinterpret_cast<const BYTE*>(&serializedCertificate.front()));
        inputBlob.cbData = static_cast<DWORD>(serializedCertificate.size());

        THROW_IF_WIN32_BOOL_FALSE(CryptQueryObject(CERT_QUERY_OBJECT_BLOB, &inputBlob,
            CERT_QUERY_CONTENT_FLAG_CERT, CERT_QUERY_FORMAT_FLAG_ALL, 0,
            &encodingType, nullptr, nullptr, certificateStore.addressof(),
            nullptr, nullptr));

        assert(encodingType == X509_ASN_ENCODING);

        wil::unique_cert_context certificate(CertEnumCertificatesInStore(certificateStore.get(), nullptr));

        return std::make_unique<X509Cert>(std::move(certificate));
    }

    std::vector<uint8_t> FindExtension(const char* extensionOid) const
    {
        std::vector<uint8_t> extensionData;
        for (unsigned int i = 0; i < _certificateContext.get()->pCertInfo->cExtension; i += 1)
        {
            if (strcmp(_certificateContext.get()->pCertInfo->rgExtension[i].pszObjId, extensionOid) == 0)
            {
                uint8_t *extensionStart = _certificateContext.get()->pCertInfo->rgExtension[i].Value.pbData;
                extensionData = std::vector<uint8_t>(extensionStart, extensionStart + _certificateContext.get()->pCertInfo->rgExtension[i].Value.cbData);
                break;
            }
        }

        return extensionData;
    }
    typedef wil::unique_any <PCRYPT_SEQUENCE_OF_ANY, decltype(::LocalFree), ::LocalFree> UniqueCryptSequenceOfAny;
    typedef wil::unique_any <PCRYPT_DATA_BLOB, decltype(::LocalFree), ::LocalFree> UniqueCryptDataBlob;

    std::vector<uint8_t> ExtractOctetString(const std::vector<uint8_t>& extension)
    {
        UniqueCryptDataBlob sequence;
        DWORD sequenceLength = 0;

        //  The input extension buffer should be an encoded X509 certificate sequence. Decode the object into an X509 sequence.
        THROW_IF_WIN32_BOOL_FALSE(CryptDecodeObjectEx(X509_ASN_ENCODING, X509_OCTET_STRING, extension.data(), static_cast<DWORD>(extension.size()), CRYPT_DECODE_ALLOC_FLAG, nullptr, sequence.addressof(), &sequenceLength));

        return std::vector<uint8_t>(sequence.get()->pbData,sequence.get()->pbData + sequence.get()->cbData);

    }

    std::vector<uint8_t> FindOidSequenceInExtension(const std::vector<uint8_t>& extension, const char* elementOid)
    {
        UniqueCryptSequenceOfAny sequence;
        DWORD sequenceLength = 0;

        std::vector<uint8_t> extensionSequence;

        //  The input extension buffer should be an encoded X509 certificate sequence. Decode the object into an X509 sequence.
        THROW_IF_WIN32_BOOL_FALSE(CryptDecodeObjectEx(X509_ASN_ENCODING, X509_SEQUENCE_OF_ANY, extension.data(), static_cast<DWORD>(extension.size()), CRYPT_DECODE_ALLOC_FLAG, nullptr, sequence.addressof(), &sequenceLength));

        // Iterate over all the sequences looking for our desired sequence.
        bool oidFound = false;
        for (auto i = 0ul; i < sequence.get()->cValue; i += 1)
        {
            //  Each sequence in the outer sequence is a pair of sequences, the first is the OID for the element, the second is the actual element.
            UniqueCryptSequenceOfAny innerSequence;
            DWORD innerSequenceLength = 0;
            THROW_IF_WIN32_BOOL_FALSE(CryptDecodeObjectEx(X509_ASN_ENCODING, X509_SEQUENCE_OF_ANY, sequence.get()->rgValue[i].pbData, sequence.get()->rgValue[i].cbData, CRYPT_DECODE_ALLOC_FLAG, nullptr, innerSequence.addressof(), &innerSequenceLength));

            if (innerSequence.get()->cValue != 2)
            {
                THROW_EXCEPTION(wil::ResultException(E_INVALIDARG));
            }

            char** oidName = nullptr;
            DWORD oidNameSize = 0;
            THROW_IF_WIN32_BOOL_FALSE(CryptDecodeObjectEx(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER,
                innerSequence.get()->rgValue[0].pbData,
                innerSequence.get()->rgValue[0].cbData,
                CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_SHARE_OID_STRING_FLAG,
                nullptr, &oidName, &oidNameSize));

            if (strcmp(*oidName, elementOid) == 0)
            {
                // Since the OID specified is a sequence of any, the 2nd element is the sequence of any data, no further
                // decoding needed.
                extensionSequence = std::vector<uint8_t>(
                    innerSequence.get()->rgValue[1].pbData,
                    innerSequence.get()->rgValue[1].pbData + innerSequence.get()->rgValue[1].cbData
                );
                oidFound = true;
                break;
            }
        }

        return extensionSequence;
    }

    std::vector<uint8_t> ExportPublicKey()
    {
        //
        //  The exported key is a sequence with two elements. The first sequence is the key type, the second sequence is the key value.
        //

        // Calculate the key type sequence.
        DWORD keyTypeSequenceSize;
        wil::unique_hlocal keyTypeSequence;
        {
            wil::unique_hlocal oidValue;
            DWORD cbOidValue;

            THROW_IF_WIN32_BOOL_FALSE(CryptEncodeObjectEx(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER, &_certificateContext.get()->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId, CRYPT_ENCODE_ALLOC_FLAG, nullptr, oidValue.addressof(), &cbOidValue));

            uint8_t oidSequenceBuffer[sizeof(CRYPT_SEQUENCE_OF_ANY) + 2 * sizeof(CRYPT_DER_BLOB)];
            CRYPT_SEQUENCE_OF_ANY* oidSequenceOfAny = reinterpret_cast<CRYPT_SEQUENCE_OF_ANY*>(oidSequenceBuffer);
            CRYPT_ATTR_BLOB oidSequenceValues[2] = { 0 };
            oidSequenceOfAny->cValue = 2;
            oidSequenceOfAny->rgValue = oidSequenceValues;
            oidSequenceOfAny->rgValue[0].cbData = cbOidValue;
            oidSequenceOfAny->rgValue[0].pbData = reinterpret_cast<BYTE*>(oidValue.get());
            oidSequenceOfAny->rgValue[1].cbData = _certificateContext.get()->pCertInfo->SubjectPublicKeyInfo.Algorithm.Parameters.cbData;
            oidSequenceOfAny->rgValue[1].pbData = _certificateContext.get()->pCertInfo->SubjectPublicKeyInfo.Algorithm.Parameters.pbData;

            THROW_IF_WIN32_BOOL_FALSE(CryptEncodeObjectEx(X509_ASN_ENCODING, X509_SEQUENCE_OF_ANY, oidSequenceOfAny, CRYPT_ENCODE_ALLOC_FLAG, nullptr, keyTypeSequence.addressof(), &keyTypeSequenceSize));
        }

        // Calculate the key value sequence. THis is encoded as the key value embedded in a X.509 BIT STRING.
        wil::unique_hlocal keySequence;
        DWORD keySequenceLength;
        {
            CRYPT_BIT_BLOB bitString;
            bitString.cbData = _certificateContext.get()->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData;
            bitString.pbData = _certificateContext.get()->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData;
            bitString.cUnusedBits = 0;
            THROW_IF_WIN32_BOOL_FALSE(CryptEncodeObjectEx(X509_ASN_ENCODING, X509_BITS, &bitString, CRYPT_ENCODE_ALLOC_FLAG, nullptr, keySequence.addressof(), &keySequenceLength));
        }

        // Stitch the two sequence together in another sequence.
        DWORD publicKeySize;
        wil::unique_hlocal publicKeySequence;
        {
            uint8_t publicKeyBuffer[sizeof(CRYPT_SEQUENCE_OF_ANY) + 2 * sizeof(CRYPT_DER_BLOB)];
            CRYPT_SEQUENCE_OF_ANY* keySequenceOfAny = reinterpret_cast<CRYPT_SEQUENCE_OF_ANY*>(publicKeyBuffer);
            keySequenceOfAny->cValue = 2;
            CRYPT_ATTR_BLOB keySequenceValues[2] = { 0 };
            keySequenceOfAny->rgValue = keySequenceValues;
            keySequenceOfAny->rgValue[0].cbData = keyTypeSequenceSize;
            keySequenceOfAny->rgValue[0].pbData = reinterpret_cast<BYTE*>(keyTypeSequence.get());
            keySequenceOfAny->rgValue[1].cbData = keySequenceLength;
            keySequenceOfAny->rgValue[1].pbData = reinterpret_cast<BYTE*>(keySequence.get());
            THROW_IF_WIN32_BOOL_FALSE(CryptEncodeObjectEx(X509_ASN_ENCODING, X509_SEQUENCE_OF_ANY, keySequenceOfAny, CRYPT_ENCODE_ALLOC_FLAG, nullptr, &publicKeySequence, &publicKeySize));
        }
        return std::vector<uint8_t>(reinterpret_cast<uint8_t*>(publicKeySequence.get()), reinterpret_cast<uint8_t*>(publicKeySequence.get()) + publicKeySize);
    }

    std::string ExportPublicKeyAsPEM()
    {
        auto encodedKey = base64::encode(ExportPublicKey());

        // Start by taking the base64 encoded key and split it up in separate lines.
        // mbedtls uses a 64 byte line length and a \n line separator.
        const size_t lineLength = 64;
        const char* lineSeparator = "\n";
        // Insert crlf characters every 80 characters into the base64 encoded key to make it prettier.
        size_t insertPos = lineLength;
        while (insertPos < encodedKey.length())
        {
            encodedKey.insert(insertPos, lineSeparator);
            insertPos += lineLength + strlen(lineSeparator); /* line length characters plus the separator we just inserted */
        }

        std::string pemEncodedKey = "-----BEGIN PUBLIC KEY-----";
        pemEncodedKey += lineSeparator;
        pemEncodedKey += encodedKey;
        pemEncodedKey += lineSeparator;
        pemEncodedKey += "-----END PUBLIC KEY-----";
        pemEncodedKey += lineSeparator;

        return pemEncodedKey;
    }

    std::unique_ptr<PublicKey> GetPublicKey()
    {
        return PublicKey::CreateFromCertificate(_certificateContext);
    }

    X509Cert(wil::unique_cert_context&& certificate)
        : _certificateContext(std::move(certificate))
    {

    }
private:
    wil::unique_cert_context _certificateContext;
};

