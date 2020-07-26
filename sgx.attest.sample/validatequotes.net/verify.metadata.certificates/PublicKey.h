#pragma once

#include <windows.h>
#include <wincrypt.h>
#pragma warning(push)
#pragma warning(disable: 6319)
#include <wil\resource.h>
#include <wil\result.h>
#pragma warning(pop)
#include <vector>
#include <memory>
class PublicKey
{
public:
    enum class KeyKind
    {
        RSA,
        ECC
    };
    enum class KeyType
    {
        FullKey,
        PublicKey
    };

    static std::unique_ptr<PublicKey> CreateFromCertificate(const wil::unique_cert_context& context)
    {
        wil::unique_bcrypt_key keyHandle;
        CERT_PUBLIC_KEY_INFO publicKeyInfo{};
        publicKeyInfo.Algorithm.pszObjId = context.get()->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
        publicKeyInfo.Algorithm.Parameters.cbData = context.get()->pCertInfo->SubjectPublicKeyInfo.Algorithm.Parameters.cbData;
        publicKeyInfo.Algorithm.Parameters.pbData = context.get()->pCertInfo->SubjectPublicKeyInfo.Algorithm.Parameters.pbData;
        publicKeyInfo.PublicKey.cbData = context.get()->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData;
        publicKeyInfo.PublicKey.pbData = context.get()->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData;

        THROW_IF_WIN32_BOOL_FALSE(CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &publicKeyInfo, 0, nullptr, keyHandle.addressof()));

        return std::make_unique<PublicKey>((strcmp(publicKeyInfo.Algorithm.pszObjId, szOID_RSA_RSA) == 0 ? KeyKind::RSA : KeyKind::ECC), KeyType::PublicKey, std::move(keyHandle));
    }

    PublicKey(KeyKind kind, KeyType keyType, wil::unique_bcrypt_key&& key)
        : _keyKind(kind)
        , _keyType(keyType)
        , _key(std::move(key))
    {}

    static LPCWSTR BCryptKeyBlob(
        _In_ KeyKind keyKind,
        _In_ KeyType keyType)
    {
        switch (keyKind)
        {
        case KeyKind::RSA:
            return (keyType == KeyType::PublicKey) ? BCRYPT_RSAPUBLIC_BLOB : BCRYPT_RSAFULLPRIVATE_BLOB;

        case KeyKind::ECC:
            return (keyType == KeyType::PublicKey) ? BCRYPT_ECCPUBLIC_BLOB : BCRYPT_ECCPRIVATE_BLOB;

        default:
            return NULL;
        }
    }

    std::vector<uint8_t> ExportKey(KeyType keyType) const
    {
        ULONG cbKey;

        // If this key isn't a full key, we can't ask for a full key.
        if ((_keyType == KeyType::PublicKey) && (keyType == KeyType::FullKey))
        {
            THROW_EXCEPTION_MSG(wil::ResultException(E_INVALIDARG), "Illegal to ask for full key from a full key");
        }

        THROW_IF_NTSTATUS_FAILED(BCryptExportKey(
            _key.get(),
            nullptr,
            BCryptKeyBlob(_keyKind, keyType),
            nullptr,
            0,
            &cbKey,
            0));

        std::vector<uint8_t> key(cbKey);

        THROW_IF_NTSTATUS_FAILED(BCryptExportKey(
            _key.get(),
            nullptr,
            BCryptKeyBlob(_keyKind, keyType),
            key.data(),
            static_cast<DWORD>(key.size()),
            &cbKey,
            0));

        return key;
    }

private:
    KeyKind _keyKind;
    KeyType _keyType;
    wil::unique_bcrypt_key _key;
};

