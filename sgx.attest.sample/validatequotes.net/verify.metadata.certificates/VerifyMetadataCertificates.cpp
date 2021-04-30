// VerifyMetadataCertificates.cpp : Defines the exported functions for the DLL.
//

#include <array>
#include "framework.h"
#include "VerifyMetadataCertificates.h"
#pragma warning(push)
#pragma warning(disable: 6319)
#include <wil\com.h>
#pragma warning(pop)
#pragma warning(push)
#pragma warning(disable: 26812)
#include <openenclave/host.h>
#include <openenclave/host_verify.h>
//#include "plugin.h"
#pragma warning(pop)
#include "X509Cert.h"

const char* SgxExtensionOidX = "1.2.840.113556.10.1.1";

// This class is exported from the dll
class CVerifyMetadataCertificates : public IVerifyMetadataCertificates
{
public:
    CVerifyMetadataCertificates(void);

    // Inherited via IUnknown
    virtual HRESULT __stdcall QueryInterface(REFIID riid, void** ppvObject) override
    {
        if (riid == __uuidof(IUnknown))
        {
            AddRef();
            *ppvObject = this;
            return S_OK;
        }
        else if (riid == __uuidof(IVerifyMetadataCertificates))
        {
            AddRef();
            *ppvObject = this;
            return S_OK;
        }
        return E_NOINTERFACE;
    }

    virtual ULONG __stdcall AddRef(void) override
    {
        return InterlockedIncrement(&_refCount);
    }

    virtual ULONG __stdcall Release(void) override
    {
        ULONG rv = InterlockedDecrement(&_refCount);
        if (rv == 0)
        {
            delete this;
        }
        return rv;
    }

private:

    static oe_result_t StaticVerifyMetadataQuote(oe_identity_t* identity, void* arg)
    {
        CVerifyMetadataCertificates *verifyCerts = static_cast<CVerifyMetadataCertificates*>(arg);

        return verifyCerts->VerifyMetadataQuote(identity);
    }

    oe_result_t VerifyMetadataQuote(oe_identity_t* identity)
    {
        _attributes = identity->attributes;
        _id_version = identity->id_version;
        _security_version = identity->security_version;
        std::memcpy(_unique_id.data(), identity->unique_id, OE_UNIQUE_ID_SIZE);
        std::memcpy(_signer_id.data(), identity->signer_id, OE_SIGNER_ID_SIZE);
        std::memcpy(_product_id.data(), identity->product_id, OE_PRODUCT_ID_SIZE);
        return OE_OK;
    }

    uint32_t _id_version;
    uint64_t _attributes;
    uint32_t _security_version;
    std::array<uint8_t, OE_UNIQUE_ID_SIZE> _unique_id{};
    std::array<uint8_t, OE_SIGNER_ID_SIZE> _signer_id{};
    std::array<uint8_t, OE_PRODUCT_ID_SIZE> _product_id{};


    // Inherited via IVerifyMetadataCertificates
    virtual HRESULT __stdcall VerifyQuoteInCertificate(LPCSTR base64encodedCertificate, bool* extensionFound) override;

    virtual HRESULT __stdcall SecurityVersion(uint32_t *version) override
    {
        if (!version)
        {
            return E_POINTER;
        }

        *version = _security_version;
        return S_OK;
    }

    STDMETHODIMP UniqueId(uint32_t* uniqueIdSize, uint8_t** uniqueId) override
    {
        if (uniqueIdSize == nullptr || uniqueId == nullptr)
        {
            return E_POINTER;
        }
        *uniqueIdSize = static_cast<uint32_t>(_unique_id.size());

        *uniqueId = static_cast<uint8_t*>(CoTaskMemAlloc(*uniqueIdSize));
        if (*uniqueId == nullptr)
        {
            return E_OUTOFMEMORY;
        }
        CopyMemory(*uniqueId, _unique_id.data(), *uniqueIdSize);
        return S_OK;
    }

    STDMETHODIMP SignerId(uint32_t* signerIdSize, uint8_t** signerId) override
    {
        if (signerIdSize == nullptr || signerId == nullptr)
        {
            return E_POINTER;
        }
        *signerIdSize = static_cast<uint32_t>(_signer_id.size());
        *signerId = static_cast<uint8_t*>(CoTaskMemAlloc(*signerIdSize));
        if (*signerId == nullptr)
        {
            return E_OUTOFMEMORY;
        }
        CopyMemory(*signerId, _signer_id.data(), *signerIdSize);
        return S_OK;
    }

    STDMETHODIMP ProductId(uint32_t *productIdSize, uint8_t** productId) override
    {
        if (productIdSize == nullptr || productId == nullptr)
        {
            return E_POINTER;
        }
        *productIdSize = static_cast<uint32_t>(_product_id.size());
        *productId = static_cast<uint8_t*>(CoTaskMemAlloc(*productIdSize));
        if (*productId == nullptr)
        {
            return E_OUTOFMEMORY;
        }
        CopyMemory(*productId, _product_id.data(), *productIdSize);
        return S_OK;
    }

    unsigned long _refCount{ 1 };
};

// This is the constructor of a class that has been exported.
CVerifyMetadataCertificates::CVerifyMetadataCertificates()
{
}



HRESULT __stdcall CVerifyMetadataCertificates::VerifyQuoteInCertificate(LPCSTR base64certificate, bool* quoteIsValid)
{
    *quoteIsValid = false;

    auto decodedCert = base64::decode(base64certificate);
    auto rv = oe_verify_attestation_certificate(decodedCert.data(), decodedCert.size(), StaticVerifyMetadataQuote, this);
    if (rv != OE_OK)
    {
        return E_FAIL;
    }
    *quoteIsValid = true;

    return S_OK;
}


extern "C"
{
    HRESULT GetMetadataCertificateVerifier(IVerifyMetadataCertificates** certificateVerifier)
    {
        wil::com_ptr<IVerifyMetadataCertificates> verifier = new CVerifyMetadataCertificates();
        *certificateVerifier = verifier.detach();
        return S_OK;
    }
}