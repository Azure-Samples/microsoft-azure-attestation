// VerifyMetadataCertificates.cpp : Defines the exported functions for the DLL.
//

#include "framework.h"
#include "VerifyMetadataCertificates.h"
#pragma warning(push)
#pragma warning(disable: 6319)
#include <wil\com.h>
#pragma warning(pop)
#pragma warning(push)
#pragma warning(disable: 26812)
#include <openenclave\host.h>
#include <openenclave\host_verify.h>
#include <openenclave\plugin.h>
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
    // Inherited via IVerifyMetadataCertificates
    virtual HRESULT __stdcall VerifyQuoteExtensionInCertificate(LPCSTR base64encodedCertificate, bool* extensionFound) override;
    virtual HRESULT __stdcall VerifyQuoteInExtension(bool* quoteIsValid) override;
    virtual HRESULT __stdcall VerifyCertificateKeyMatchesHash(bool* certificateKeyIsValid) override;
    virtual HRESULT __stdcall SecurityVersion(uint32_t *version) override
    {
        if (!version)
        {
            return E_POINTER;
        }

        *version = _parsedReport.identity.security_version;
        return S_OK;
    }

    STDMETHODIMP UniqueId(uint32_t* uniqueIdSize, uint8_t** uniqueId) override
    {
        if (uniqueIdSize == nullptr || uniqueId == nullptr)
        {
            return E_POINTER;
        }
        *uniqueIdSize = sizeof(_parsedReport.identity.unique_id);
        *uniqueId = static_cast<uint8_t*>(CoTaskMemAlloc(*uniqueIdSize));
        if (*uniqueId == nullptr)
        {
            return E_OUTOFMEMORY;
        }
        CopyMemory(*uniqueId, _parsedReport.identity.unique_id, *uniqueIdSize);
        return S_OK;
    }

    STDMETHODIMP SignerId(uint32_t* signerIdSize, uint8_t** signerId) override
    {
        if (signerIdSize == nullptr || signerId == nullptr)
        {
            return E_POINTER;
        }
        *signerIdSize = sizeof(_parsedReport.identity.signer_id);
        *signerId = static_cast<uint8_t*>(CoTaskMemAlloc(*signerIdSize));
        if (*signerId == nullptr)
        {
            return E_OUTOFMEMORY;
        }
        CopyMemory(*signerId, _parsedReport.identity.signer_id, *signerIdSize);
        return S_OK;
    }

    STDMETHODIMP ProductId(uint32_t *productIdSize, uint8_t** productId) override
    {
        if (productIdSize == nullptr || productId == nullptr)
        {
            return E_POINTER;
        }
        *productIdSize = sizeof(_parsedReport.identity.product_id);
        *productId = static_cast<uint8_t*>(CoTaskMemAlloc(*productIdSize));
        if (*productId == nullptr)
        {
            return E_OUTOFMEMORY;
        }
        CopyMemory(*productId, _parsedReport.identity.product_id, *productIdSize);
        return S_OK;
    }

    STDMETHODIMP ReportData(uint32_t* reportDataSize, uint8_t** reportData) override
    {
        if (reportDataSize == nullptr || reportData == nullptr)
        {
            return E_POINTER;
        }
        *reportDataSize = static_cast<uint32_t>(_parsedReport.report_data_size);
        *reportData = static_cast<uint8_t*>(CoTaskMemAlloc(*reportDataSize));
        if (*reportData == nullptr)
        {
            return E_OUTOFMEMORY;
        }
        CopyMemory(*reportData, _parsedReport.report_data, *reportDataSize);
        return S_OK;
    }

    STDMETHODIMP PublicKeyHash(uint32_t* publicKeyHashSize, uint8_t** publicKeyHash) override
    {
        if (publicKeyHashSize == nullptr || publicKeyHash == nullptr)
        {
            return E_POINTER;
        }

        RETURN_IF_FAILED(EnsurePublicKeyHash());
        *publicKeyHashSize = static_cast<uint32_t>(_publicKeyHash.size());
        *publicKeyHash = static_cast<uint8_t*>(CoTaskMemAlloc(*publicKeyHashSize));
        if (*publicKeyHash == nullptr)
        {
            return E_OUTOFMEMORY;
        }
        CopyMemory(*publicKeyHash, _publicKeyHash.data(), *publicKeyHashSize);
        return S_OK;
    }

    HRESULT EnsurePublicKeyHash()
    {
        if (_publicKeyHash.empty())
        {
            std::string serializedPublicKey = _workingCert->ExportPublicKeyAsPEM();

            // The MAA generates the hash over the PEM encoded public key, including the trailing null terminator.
            auto ehd(std::vector<uint8_t>(serializedPublicKey.begin(), serializedPublicKey.end()));
            ehd.push_back(0);

            auto hasher = Sha256Hash::Create();
            _publicKeyHash = hasher->HashAndFinish(ehd);
        }
        return S_OK;
    }

    unsigned long _refCount{ 1 };
    std::unique_ptr<X509Cert> _workingCert;
    std::vector<uint8_t> _quoteExtension;
    std::vector<uint8_t> _oe_quote;
    std::vector<uint8_t> _publicKeyHash;

    oe_report_t _parsedReport{ 0 };


};

// This is the constructor of a class that has been exported.
CVerifyMetadataCertificates::CVerifyMetadataCertificates()
{
}

HRESULT __stdcall CVerifyMetadataCertificates::VerifyQuoteExtensionInCertificate(LPCSTR base64encodedCertificate, bool* extensionFound)
{
    *extensionFound = false;
    std::unique_ptr<X509Cert> cert;
    std::vector<uint8_t> quoteExtension;

    cert = X509Cert::Deserialize(base64encodedCertificate);
    quoteExtension = cert->FindExtension(SgxExtensionOidX);
    if (!quoteExtension.empty())
    {
        cert.swap(_workingCert);
        _quoteExtension = std::move(quoteExtension);
        *extensionFound = true;
        return S_OK;
        
    }
    return E_FAIL;
}

/*
**==============================================================================
**
** oe_report_type_t
**
**==============================================================================
*/
enum class oe_report_type
{
    OE_REPORT_TYPE_SGX_LOCAL = 1,
    OE_REPORT_TYPE_SGX_REMOTE = 2
};

/*
**==============================================================================
**
** oe_report_header_t
**
**==============================================================================
*/
struct oe_report_header
{
    uint32_t version;
    oe_report_type report_type;
    size_t report_size;
};

HRESULT __stdcall CVerifyMetadataCertificates::VerifyQuoteInExtension(bool* quoteIsValid)
{
    *quoteIsValid = false;

    auto quote = _workingCert->ExtractOctetString(_quoteExtension);
    // The quote embedded in the extension is an SGX quote. The oe_verify_remote_report API requires an OE remote quote, so
    // transform the SGX quote into an OE quote.
    oe_report_header header;

    header.version = 1;
    header.report_size = quote.size();
    header.report_type = oe_report_type::OE_REPORT_TYPE_SGX_REMOTE;
    auto headerVector(std::vector<uint8_t>(reinterpret_cast<uint8_t*>(&header), reinterpret_cast<uint8_t*>(&header + 1)));
    _oe_quote.insert(_oe_quote.end(), headerVector.begin(), headerVector.end());
    _oe_quote.insert(_oe_quote.end(), quote.begin(), quote.end());
#pragma warning(push)
#pragma warning(disable:26812)
    auto rv = oe_verify_remote_report(_oe_quote.data(), _oe_quote.size(), nullptr, 0, &_parsedReport);
#pragma warning(pop)
    if (rv != OE_OK)
    {
        return E_FAIL;
    }
    *quoteIsValid = true;

    return S_OK;
}

HRESULT __stdcall CVerifyMetadataCertificates::VerifyCertificateKeyMatchesHash(bool* certificateKeyIsValid)
{
    *certificateKeyIsValid = false;

    RETURN_IF_FAILED(EnsurePublicKeyHash());

    if (_publicKeyHash.size() > _parsedReport.report_data_size)
    {
        return E_FAIL;
    }

    if (memcmp(_publicKeyHash.data(), _parsedReport.report_data, _publicKeyHash.size()) != 0)
    {
        return E_FAIL;
    }

    *certificateKeyIsValid = true;
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