#include <Unknwn.h>
#include <cstdlib>
#include "X509Cert.h"
#include "Sha256Hash.h"
#include <memory>


// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the VERIFYMETADATACERTIFICATES_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// VERIFYMETADATACERTIFICATES_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef VERIFYMETADATACERTIFICATES_EXPORTS
#define VERIFYMETADATACERTIFICATES_API __declspec(dllexport)
#else
#define VERIFYMETADATACERTIFICATES_API __declspec(dllimport)
#endif

extern "C"
{

DECLARE_INTERFACE_IID(IVerifyMetadataCertificates, "46981BEA-6938-4D6F-8339-40C4CAC66E5B") : public IUnknown
{
public:
	STDMETHOD(VerifyQuoteExtensionInCertificate)(LPCSTR base64encodedCertificate, bool* extensionFound) = 0;
	STDMETHOD(VerifyQuoteInExtension)(bool* quoteIsValid) = 0;
	STDMETHOD(VerifyCertificateKeyMatchesHash)(bool* certificateKeyIsValid) = 0;
	STDMETHOD(SecurityVersion)(uint32_t* version) = 0;
	STDMETHOD(ProductId)(uint32_t* productIdSize, uint8_t** productId) = 0;
	STDMETHOD(UniqueId)(uint32_t* uniqueIdSize, uint8_t** uniqueId) = 0;
	STDMETHOD(SignerId)(uint32_t* signerIdSize, uint8_t** signerId) = 0;
	STDMETHOD(ReportData)(uint32_t* reportDataSize, uint8_t** reportData) = 0;
	STDMETHOD(PublicKeyHash)(uint32_t* publicKeyHashSize, uint8_t** publicKeyHash) = 0;
};


VERIFYMETADATACERTIFICATES_API HRESULT GetMetadataCertificateVerifier(IVerifyMetadataCertificates** certificateVerifier);
}
