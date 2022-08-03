---
page_type: sample
languages:
- c
- csharp
products:
  - azure
description: "Learn how to perform Intel® SGX Attestation using Microsoft Azure Attestation"
---

# Sample code for Intel® SGX Attestation using Microsoft Azure Attestation

Intel® SGX Attestation sample code demonstrates how to generate a quote from an SGX enclave using Open Enclave SDK / Intel SDK and then get it validated by Microsoft Azure Attestation. The "enclave held data" for the quote is populated with public key component that's held within the enclave.

The components used in the sample code are outlined in the following diagram:
![SGX Attestation Overview Diagram](./media/maa.sample.diagram.png)

The flow is:
1. Build an SGX enclave
2. Launch an SGX enclave and get SGX quote
3. Persist SGX quote and Enclave Held Data (EHD) to JSON file
4. Call Azure Attestation for validation
5. Output validation results

See code sample to perform SGX attestation using [Open Enclave SDK](./sgx.attest.sample.oe.sdk)

See code sample to perform SGX attestation using [Intel SDK](./sgx.attest.sample.intel.sdk)

# Sample code to manage trusted signing certificates for Isolated providers

The [Microsoft Azure Attestation service](https://docs.microsoft.com/en-us/azure/attestation/overview) (MAA) allows users to manage their own attestation provider instance.  Furthermore, MAA enables users to operate their instance in *Isolated* mode.  This means:
* all updates to attestation policy must be authorized by signing the request with a user managed private key
* all updates to the set of trusted signing keys must be authorized by signing the request with a user managed private key

The user must manage an X509 certificate for each private key.  Additionally, to share a signed request with the MAA service, the user must create a specific JWT format as defined in the MAA documentation [here](https://docs.microsoft.com/en-us/azure/attestation/author-sign-policy#creating-the-policy-file-in-json-web-signature-format).  The JWT format is described in great detail in [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519).

See a code sample to manage trusted signing certificates and keys for Isolated providers [here](./maa.signing.tool.sample)

# Customer code samples leveraging Azure Attestation

- [EGo's code sample using Azure Attestation](https://github.com/edgelesssys/ego/tree/master/samples/azure_attestation)
- [Azure Attestation integration in SCONE platform](https://github.com/scontain/scone-azure-integration)
- [Azure Attestation integration in Occlum](https://github.com/occlum/occlum/tree/master/demos/remote_attestation/azure_attestation)

