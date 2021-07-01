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

See code sample to perform SGX attestation using [Open Enclave SDK](./sgx.attest.sample)

See code sample to perform SGX attestation using [Intel SDK](./intel.sdk.attest.sample)

## Customer code samples leveraging Azure Attestation

- [EGo's code sample using Azure Attestation](https://github.com/edgelesssys/ego/tree/master/samples/azure_attestation)
- [Azure Attestation integration in SCONE platform](https://github.com/scontain/scone-azure-integration)

