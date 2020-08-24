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

Intel® SGX Attestation sample code demonstrates how to generate a quote from an SGX enclave using Open Enclave SDK / Intel SDK and then get it validated by Microsoft Azure Attestation. 

The components used in the sample code are outlined in the following diagram:
![SGX Attestation Overview Diagram](./media/maa.sample.diagram.png)

The flow is:
1. Build an SGX enclave
2. Launch and SGX enclave and get SGX quote
3. Persist SGX quote and Enclahe Held Data (EHD) to JSON file
4. Call Azure Attestation fro validation
5. Output validation results


