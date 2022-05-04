---
page_type: sample
languages:
- c
- csharp
products:
  - azure
description: "Learn how to perform Intel® SGX Attestation using Microsoft Azure Attestation and Open Enclave SDK."
--- 

# Sample code for Intel® SGX Attestation using Microsoft Azure Attestation and Open Enclave SDK for Linux OS

Intel® SGX Attestation sample code demonstrates how to generate a quote from an SGX enclave using Open Enclave SDK and then get it validated by Microsoft Azure Attestation. The "enclave held data" for the quote is populated with public key component of a 2048 bit RSA key that's held within the enclave.

The components used in the sample code are outlined in the following diagram:
![SGX Attestation Overview Diagram](../media/maa.sample.diagram.png)

The flow is:
1. ```genquote_host``` - This application is run first and performs the following:
    1. Launches the ```genquote_enclave``` SGX enclave
    1. Calls into the enclave (via an ecall) to retrieve a remote quote and a copy of the enclave held data, which in this case is the public key for a 2048 bit RSA key
    1. Calls into the Open Enclave SDK to parse the remote quote to retrieve important attributes like Security Version Number, ProductID, MRSIGNER, MRENCLAVE, etc.
    1. Persists the remote quote, enclave held data and parsed report fields to a JSON file on disk
1. ```genquote_enclave``` - This application is an SGX enclave created via the Open Enclave SDK.  It exposes one ecall to retrieve a remote quote and enclave held data.
1. ```validatequotes.core``` - This application is built on .NET core and runs on any platform.  It consumes the JSON file persisted by the ```genquote_host``` application and performs the following:
    1. Calls the Azure Attestation for validation, passing it the remote quote and enclave held data found in the JSON file
    1. Validates that the Azure Attestation JWT passes signature validation and is issued by the expected party
    1. Validates that the Azure Attestation JWT claim values match the parsed data in the JSON file for the well known fields like Security Version Number, ProductID, MRSIGNER, MRENCLAVE, etc.
    1. Produces a report in the console with the results
1. ```validatequotes.net``` - This application is build on the .NET framework and only runs on Windows.  It performs all the validation performed by ```validatequotes.core``` and additionally validates the Azure Attestation SGX quote embedded in its signing certificate using the Open Enclave SDK locally.  The additional steps are:
    1. Checks for the presence of an SGX quote for the Azure Attestation itself as an extension in the Azure Attestation X.509 signing certificate.
    1. Verifies the SGX quote with the Open Enclve SDK's ```oe_verify_remote_report``` API.
    1. Verifies that the hash of the public key that signed the JWT token matches the report data in the verified quote.

The following diagram depicts the relationship between the different artifacts produced the Azure Attestation for JWT token validation.
![JWT Validation Overview Diagram](../media/maa.jwt.validation.overview.png)


## Remote Quote Generation
*Note: The SGX enclave code in this sample is derived from the [remote_attestation sample code](https://github.com/openenclave/openenclave/tree/master/samples/remote_attestation) in Open Enclave SDK.  Many thanks to the author(s)!*

Remote quote generation is performed by the following call to the ```oe_get_report``` method in the [attestation.cpp](../sgx.attest.sample/genquotes/common/attestation.cpp#L43) file in the ```genquote_enclave``` application.
```
result = oe_get_report(
    OE_REPORT_FLAGS_REMOTE_ATTESTATION,
    sha256,
    sizeof(sha256),
    NULL, 
    0,
    &temp_buf,
    remote_report_buf_size);
```

## Remote Quote Validation via Azure Attestation

Azure Attestation is called to perform attestation by the following call in the [MaaService.cs](../sgx.attest.sample/validatequotes.core/MaaService.cs#L32) file:

```
// Send request
var response = await theHttpClient.SendAsync(request);
```

The verification that the Azure Attestation JWT passes signature validation and is issued by the expected issuer is in the  [JwtValidationHelper.cs](../sgx.attest.sample/validatequotes.core/Helpers/JwtValidationHelper.cs#L15) file:
```
public static TokenValidationResult ValidateMaaJwt(string attestDnsName, string serviceJwt, bool includeDetails)
```

The verification that the Azure Attestation JWT claims match the initial parsed report data is performed in the [EnclaveInfo.cs](../sgx.attest.sample/validatequotes.core/EnclaveInfo.cs#L31) file:
```
public void CompareToMaaServiceJwtToken(string serviceJwtToken, bool includeDetails)
```

If the Azure Attestation service is running within an SGX enclave, the validation of the Azure Attestation service quote is performed in the [MaaQuoteValidator.cs](./validatequotes.net/MaaQuoteValidator.cs#L41) file:
```
    static public void ValidateMaaQuote(string x5c, bool includeDetails)
```

## Instructions to Build and Run Yourself

To set up the pre-requisites to build and run these samples:
1. Install Ubuntu 18.04 on an [Azure Confidential Compute](https://azure.microsoft.com/en-us/solutions/confidential-compute/) VM.
1. Install the [Open Enclave SDK](https://github.com/openenclave/openenclave/blob/v0.9.x/docs/GettingStartedDocs/install_oe_sdk-Ubuntu_18.04.md) on this VM.  You don't need to install Ninja or CMake -- they are not used here.
1. Add the command "```. /opt/openenclave/share/openenclave/openenclaverc```" to your ~/.bashrc file.
1. Install the [.NET 5.0 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/5.0) on this VM.
    1. `wget https://packages.microsoft.com/config/ubuntu/18.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb`
    1. `sudo dpkg -i packages-microsoft-prod.deb`
    1. `rm packages-microsoft-prod.deb`
    1. `sudo apt update`
    1. `sudo apt install -y apt-transport-https && sudo apt update && sudo apt install -y dotnet-sdk-5.0`

To build and run the samples:
1. ```git clone``` this repo to the VM
1. ```cd``` to the subdirectory containing this sample code
1. To build, run and generate the JSON files do the following:
    1. ```cd genquotes```
    1. ```make build```
    1. ```sudo make run```
    1. This runs the application in four different enclave configurations to generate four different remote quotes.  You should see four new files created in the ```../quotes``` directory.
1. To build, run and validate the JSON files with Azure Attestation do the following:
    1. ```cd validatequotes.core```
    1. ```./runall.sh```
    1. This builds and runs the validation application against the four different JSON files produced earlier.

The four different JSON files are:
* *enclave.info.debug.json* - debugging enabled
* *enclave.info.release.json* - debugging disabled
* *enclave.info.securityversion.json* - security version set to 999
* *enclave.info.prodid.json* - product id set to 999

## Example Output for make run
Here is an example of what the output of ```make run``` should look like:

```
greg@gnksgxlinuxvm0:~/src/github/maa-sample/sgx.attest.sample/genquotes$ sudo make run
host/genquote_host ./enclave/genquote_enclave.debug.signed              enclave.info.debug.json
    JSON file created: enclave.info.debug.json
host/genquote_host ./enclave/genquote_enclave.release.signed            enclave.info.release.json
    JSON file created: enclave.info.release.json
host/genquote_host ./enclave/genquote_enclave.prodid.signed             enclave.info.prodid.json
    JSON file created: enclave.info.prodid.json
host/genquote_host ./enclave/genquote_enclave.securityversion.signed    enclave.info.securityversion.json
    JSON file created: enclave.info.securityversion.json
```

## Example Output for ./runall.sh
Here is an example of what the output of ```./runall.sh``` should look like:

```
greg@gnksgxlinuxvm0:~/src/github/maa-sample/sgx.attest.sample/validatequotes.core$ ./runall.sh 
[16:52:29.213] : 
[16:52:29.235] : ************************************************************************************************************************
[16:52:29.235] : *      PARAMETERS FOR THIS RUN
[16:52:29.235] : ************************************************************************************************************************
[16:52:29.235] : Validating filename                : ../genquotes/quotes/enclave.info.debug.json
[16:52:29.235] : Using attestation provider         : sharedcus.cus.attest.azure.net
[16:52:29.235] : Including details                  : False
[16:52:29.870] : 
[16:52:29.870] : ************************************************************************************************************************
[16:52:29.870] : *      VALIDATING MAA JWT TOKEN - BASICS
[16:52:29.870] : ************************************************************************************************************************
[16:52:29.893] : JWT JKU location validation        : True
[16:52:30.325] : JWT signature validation           : True
[16:52:30.326] : JWT issuer claim validation        : True
[16:52:30.326] : JWT signing cert issuer validation : True
[16:52:30.326] : 
[16:52:30.326] : ************************************************************************************************************************
[16:52:30.326] : *      VALIDATING MAA JWT TOKEN - MATCHES CLIENT ENCLAVE INFO
[16:52:30.326] : ************************************************************************************************************************
[16:52:30.328] : IsDebuggable match                 : True
[16:52:30.328] : MRENCLAVE match                    : True
[16:52:30.328] : MRSIGNER match                     : True
[16:52:30.329] : ProductID match                    : True
[16:52:30.329] : Security Version match             : True
[16:52:30.329] : Enclave Held Data match            : True
[16:52:30.329] : 
[16:52:31.485] : 
[16:52:31.507] : ************************************************************************************************************************
[16:52:31.507] : *      PARAMETERS FOR THIS RUN
[16:52:31.507] : ************************************************************************************************************************
[16:52:31.507] : Validating filename                : ../genquotes/quotes/enclave.info.release.json
[16:52:31.507] : Using attestation provider         : sharedcus.cus.attest.azure.net
[16:52:31.507] : Including details                  : False
[16:52:31.976] : 
[16:52:31.976] : ************************************************************************************************************************
[16:52:31.976] : *      VALIDATING MAA JWT TOKEN - BASICS
[16:52:31.976] : ************************************************************************************************************************
[16:52:32.011] : JWT JKU location validation        : True
[16:52:32.477] : JWT signature validation           : True
[16:52:32.477] : JWT issuer claim validation        : True
[16:52:32.478] : JWT signing cert issuer validation : True
[16:52:32.478] : 
[16:52:32.478] : ************************************************************************************************************************
[16:52:32.478] : *      VALIDATING MAA JWT TOKEN - MATCHES CLIENT ENCLAVE INFO
[16:52:32.478] : ************************************************************************************************************************
[16:52:32.480] : IsDebuggable match                 : True
[16:52:32.480] : MRENCLAVE match                    : True
[16:52:32.480] : MRSIGNER match                     : True
[16:52:32.480] : ProductID match                    : True
[16:52:32.480] : Security Version match             : True
[16:52:32.480] : Enclave Held Data match            : True
[16:52:32.480] : 
[16:52:33.641] : 
[16:52:33.662] : ************************************************************************************************************************
[16:52:33.662] : *      PARAMETERS FOR THIS RUN
[16:52:33.662] : ************************************************************************************************************************
[16:52:33.662] : Validating filename                : ../genquotes/quotes/enclave.info.prodid.json
[16:52:33.662] : Using attestation provider         : sharedcus.cus.attest.azure.net
[16:52:33.662] : Including details                  : False
[16:52:34.195] : 
[16:52:34.195] : ************************************************************************************************************************
[16:52:34.195] : *      VALIDATING MAA JWT TOKEN - BASICS
[16:52:34.195] : ************************************************************************************************************************
[16:52:34.216] : JWT JKU location validation        : True
[16:52:34.567] : JWT signature validation           : True
[16:52:34.567] : JWT issuer claim validation        : True
[16:52:34.567] : JWT signing cert issuer validation : True
[16:52:34.567] : 
[16:52:34.567] : ************************************************************************************************************************
[16:52:34.567] : *      VALIDATING MAA JWT TOKEN - MATCHES CLIENT ENCLAVE INFO
[16:52:34.567] : ************************************************************************************************************************
[16:52:34.569] : IsDebuggable match                 : True
[16:52:34.570] : MRENCLAVE match                    : True
[16:52:34.570] : MRSIGNER match                     : True
[16:52:34.570] : ProductID match                    : True
[16:52:34.570] : Security Version match             : True
[16:52:34.570] : Enclave Held Data match            : True
[16:52:34.570] : 
[16:52:35.705] : 
[16:52:35.727] : ************************************************************************************************************************
[16:52:35.727] : *      PARAMETERS FOR THIS RUN
[16:52:35.727] : ************************************************************************************************************************
[16:52:35.727] : Validating filename                : ../genquotes/quotes/enclave.info.securityversion.json
[16:52:35.727] : Using attestation provider         : sharedcus.cus.attest.azure.net
[16:52:35.727] : Including details                  : False
[16:52:36.328] : 
[16:52:36.328] : ************************************************************************************************************************
[16:52:36.328] : *      VALIDATING MAA JWT TOKEN - BASICS
[16:52:36.328] : ************************************************************************************************************************
[16:52:36.350] : JWT JKU location validation        : True
[16:52:36.779] : JWT signature validation           : True
[16:52:36.779] : JWT issuer claim validation        : True
[16:52:36.779] : JWT signing cert issuer validation : True
[16:52:36.779] : 
[16:52:36.779] : ************************************************************************************************************************
[16:52:36.779] : *      VALIDATING MAA JWT TOKEN - MATCHES CLIENT ENCLAVE INFO
[16:52:36.779] : ************************************************************************************************************************
[16:52:36.781] : IsDebuggable match                 : True
[16:52:36.781] : MRENCLAVE match                    : True
[16:52:36.782] : MRSIGNER match                     : True
[16:52:36.782] : ProductID match                    : True
[16:52:36.782] : Security Version match             : True
[16:52:36.782] : Enclave Held Data match            : True
[16:52:36.782] : 
```


