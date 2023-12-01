# Overview

This project contains .NET 6 C# code for a console application that can be used to create signed JWT's to work with the MAA service when it's running in *Isolated* mode.  Since the code is written using .NET 6, it can run on Windows, Linux or a Mac. This tool supports:
* creating a signing key and certificate
* using a signing key + certificate to create a signed policy JWT
* using a signing key + certificate to create a signed certificate JWT

## Background

The [Microsoft Azure Attestation service](https://docs.microsoft.com/en-us/azure/attestation/overview) (MAA) allows users to manage their own attestation provider instance.  Furthermore, MAA enables users to operate their instance in *Isolated* mode.  This means:
* all updates to attestation policy must be authorized by signing the request with a user managed private key
* all updates to the set of trusted signing keys must be authorized by signing the request with a user managed private key

The user must manage an X509 certificate for each private key.  Additionally, to share a signed request with the MAA service, the user must create a specific JWT format as defined in the MAA documentation [here](https://docs.microsoft.com/en-us/azure/attestation/author-sign-policy#creating-the-policy-file-in-json-web-signature-format).  The JWT format is described in great detail in [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519).

## Create a signing key and certificate

The `openssl` tool can be used to create an MAA compatable signing key and certificate.  The maa.signing.tool application explains how when run with the `createsigningcert` command:

```
C:\src\attestation\maa.signing.tool>dotnet run -- createsigningcert

To create a signing key and certificate files follow these steps:

    1. Locate an environment with access to the openssl tool (e.g. WSL shell, Linux Bash)

    2. Switch to a directory where you will store the two generated files

    3. For a password protected key file, run this command:
           openssl req -newkey rsa:2048 -keyout mycert.key -x509 -days 36500 -out mycert.crt

    4. For a non password protected key file, run this command:
           openssl req -newkey rsa:2048 -nodes -keyout mycert.key -x509 -days 36500 -out mycert.crt
```

## Create MAA provider in Isolated Mode

Now that you have generated a signing key and certificate, you can create an MAA attestation provider in *Isolated* mode.  Here is how in PowerShell:

```PowerShell
PS C:\maa> New-AzAttestation -ResourceGroupName gnkdemo -Name isolatedtest001 -Location westus -PolicySignersCertificateFile .\mycert.crt


Id                : /subscriptions/d7e5bff8-d14b-4d3c-a40d-754659ef53b5/resourceGroups/gnkdemo/providers/Microsoft.Attestation/attestationProviders/isolatedtest001
Location          : westus
ResourceGroupName : gnkdemo
Name              : isolatedtest001
Status            : Ready
TrustModel        : Isolated
AttestUri         : https://isolatedtest001.wus.attest.azure.net
Tags              :
TagsTable         :
```

## Create signed policy JWT

To create a signed policy JWT, run the maa.signing.tool using the `signpolicy` command pointing to a text file containing the policy you want to sign.  Specify the `-v` flag if you want a bit more detail about the JWT that's generated.

```
C:\src\attestation\maa.signing.tool>dotnet run -- help signpolicy
maa.signing.tool 1.0.0
Copyright (C) 2021 maa.signing.tool

  -p, --policyfile         Required. Path to text file that contains the MAA policy to be signed into a MAA policy JWT

  -k, --keyfile            Required. Path to PEM formatted file that contains your 2048 bit RSA private key

  -x, --password           Password required to decrypt a PEM formatted key file that is encrypted

  -s, --signingcertfile    Required. Path to PEM formatted file that contains your signing certificate

  -j, --jwtfile            Path to store generated JWT

  -v, --verbose            Enable verbose tracing

  --help                   Display this help screen.

  --version                Display version information.

C:\src\attestation\maa.signing.tool>dotnet run -- signpolicy -p .\policy\deny.all.txt -k \maa\mycert.key -x 12345 -s \maa\mycert.crt -j .\my.signed.policy.txt

Policy JWT:
eyAiYWxnIjoiUlMyNTYiLCAieDVjIjogWyJNSUlEUlRDQ0FpMmdBd0lCQWdJVURWMW43aUc2MDF3ckdLMXA2dU0yQWtBaWNoc3dEUVlKS29aSWh2Y05BUUVMQlFBd01URUxNQWtHQTFVRUJoTUNWVk14RXpBUkJnTlZCQWdNQ2xkaGMyaHBibWQwYjI0eERUQUxCZ05WQkFvTUJGTmxiR1l3SUJjTk1qRXhNVEUwTVRVd056QTNXaGdQTWpFeU1URXdNakV4TlRBM01EZGFNREV4Q3pBSkJnTlZCQVlUQWxWVE1STXdFUVlEVlFRSURBcFhZWE5vYVc1bmRHOXVNUTB3Q3dZRFZRUUtEQVJUWld4bU1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBN2pRWlVRemV5ZEI4dExmTXpnRzZNdUxsclFpTllUNWdjaGJDZVAwNlF1RzZNWEtoMW9EVFAvMkhDVXdXYnovaURDNVROSkVaTVFiUEJDRHNYcktiTFhpNEJRenJzODZuZkZTNCtyZFpGT3BldUtWSmhmSmJKbkJDNW5MekVWc2w2SFFHY08yRGMzbTVhL3VyaURSOTFHZ1JpR1pjditlVHhab0dmUzBXNFJRYytlV0UzVE9YWTVoNFlEWVBnK2JFdFcvMGlJWUxOYmZrdjV6bHMyVEFFTGdFelVGU0ZGLzVOOEk4QllETzFGVFlKZmVEdk90V2hjNzdMZXN4R3d3TGdmRWgrM2FpZkdJMXMrKzdmZHpNRk9Ob3lWZ3hVRWRTUTZyTTM2cEhHWVJpS3hSNnc4eDBDMW1MTHBPUTFJNjV2clhCMmZ1cTFjRkYybml3MFVXd2VRSURBUUFCbzFNd1VUQWRCZ05WSFE0RUZnUVU4WWN0QnY2RXByeXEyWEZRYXE2WDMwQ3NlNWd3SHdZRFZSMGpCQmd3Rm9BVThZY3RCdjZFcHJ5cTJYRlFhcTZYMzBDc2U1Z3dEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFJVGdBZm5RVVpiVlJpOTliUTZNU0pSaUl1RTMvQms5M29EWVlONGE5eERHdm9Zb3ZTZE42bUhpZTNWd1pYUzFublhxc1BGMmpZdEJBNXlpU0tuRU1jNWkyb0xNVEw5N0UwMC9LUmhPN2hZU0F4SWFheVI5bUkwMkdIb2tTYW5kNDZJbVJLT0JSYWJtSjBLNXFhS1hvR0xlMGlkakVtdk1KU0Rlb3ZDdG0yRi90R2c5ME5oZUxuRlZQclhTTlYyTDJqbytnZ0x3SDNnQ0JWWW9jN2trbWNzYktTY3EwczlITlNuOGtDMS9aV0JpUUZIL3hXTWwxVUtLWUNFazlkakpJVE16ZkNxR2NaRnM2YzVqNGhyNEpmdDdIN2l0RDVWSDBWcURnSGlHV2xaakdvUFZCdkR1RWZLVXZpWnVKKzBCWnBKSjhzMWxTVXhLc0xlUldxamZZQmc9PSJdfQ.eyJBdHRlc3RhdGlvblBvbGljeSI6InZlcnNpb249MS4wO1xyXG5cclxuYXV0aG9yaXphdGlvbnJ1bGVzXHJcbntcclxuPT5kZW55KCk7XHJcbn07XHJcblxyXG5pc3N1YW5jZXJ1bGVzXHJcbntcclxufTsifQ.WTua1_Zb5EnYN7YLCueY1uu5U7LV5QeSbojHjXU6BWSQU85FaKqopXtpV3xv4AAsOQvc06B4vXx1dAnNW4bYRPgWuCfOO7sOOfkuxqqRJvzEmCBHiJVFa-CryWvTkH2SRyEqw8Hgs75nrG1rq2im0CEcqPIWyYxPohPUWje82ZA9HE0ncxpv2SZY8tTx_Mt4ox03ondkjjXrRvRJ1Z-AhmeqVH4qhaevAPzPmB5N8SdjYpvwcvcj1_2WJ-vqDeo84lGccy0VeH_ubluPtWZV9shlPKYpR6cnhzEI4WDzUNMnY2lUT6U4-xEP3T3uPw3U2oZnOGMgrsq6-GJY-vdjsA
```

## Update MAA using signed policy JWT

To upload the signed policy JWT, you can use the PowerShell `Set-AzAttestationPolicy` cmdlet:

```PowerShell
PS C:\src\attestation\maa.signing.tool> Set-AzAttestationPolicy -ResourceGroupName gnkdemo -Name isolatedtest001 -Tee OpenEnclave -PolicyFormat JWT -Policy (Get-Content -Path .\my.signed.policy.txt -Raw)

PS C:\src\attestation\maa.signing.tool> Get-AzAttestationPolicy -ResourceGroupName gnkdemo -Name isolatedtest001 -Tee OpenEnclave


Text       : version=1.0;

             authorizationrules
             {
             =>deny();
             };

             issuancerules
             {
             };
TextLength : 76
Jwt        : <base64url JWT here>
JwtLength  : 2040
Algorithm  : RS256

```

## Create signed certificate JWT

To create a signed certificate JWT, run the maa.signing.tool using the `signcert` command pointing to a certificate file containing the certificate you want to sign.  Specify the `-v` flag if you want a bit more detail about the JWT that's generated.  Specify the `-w` flag if you want to generate a JWT that works with the original MAA preview api-version (2018-09-01-preview).

```
C:\src\attestation\maa.signing.tool>dotnet run -- help signcert
maa.signing.tool 1.0.0
Copyright (C) 2023 maa.signing.tool

  -c, --certfile           Required. Path to certificate file to be signed into a MAA certificate JWT

  -w, --preview            Generate files consistent with MAA 2018-09-01-preview api-version

  -k, --keyfile            Required. Path to PEM formatted file that contains your 2048 bit RSA private key

  -x, --password           Password required to decrypt a PEM formatted key file that is encrypted

  -s, --signingcertfile    Required. Path to PEM formatted file that contains your signing certificate

  -j, --jwtfile            Path to store generated JWT

  -v, --verbose            Enable verbose tracing

  --help                   Display this help screen.

  --version                Display version information.
```
Here's an example producing a JWT appropriate for all MAA api-versions except the original preview (2018-09-01-preview):
```
C:\src\github\azure-samples\microsoft-azure-attestation\maa.signing.tool.sample>dotnet run -- signcert -c .\mycert2.crt -k .\mycert.key -s .\mycert.crt -j .\my.signed.cert.ga.txt

Cert JWT:
eyAiYWxnIjoiUlMyNTYiLCAieDVjIjogWyJNSUlEYVRDQ0FsR2dBd0lCQWdJVUpVTFZUSHk3RERpZ3ZzT2RXczk3c1I1UEJ2RXdEUVlKS29aSWh2Y05BUUVMQlFBd1F6RUxNQWtHQTFVRUJoTUNWVk14Q3pBSkJnTlZCQWdNQWxkQk1SRXdEd1lEVlFRSERBaExhWEpyYkdGdVpERVVNQklHQTFVRUNnd0xWMmxrWjJWMGN5QkpibU13SUJjTk1qTXhNakF4TVRNME5EQXpXaGdQTWpFeU16RXhNRGN4TXpRME1ETmFNRU14Q3pBSkJnTlZCQVlUQWxWVE1Rc3dDUVlEVlFRSURBSlhRVEVSTUE4R0ExVUVCd3dJUzJseWEyeGhibVF4RkRBU0JnTlZCQW9NQzFkcFpHZGxkSE1nU1c1ak1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBaVBObGNhVSsrQTZ4VEd1RVhSRHRDb0VES0dieFhJak9ySjBOdWFtMG9nbVBPUk95TTdQNy9nbDdXcFUrd3g2SjRkQzl1cExsd3EwM2JIQStTYS9JUmx1SUt4RU5DdW9XbUF6dk43L1V5dVFqSE0rN1gwRVpteW1HOXFyck9ENHdTYjZkM0hTWW5nQU5YMVVsMDV5UXRtYUl6NTZNcHpLanRxbW85T2IySG14NnZYZ25DZHhwc1pGSXFLVzZ6UUNFSkJjbndFbEtxRjVNcnd4Wjc3VUx4cmpQY1loaW9NOWExc0pKQjZNcXFPQkt2SGFiOGVNbFlCNFBsNC9STzR6R0RDZFR1QlZiWGZMY2xkdHZneC9LRFhRZkFxUEpEU092SmdYWGRKSE9BQXZpKzdEczMvNUsxN21tNVg4M1lyS2FlendpSGFZZ2pHYjNnT1BCN3Y2d3FRSURBUUFCbzFNd1VUQWRCZ05WSFE0RUZnUVVtTTNDaW1sTjVqOSt2eFZzRVlCSnVxUXNaU3d3SHdZRFZSMGpCQmd3Rm9BVW1NM0NpbWxONWo5K3Z4VnNFWUJKdXFRc1pTd3dEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFXRWtTTmdaNUFFbFZJcnl5d2o5aXhLMGs0ZW8vNTNHakZZVzc5bHNvTCtPR1dGeGdIdnlqNktPVW4yOFJqNHpGK0FuaklWb1ZmaG16TTNCd2s1Qm9lT3pDTlFoWXNWd2FqYXlSOEVvZWpZNDN4NjY2NzVESUF2MHU0VFdsd2pHbk9oemUrVGJtcjRvNHlqRGJTMlVQd2JjanJVT2V1OVRMYU9lOFMramhKTlF4N0lRQlp6TzdrV3F1YUQrWlVxVVpsL2ZBcjZlNHhpZlVxazdTZEFhaTB2QW54cllhRDE5TjFWdk1yRlhsZ09DQy9ydFlndk9uTHFwMVpWdCs4VC9qYU1SYjltOTYxTUpsYWdrNllMVm4xUk8wQzNEdE5ESU5YRElqTmdPc254RFFmWC9sQ1JDU2NUUlYvdE5wRFA3S3M2NTF6S0QvWWVpMHZQdGtlc0lYV0E9PSJdfQ.eyJwb2xpY3lDZXJ0aWZpY2F0ZSI6eyJrdHkiOiJSU0EiLCAieDVjIjpbIk1JSURaekNDQWsrZ0F3SUJBZ0lVY1Y4ODFjaFFDeXNTeDBnT2lpQnRJSGNHdGJFd0RRWUpLb1pJaHZjTkFRRUxCUUF3UWpFTE1Ba0dBMVVFQmhNQ1ZWTXhDekFKQmdOVkJBZ01BbGRCTVJFd0R3WURWUVFIREFoQ1pXeHNaWFoxWlRFVE1CRUdBMVVFQ2d3S1RYa2dRMjl0Y0dGdWVUQWdGdzB5TXpFeU1ERXhOelV4TVRaYUdBOHlNVEl6TVRFd056RTNOVEV4Tmxvd1FqRUxNQWtHQTFVRUJoTUNWVk14Q3pBSkJnTlZCQWdNQWxkQk1SRXdEd1lEVlFRSERBaENaV3hzWlhaMVpURVRNQkVHQTFVRUNnd0tUWGtnUTI5dGNHRnVlVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFMa3FOWjdzVGFCS3VpU1ZFdDA0M29BOWRnS254ZkcwTVRqd0hwZHNWT3B3MUxaMjFOSmNiL2R5SmlrWlJBVEdyUlpMbUdZV2M1OHVrSXdQNmlWOXdiYysvM1lCeUdRNlZ5ZlpETzNJSk4yc1FIMzRIM3ZxZmo4MkFrVFBHV1N2Nmlnc2lvRGQ3VGg5WDR5emViOGJwakhudFBVSTVxY1lJeUV1aStxc2NReU9BZE5SSUd2UDNyYU1hZmt0YS9KUGpMUk8rcWdxUnZPdjZzQzdTV3h3d0k4TFVLQWdGTG1adWd6TzRQUC9KM3FIa3JUQUFUZFoxVTArTEV3c21YQ2Jxb2VzSytBcFNRa01HdWZDT3U0ajBiWWllcEhlOXR5TWUwRHB3YVE2S2NKcXNmRXhMSk5sd0tHNlNSR3kzOTg4S1Q5YnhpSnl0cXk2T2dvRVZGUFdqU2NDQXdFQUFhTlRNRkV3SFFZRFZSME9CQllFRk9hYWszREhhQ1Zrek1odEFYSTA2VWk1L0tuQ01COEdBMVVkSXdRWU1CYUFGT2FhazNESGFDVmt6TWh0QVhJMDZVaTUvS25DTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUJLVnRKQTNyUjI5cDNpcW9hZXRiTU02RVFQRTBJY1U0L2Z5SnNvdWF2cm4raGFjWXIwU1FrdTZZemR4dEVhUFBkSEFuNWdDbmsyb251RVd2OStaVkhDN0g5RUt2MGRXL0ZxVmlRa280bXlxRGVDRk1oeVp5OEM1b3owbHZmZUN4SFFucCt2S3VDRElrbXZvMnF2d1kxZXArLzR6eFhSSXVQQThpdE41eDBkWlhTZ2dkTW56Mjc4UGNSUXd5R1NDSERSU0hDWHVXeUt4aVRNTGxMbW0weHdrWGlQcDNRN2FjMkdnMDdMNUNJWUFrK0VEbWxIMnZkdEtxVjBMbFAreFlXZi81RlVCUTN0ZGtRRWRlblhDMHhXdDZaWDMyL2J4OU1NcXg2Vmw4cjF6aDh5SlJEdkJzbC9HdGZNcElobjNSeERlWGQ1eDVFUmFpNTNMaDQ5TjJYaz0iXX19.XSQHnwAMsBz8CJdqIIndwffD2bYnodWvaCweCSdiqeKbcR-d51i-ML5CKvwvqvVdBFFgaj-uAvSB5ugDxbE54ZcuNGIO-3BDmMRTEwvWtGxtg4YYilGFCBuKvaTtMk75fd_QIEOMrdx07Wv1ESGENuZhwhLuIqGhYr7SCvrw2iPIP4i3XBgUaOqxsWMAfZp5ePMqkdqscn-8GwDmalXXKRT57mocLQ6E6c9BLluvvQ81f6ylF5rKlTtNJkaLBqATyh4QtXqsJ8RcPzTyulzcAuxEA6O-WY9b4XCKyIxamxZpaCnaV6ppVi34VY92SnlOkGNR0I5QiDBam_TdhyjszQ

```
Here's an example producing a JWT appropriate for the original MAA preview api-version  (2018-09-01-preview):
```

C:\src\github\azure-samples\microsoft-azure-attestation\maa.signing.tool.sample>dotnet run -- signcert -c .\mycert2.crt -k .\mycert.key -s .\mycert.crt -w -j .\my.signed.cert.preview.txt

Cert JWT:
eyAiYWxnIjoiUlMyNTYiLCAieDVjIjogWyJNSUlEYVRDQ0FsR2dBd0lCQWdJVUpVTFZUSHk3RERpZ3ZzT2RXczk3c1I1UEJ2RXdEUVlKS29aSWh2Y05BUUVMQlFBd1F6RUxNQWtHQTFVRUJoTUNWVk14Q3pBSkJnTlZCQWdNQWxkQk1SRXdEd1lEVlFRSERBaExhWEpyYkdGdVpERVVNQklHQTFVRUNnd0xWMmxrWjJWMGN5QkpibU13SUJjTk1qTXhNakF4TVRNME5EQXpXaGdQTWpFeU16RXhNRGN4TXpRME1ETmFNRU14Q3pBSkJnTlZCQVlUQWxWVE1Rc3dDUVlEVlFRSURBSlhRVEVSTUE4R0ExVUVCd3dJUzJseWEyeGhibVF4RkRBU0JnTlZCQW9NQzFkcFpHZGxkSE1nU1c1ak1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBaVBObGNhVSsrQTZ4VEd1RVhSRHRDb0VES0dieFhJak9ySjBOdWFtMG9nbVBPUk95TTdQNy9nbDdXcFUrd3g2SjRkQzl1cExsd3EwM2JIQStTYS9JUmx1SUt4RU5DdW9XbUF6dk43L1V5dVFqSE0rN1gwRVpteW1HOXFyck9ENHdTYjZkM0hTWW5nQU5YMVVsMDV5UXRtYUl6NTZNcHpLanRxbW85T2IySG14NnZYZ25DZHhwc1pGSXFLVzZ6UUNFSkJjbndFbEtxRjVNcnd4Wjc3VUx4cmpQY1loaW9NOWExc0pKQjZNcXFPQkt2SGFiOGVNbFlCNFBsNC9STzR6R0RDZFR1QlZiWGZMY2xkdHZneC9LRFhRZkFxUEpEU092SmdYWGRKSE9BQXZpKzdEczMvNUsxN21tNVg4M1lyS2FlendpSGFZZ2pHYjNnT1BCN3Y2d3FRSURBUUFCbzFNd1VUQWRCZ05WSFE0RUZnUVVtTTNDaW1sTjVqOSt2eFZzRVlCSnVxUXNaU3d3SHdZRFZSMGpCQmd3Rm9BVW1NM0NpbWxONWo5K3Z4VnNFWUJKdXFRc1pTd3dEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFXRWtTTmdaNUFFbFZJcnl5d2o5aXhLMGs0ZW8vNTNHakZZVzc5bHNvTCtPR1dGeGdIdnlqNktPVW4yOFJqNHpGK0FuaklWb1ZmaG16TTNCd2s1Qm9lT3pDTlFoWXNWd2FqYXlSOEVvZWpZNDN4NjY2NzVESUF2MHU0VFdsd2pHbk9oemUrVGJtcjRvNHlqRGJTMlVQd2JjanJVT2V1OVRMYU9lOFMramhKTlF4N0lRQlp6TzdrV3F1YUQrWlVxVVpsL2ZBcjZlNHhpZlVxazdTZEFhaTB2QW54cllhRDE5TjFWdk1yRlhsZ09DQy9ydFlndk9uTHFwMVpWdCs4VC9qYU1SYjltOTYxTUpsYWdrNllMVm4xUk8wQzNEdE5ESU5YRElqTmdPc254RFFmWC9sQ1JDU2NUUlYvdE5wRFA3S3M2NTF6S0QvWWVpMHZQdGtlc0lYV0E9PSJdfQ.eyJtYWEtcG9saWN5Q2VydGlmaWNhdGUiOnsia3R5IjoiUlNBIiwgIng1YyI6WyJNSUlEWnpDQ0FrK2dBd0lCQWdJVWNWODgxY2hRQ3lzU3gwZ09paUJ0SUhjR3RiRXdEUVlKS29aSWh2Y05BUUVMQlFBd1FqRUxNQWtHQTFVRUJoTUNWVk14Q3pBSkJnTlZCQWdNQWxkQk1SRXdEd1lEVlFRSERBaENaV3hzWlhaMVpURVRNQkVHQTFVRUNnd0tUWGtnUTI5dGNHRnVlVEFnRncweU16RXlNREV4TnpVeE1UWmFHQTh5TVRJek1URXdOekUzTlRFeE5sb3dRakVMTUFrR0ExVUVCaE1DVlZNeEN6QUpCZ05WQkFnTUFsZEJNUkV3RHdZRFZRUUhEQWhDWld4c1pYWjFaVEVUTUJFR0ExVUVDZ3dLVFhrZ1EyOXRjR0Z1ZVRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTGtxTlo3c1RhQkt1aVNWRXQwNDNvQTlkZ0tueGZHME1UandIcGRzVk9wdzFMWjIxTkpjYi9keUppa1pSQVRHclJaTG1HWVdjNTh1a0l3UDZpVjl3YmMrLzNZQnlHUTZWeWZaRE8zSUpOMnNRSDM0SDN2cWZqODJBa1RQR1dTdjZpZ3Npb0RkN1RoOVg0eXplYjhicGpIbnRQVUk1cWNZSXlFdWkrcXNjUXlPQWROUklHdlAzcmFNYWZrdGEvSlBqTFJPK3FncVJ2T3Y2c0M3U1d4d3dJOExVS0FnRkxtWnVnek80UFAvSjNxSGtyVEFBVGRaMVUwK0xFd3NtWENicW9lc0srQXBTUWtNR3VmQ091NGowYllpZXBIZTl0eU1lMERwd2FRNktjSnFzZkV4TEpObHdLRzZTUkd5Mzk4OEtUOWJ4aUp5dHF5Nk9nb0VWRlBXalNjQ0F3RUFBYU5UTUZFd0hRWURWUjBPQkJZRUZPYWFrM0RIYUNWa3pNaHRBWEkwNlVpNS9LbkNNQjhHQTFVZEl3UVlNQmFBRk9hYWszREhhQ1Zrek1odEFYSTA2VWk1L0tuQ01BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFCS1Z0SkEzclIyOXAzaXFvYWV0Yk1NNkVRUEUwSWNVNC9meUpzb3VhdnJuK2hhY1lyMFNRa3U2WXpkeHRFYVBQZEhBbjVnQ25rMm9udUVXdjkrWlZIQzdIOUVLdjBkVy9GcVZpUWtvNG15cURlQ0ZNaHlaeThDNW96MGx2ZmVDeEhRbnArdkt1Q0RJa212bzJxdndZMWVwKy80enhYUkl1UEE4aXRONXgwZFpYU2dnZE1uejI3OFBjUlF3eUdTQ0hEUlNIQ1h1V3lLeGlUTUxsTG1tMHh3a1hpUHAzUTdhYzJHZzA3TDVDSVlBaytFRG1sSDJ2ZHRLcVYwTGxQK3hZV2YvNUZVQlEzdGRrUUVkZW5YQzB4V3Q2WlgzMi9ieDlNTXF4NlZsOHIxemg4eUpSRHZCc2wvR3RmTXBJaG4zUnhEZVhkNXg1RVJhaTUzTGg0OU4yWGs9Il19fQ.ed5q3MDDDJ4DTTDs6uqKBm7dQeIuf4S3zrAI2PE4YxSfb06Bezu473FegSnQbJj0wic8vJXPa9iuF_YnrOuFDLWnk665Tzvt6CsGxgEk6mJ_dX9xQz6kxsv92GYm9CUtGb6TfW505o-jok0r4bw0y7frtnO820nU3Ue9pM4Acyy8U4tcAF9sEUHSOjIzs2HtPWtOAqE78V6PsY2YGCpDaja3u9C4ZhR_YVVPlnWmxse5FRhKaf5TF0105fx1vjby_OJKC88aC7TSqQXvA1rFg534UhFwNPp7DBiRNWBYWmvkNRosUjLykgP4COgNTBXaNFRMCZ43Zk2JqjHhk1GYAw
```

## Update MAA using signed certificate JWT

To upload the signed certificate JWT, you can use the PowerShell `Add-AzAttestationPolicySigner` cmdlet.  Note that after the operation completes, there are now 2 trusted signing certificates.

```PowerShell
PS C:\src\attestation\maa.signing.tool> Add-AzAttestationPolicySigner -ResourceGroupName gnkdemo -Name isolatedtest001 -Signer (Get-Content -Path .\my.signed.cert.txt -Raw)


CertificateCount : 2
Jwt              : <base64url text here>
Algorithm        : RS256
JKU              : https://isolatedtest001.wus.attest.azure.net/certs
Certificates     : {{
                     "alg": "RS256",
                     "kty": "RSA",
                     "use": "sig",
                     "x5c": [
                       "MIIDRTCCAi2gAwIBAgIUDV1n7iG601wrGK1p6uM2AkAichswDQYJKoZIhvcNAQELBQAwMTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xDTALBgNVBAoMBFNlbGYwIBcNMjExMTE0MTUwNzA3WhgPMjEyMTEwMjExNTA3MDdaMDExCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMQ0wCwYDVQQKDA
                   RTZWxmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7jQZUQzeydB8tLfMzgG6MuLlrQiNYT5gchbCeP06QuG6MXKh1oDTP/2HCUwWbz/iDC5TNJEZMQbPBCDsXrKbLXi4BQzrs86nfFS4+rdZFOpeuKVJhfJbJnBC5nLzEVsl6HQGcO2Dc3m5a/uriDR91GgRiGZcv+eTxZoGfS0W4RQc+eWE3TOXY5h4YDYPg+bEtW/0i
                   IYLNbfkv5zls2TAELgEzUFSFF/5N8I8BYDO1FTYJfeDvOtWhc77LesxGwwLgfEh+3aifGI1s++7fdzMFONoyVgxUEdSQ6rM36pHGYRiKxR6w8x0C1mLLpOQ1I65vrXB2fuq1cFF2niw0UWweQIDAQABo1MwUTAdBgNVHQ4EFgQU8YctBv6Epryq2XFQaq6X30Cse5gwHwYDVR0jBBgwFoAU8YctBv6Epryq2XFQaq6X30Cse5gwDwYD
                   VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAITgAfnQUZbVRi99bQ6MSJRiIuE3/Bk93oDYYN4a9xDGvoYovSdN6mHie3VwZXS1nnXqsPF2jYtBA5yiSKnEMc5i2oLMTL97E00/KRhO7hYSAxIaayR9mI02GHokSand46ImRKOBRabmJ0K5qaKXoGLe0idjEmvMJSDeovCtm2F/tGg90NheLnFVPrXSNV2L2jo+ggLwH3gC
                   BVYoc7kkmcsbKScq0s9HNSn8kC1/ZWBiQFH/xWMl1UKKYCEk9djJITMzfCqGcZFs6c5j4hr4Jft7H7itD5VH0VqDgHiGWlZjGoPVBvDuEfKUviZuJ+0BZpJJ8s1lSUxKsLeRWqjfYBg=="
                     ]
                   }, {
                     "alg": "RS256",
                     "kty": "RSA",
                     "use": "sig",
                     "x5c": [
                       "MIIDRzCCAi+gAwIBAgIUewYZXGxv5ZhIT03gC2Q3zdkF50YwDQYJKoZIhvcNAQELBQAwMjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xDjAMBgNVBAoMBVNlbGYyMCAXDTIxMTExNDE1MDc1NloYDzIxMjExMDIxMTUwNzU2WjAyMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjEOMAwGA1UECg
                   wFU2VsZjIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDm1fAYdDSboilmeO5hlMLw96lFWg3AtC8j4TqozuvFY5ANyG0iE3uEGzJtyjfX25Iymncjrx6aPprkM4zea5dsMou4IqucuXBVYx3QorByLrnF3+Fpi8OP+gwRwYrcTpKY71SExqKKZOetDUIPpTR8xqrGDoEl9alsfFRZIQvlCV0JascyfVHajsXul6rLKthJC
                   OiKsCI+x3Qg8p5rCvd1k0ofw2yyZzNQTn/Z/1xdQBN2diVVZwPyrMsHxaE5Ha7J0L1URMe9PpVG+FGcqmKHG23jF3/jGm3PKo7lfCH2A+1XQQBSd+B5TIiswxw7InefA07inm/7ra21LmyjGk9tAgMBAAGjUzBRMB0GA1UdDgQWBBQh3B7u+LaiA40ltVPND3WWtGaUyjAfBgNVHSMEGDAWgBQh3B7u+LaiA40ltVPND3WWtGaUyjAP
                   BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQA7gTfoQbj8L1Srg6xDL7K1Lo0Y22MsOMCkDEg3Dn0qAxk2wNjXdzrV17Bv+mLDiiDrwTnacaDAt/b58vv9BP0PJdisibuJwTfG+pgYnosTlQsRw3hLNLUgX8QlGh19cF7PokhRgdjcnObUPZNJaqbaapUkMD6PZPt77rsPuI1I3CIOKlFvlbkzmq2LSVQFM1grZiG7SQd
                   EBH5mkXvjA6mKuoXrgifwxMSYUFWnu4XPR/p0kh9ANChQMACfMJSbyjMEfQhunH65gFQnc1NOSAQ5J7WomChRt4N2wjdP+OtRpWebW2biwFJlwyGUv1Li3Tk3oOJhymJrzjGNy9TvfZMK"
                     ]
                   }}
```

