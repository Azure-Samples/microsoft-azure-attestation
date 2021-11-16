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

To create a signed certificate JWT, run the maa.signing.tool using the `signcert` command pointing to a certificate file containing the certificate you want to sign.  Specify the `-v` flag if you want a bit more detail about the JWT that's generated.

```
C:\src\attestation\maa.signing.tool>dotnet run -- help signcert
maa.signing.tool 1.0.0
Copyright (C) 2021 maa.signing.tool

  -c, --certfile           Required. Path to certificate file to be signed into a MAA certificate JWT

  -k, --keyfile            Required. Path to PEM formatted file that contains your 2048 bit RSA private key

  -x, --password           Password required to decrypt a PEM formatted key file that is encrypted

  -s, --signingcertfile    Required. Path to PEM formatted file that contains your signing certificate

  -j, --jwtfile            Path to store generated JWT

  -v, --verbose            Enable verbose tracing

  --help                   Display this help screen.

  --version                Display version information.

C:\src\attestation\maa.signing.tool>dotnet run -- signcert -c \maa\mycert2.crt -k \maa\mycert.key -x 12345 -s \maa\mycert.crt -j .\my.signed.cert.txt

Cert JWT:
eyAiYWxnIjoiUlMyNTYiLCAieDVjIjogWyJNSUlEUlRDQ0FpMmdBd0lCQWdJVURWMW43aUc2MDF3ckdLMXA2dU0yQWtBaWNoc3dEUVlKS29aSWh2Y05BUUVMQlFBd01URUxNQWtHQTFVRUJoTUNWVk14RXpBUkJnTlZCQWdNQ2xkaGMyaHBibWQwYjI0eERUQUxCZ05WQkFvTUJGTmxiR1l3SUJjTk1qRXhNVEUwTVRVd056QTNXaGdQTWpFeU1URXdNakV4TlRBM01EZGFNREV4Q3pBSkJnTlZCQVlUQWxWVE1STXdFUVlEVlFRSURBcFhZWE5vYVc1bmRHOXVNUTB3Q3dZRFZRUUtEQVJUWld4bU1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBN2pRWlVRemV5ZEI4dExmTXpnRzZNdUxsclFpTllUNWdjaGJDZVAwNlF1RzZNWEtoMW9EVFAvMkhDVXdXYnovaURDNVROSkVaTVFiUEJDRHNYcktiTFhpNEJRenJzODZuZkZTNCtyZFpGT3BldUtWSmhmSmJKbkJDNW5MekVWc2w2SFFHY08yRGMzbTVhL3VyaURSOTFHZ1JpR1pjditlVHhab0dmUzBXNFJRYytlV0UzVE9YWTVoNFlEWVBnK2JFdFcvMGlJWUxOYmZrdjV6bHMyVEFFTGdFelVGU0ZGLzVOOEk4QllETzFGVFlKZmVEdk90V2hjNzdMZXN4R3d3TGdmRWgrM2FpZkdJMXMrKzdmZHpNRk9Ob3lWZ3hVRWRTUTZyTTM2cEhHWVJpS3hSNnc4eDBDMW1MTHBPUTFJNjV2clhCMmZ1cTFjRkYybml3MFVXd2VRSURBUUFCbzFNd1VUQWRCZ05WSFE0RUZnUVU4WWN0QnY2RXByeXEyWEZRYXE2WDMwQ3NlNWd3SHdZRFZSMGpCQmd3Rm9BVThZY3RCdjZFcHJ5cTJYRlFhcTZYMzBDc2U1Z3dEd1lEVlIwVEFRSC9CQVV3QXdFQi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFJVGdBZm5RVVpiVlJpOTliUTZNU0pSaUl1RTMvQms5M29EWVlONGE5eERHdm9Zb3ZTZE42bUhpZTNWd1pYUzFublhxc1BGMmpZdEJBNXlpU0tuRU1jNWkyb0xNVEw5N0UwMC9LUmhPN2hZU0F4SWFheVI5bUkwMkdIb2tTYW5kNDZJbVJLT0JSYWJtSjBLNXFhS1hvR0xlMGlkakVtdk1KU0Rlb3ZDdG0yRi90R2c5ME5oZUxuRlZQclhTTlYyTDJqbytnZ0x3SDNnQ0JWWW9jN2trbWNzYktTY3EwczlITlNuOGtDMS9aV0JpUUZIL3hXTWwxVUtLWUNFazlkakpJVE16ZkNxR2NaRnM2YzVqNGhyNEpmdDdIN2l0RDVWSDBWcURnSGlHV2xaakdvUFZCdkR1RWZLVXZpWnVKKzBCWnBKSjhzMWxTVXhLc0xlUldxamZZQmc9PSJdfQ.eyJtYWEtcG9saWN5Q2VydGlmaWNhdGUiOnsia3R5IjoiUlNBIiwgIng1YyI6WyJNSUlEUnpDQ0FpK2dBd0lCQWdJVWV3WVpYR3h2NVpoSVQwM2dDMlEzemRrRjUwWXdEUVlKS29aSWh2Y05BUUVMQlFBd01qRUxNQWtHQTFVRUJoTUNWVk14RXpBUkJnTlZCQWdNQ2xkaGMyaHBibWQwYjI0eERqQU1CZ05WQkFvTUJWTmxiR1l5TUNBWERUSXhNVEV4TkRFMU1EYzFObG9ZRHpJeE1qRXhNREl4TVRVd056VTJXakF5TVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tWMkZ6YUdsdVozUnZiakVPTUF3R0ExVUVDZ3dGVTJWc1pqSXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFEbTFmQVlkRFNib2lsbWVPNWhsTUx3OTZsRldnM0F0QzhqNFRxb3p1dkZZNUFOeUcwaUUzdUVHekp0eWpmWDI1SXltbmNqcng2YVBwcmtNNHplYTVkc01vdTRJcXVjdVhCVll4M1FvckJ5THJuRjMrRnBpOE9QK2d3UndZcmNUcEtZNzFTRXhxS0taT2V0RFVJUHBUUjh4cXJHRG9FbDlhbHNmRlJaSVF2bENWMEphc2N5ZlZIYWpzWHVsNnJMS3RoSkNPaUtzQ0kreDNRZzhwNXJDdmQxazBvZncyeXlaek5RVG4vWi8xeGRRQk4yZGlWVlp3UHlyTXNIeGFFNUhhN0owTDFVUk1lOVBwVkcrRkdjcW1LSEcyM2pGMy9qR20zUEtvN2xmQ0gyQSsxWFFRQlNkK0I1VElpc3d4dzdJbmVmQTA3aW5tLzdyYTIxTG15akdrOXRBZ01CQUFHalV6QlJNQjBHQTFVZERnUVdCQlFoM0I3dStMYWlBNDBsdFZQTkQzV1d0R2FVeWpBZkJnTlZIU01FR0RBV2dCUWgzQjd1K0xhaUE0MGx0VlBORDNXV3RHYVV5akFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUJBUUE3Z1Rmb1FiajhMMVNyZzZ4REw3SzFMbzBZMjJNc09NQ2tERWczRG4wcUF4azJ3TmpYZHpyVjE3QnYrbUxEaWlEcndUbmFjYURBdC9iNTh2djlCUDBQSmRpc2lidUp3VGZHK3BnWW5vc1RsUXNSdzNoTE5MVWdYOFFsR2gxOWNGN1Bva2hSZ2RqY25PYlVQWk5KYXFiYWFwVWtNRDZQWlB0Nzdyc1B1STFJM0NJT0tsRnZsYmt6bXEyTFNWUUZNMWdyWmlHN1NRZEVCSDVta1h2akE2bUt1b1hyZ2lmd3hNU1lVRldudTRYUFIvcDBraDlBTkNoUU1BQ2ZNSlNieWpNRWZRaHVuSDY1Z0ZRbmMxTk9TQVE1SjdXb21DaFJ0NE4yd2pkUCtPdFJwV2ViVzJiaXdGSmx3eUdVdjFMaTNUazNvT0poeW1KcnpqR055OVR2ZlpNSyJdfX0.M0rVb1BMXtgeATjucW0UcV1_z78Wec-9O6Sf5SJ7p2ZyltpxCa8jq8Fj4t2XDaoCp-XscVIWFKJc8bxZoiWNZgUduZMYxDUTO0O02RGHsTqqB4RdtN6IbCGx1iYImDLjnvJbTEetr2iAsIkGIr5JgjIaNmJOHq_mLXgm1ydM4xb8qMDb4cCk1exArN96RBw6ICk5rZTx0gxmIqyASkIps184eAcbrTTKH8YD1Y9ZqXZPXjlqtu5QlfXu1PLlBAUeKRsCQQUTz0_FMjAX6NWSlBFjt5QFYkH7fXpmkwkEEf0CR7Wq71AIaA8psPEO6UIKs_k9QHXTKU3x7jv233ziiA
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

