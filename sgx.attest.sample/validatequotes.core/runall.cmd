@echo off
rem 
rem script to verify all example remote attestation quotes 
rem
dotnet run ../genquotes/quotes/enclave.info.debug.json               sharedcus.cus.attest.azure.net    false
dotnet run ../genquotes/quotes/enclave.info.release.json             sharedcus.cus.attest.azure.net    false
dotnet run ../genquotes/quotes/enclave.info.prodid.json              sharedcus.cus.attest.azure.net    false
dotnet run ../genquotes/quotes/enclave.info.securityversion.json     sharedcus.cus.attest.azure.net    false
