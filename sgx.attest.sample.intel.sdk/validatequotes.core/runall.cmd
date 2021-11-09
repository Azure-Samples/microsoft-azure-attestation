@echo off
rem 
rem script to verify all example remote attestation quotes 
rem
dotnet run ../genquotes/out/enclave.info.debug.json               sharedcus.cus.attest.azure.net    true
dotnet run ../genquotes/out/enclave.info.release.json             sharedcus.cus.attest.azure.net    true
dotnet run ../genquotes/out/enclave.info.prodid.json              sharedcus.cus.attest.azure.net    true
dotnet run ../genquotes/out/enclave.info.securityversion.json     sharedcus.cus.attest.azure.net    true
