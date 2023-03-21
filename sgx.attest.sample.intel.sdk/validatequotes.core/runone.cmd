@echo off
rem
rem script to verify one of the examples of the remote attestation quotes
rem
dotnet run ../genquotes/out/enclave.info.prodid.json              sharedcus.cus.attest.azure.net    false
