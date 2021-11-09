#!/bin/bash
# 
# Script to verify all example remote attestation quotes
#
dotnet run ../genquotes/out/enclave.info.debug.json              sharedcus.cus.attest.azure.net    true
dotnet run ../genquotes/out/enclave.info.release.json            sharedcus.cus.attest.azure.net    true
dotnet run ../genquotes/out/enclave.info.prodid.json             sharedcus.cus.attest.azure.net    true
dotnet run ../genquotes/out/enclave.info.securityversion.json    sharedcus.cus.attest.azure.net    true

