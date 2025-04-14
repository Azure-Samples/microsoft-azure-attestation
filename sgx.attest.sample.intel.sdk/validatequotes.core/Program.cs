﻿using System;
using System.IO;
using System.Threading.Tasks;
using validatequotes.Helpers;
using Azure.Security.Attestation;
using Azure.Identity;
using Azure.Core;
using System.Text;

namespace validatequotes
{
    public class Program
    {
        private readonly string fileName;
        private readonly string attestDnsName;
        private readonly bool includeDetails;

        public static void Main(string[] args)
        {
            Task.WaitAll(new Program(args).RunAsync());
        }

        public Program(string[] args)
        {
            this.fileName = args.Length > 0 ? args[0] : (Directory.GetCurrentDirectory().Contains("bin", StringComparison.InvariantCultureIgnoreCase) ? "../../../../genquotes/quotes/enclave.info.release.json" : "../genquotes/quotes/enclave.info.release.json");
            this.attestDnsName = args.Length > 1 ? args[1] : "sharedcus.cus.attest.azure.net";
            this.includeDetails = true;
            if (args.Length > 2)
            {
                _ = bool.TryParse(args[2], out this.includeDetails);
            }

            if (args.Length < 3)
            {
                Logger.WriteBanner($"USAGE");
                Logger.WriteLine($"Usage: dotnet validatequotes.core.dll <JSON file name> <attest DNS name> <include details bool>");
                Logger.WriteLine($"Usage: dotnet run                     <JSON file name> <attest DNS name> <include details bool>");
                Logger.WriteLine($" - validates remote attestation quotes generated by genquote application");
                Logger.WriteLine($" - validates via calling the OE attestation endpoint on the MAA service");
            }

            Logger.WriteBanner($"PARAMETERS FOR THIS RUN");
            Logger.WriteLine($"Validating filename                : {this.fileName}");
            Logger.WriteLine($"Using attestation provider         : {this.attestDnsName}");
            Logger.WriteLine($"Including details                  : {this.includeDetails}");
        }

        public async Task RunAsync()
        {
            // Fetch file
            var enclaveInfo = await EnclaveInfo.CreateFromFileAsync(this.fileName);

            // Send to service for attestation

            string endpoint = "https://" + this.attestDnsName;

            // Send to service for attestation
            var options = new AttestationClientOptions(tokenOptions: new AttestationTokenValidationOptions
                {
                    ExpectedIssuer = endpoint,
                    ValidateIssuer = true,
                }
            );

            options.TokenOptions.TokenValidated +=  (args) =>
            {
                // Analyze results
                Logger.WriteBanner("IN VALIDATION CALLBACK, VALIDATING MAA JWT TOKEN - BASICS");
                JwtValidationHelper.ValidateMaaJwt(attestDnsName, args.Token, args.Signer, this.includeDetails);
                args.IsValid = true;
                return Task.CompletedTask;
            };

            var maaService = new AttestationClient(new Uri(endpoint), new DefaultAzureCredential(new DefaultAzureCredentialOptions { ExcludeSharedTokenCacheCredential = true }), options);

            BinaryData sgxEnclaveReport = BinaryData.FromBytes(HexHelper.ConvertHexToByteArray(enclaveInfo.QuoteHex));

            BinaryData runtimeData = BinaryData.FromBytes(HexHelper.ConvertHexToByteArray(enclaveInfo.EnclaveHeldDataHex));

            var serviceResponse = await maaService.AttestSgxEnclaveAsync(
                new AttestationRequest
                {
                    Evidence = sgxEnclaveReport,
                    RuntimeData = new AttestationData( runtimeData, false),
                });
            var serviceJwtToken = serviceResponse.Token.ToString();

            Logger.WriteBanner("SAVING JWT TOKEN as `maa-jwt-token.txt`");
            await File.WriteAllTextAsync("maa-jwt-token.txt", serviceResponse.Token.Serialize());

            Logger.WriteBanner("VALIDATING MAA JWT TOKEN - MATCHES CLIENT ENCLAVE INFO");
            enclaveInfo.CompareToMaaServiceJwtToken(serviceResponse.Value, this.includeDetails);
        }
    }
}
