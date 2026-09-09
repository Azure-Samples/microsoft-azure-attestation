// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace maa.jwt.verifier.sevsnp
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            try
            {
                string filePath = PathUtilities.GetInputFilePathOrDefault(args, "sev-snp-jwt.txt");
                string expectedDnsName = args.Length >= 2
                    ? args[1]
                    : "https://sharedweu.weu.test.attest.azure.net";

                bool validateLifetime = !PathUtilities.IsUsingDefaultValues;
                if (PathUtilities.IsUsingDefaultValues)
                {
                    Console.WriteLine("WARNING: The tool is using the default JWT token file. Token expiration validation will be disabled.");
                }

                string jwtToken = await File.ReadAllTextAsync(filePath);

                if (await ValidateJwtAsync(jwtToken, expectedDnsName, validateLifetime))
                {
                    Console.WriteLine("SUCCESS: JWT token passed all validation checks.");
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"EXCEPTION: {ex}");
            }

            Console.WriteLine("FAILURE: JWT token failed one or more validation checks.");
            return;
        }

        public static async Task<bool> ValidateJwtAsync(string token, string expectedDnsName, bool validateLifetime)
        {
            bool result = true;
            try
            {
                var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token)
                               ?? throw new Exception("JWT token is null.");

                string certificatesString = await Utils.GetSigningCertificatesAsync(jwt);
                var selfSignedCerts = Utils.RetrieveSelfSignedSigningCertificates(certificatesString);

                result &= await ValidateTokenAsync(jwt, certificatesString, expectedDnsName, validateLifetime);

                var selfSignedCert = selfSignedCerts[0];
                var quoteValueJson = Utils.GetExtensionValueAsJson(selfSignedCert, Constants.MAA_EVIDENCE_CERTIFICATE_EXTENSION_OID);

                var vcekCertChainValue = Utils.GetExtensionValueDecodedString(quoteValueJson, "VcekCertChain");
                var endorsementsValue = Utils.GetExtensionValueDecodedString(quoteValueJson, "Endorsements");
                var snpReportBytes = Utils.GetExtensionValueDecodedBytes(quoteValueJson, "SnpReport");
                var snpReportSerialized = SnpAttestationReport.Parse(snpReportBytes);

                result &= ValidateTeeKind(selfSignedCert);
                result &= VerifySnpReportSignature(snpReportSerialized, vcekCertChainValue);
                result &= VerifyLaunchMeasurement(endorsementsValue, snpReportSerialized);
                result &= VerifyUvmEndorsement(endorsementsValue);
                result &= VerifyHostDataClaim(snpReportSerialized);
                result &= VerifyReportData(selfSignedCert, snpReportSerialized);
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR: JWT Validation Error, exception: " + ex);
                return false;
            }
            return result;
        }

        /// <summary>
        /// Validates the signature, issuer, and (optionally) the expiration of a JWT
        /// using the issuer's signing keys retrieved from its JWK endpoint.
        /// </summary>
        /// <param name="jwt">Parsed JWT token.</param>
        /// <param name="certificatesString">JWK set retrieved from the issuer's `jku` URL.</param>
        /// <param name="expectedIssuer">Expected `iss` claim value (e.g., MAA instance URL).</param>
        /// <param name="validateLifetime">Whether to validate token expiration.</param>
        /// <returns>True if the token is valid; otherwise, false.</returns>
        private static async Task<bool> ValidateTokenAsync(JwtSecurityToken jwt, string certificatesString, string expectedIssuer, bool validateLifetime)
        {
            try
            {
                var issuerPublicKeySet = new JsonWebKeySet(certificatesString);
                var parameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeys = issuerPublicKeySet.GetSigningKeys(),

                    // This sample does not validate audience because it is not acting as a specific relying party.
                    ValidateAudience = false,

                    ValidateIssuer = true,
                    ValidIssuer = expectedIssuer,

                    ValidateLifetime = validateLifetime
                };

                var handler = new JwtSecurityTokenHandler();
                var validationResult = await handler.ValidateTokenAsync(jwt.RawData, parameters);

                if (validationResult.IsValid)
                {
                    Console.WriteLine($"SUCCESS: Token signature and issuer{(validateLifetime ? ", and expiration" : "")} are valid.");
                    return true;
                }

                if (validationResult.Exception != null)
                {
                    Console.WriteLine($"Exception: {validationResult.Exception.GetType().Name} - {validationResult.Exception.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Token validation error: {ex}");
            }
            Console.WriteLine("ERROR: JWT validation failed.");
            return false;
        }

        /// <summary>
        /// Verifies whether the provided certificate contains valid attestation evidence for a SEV-SNP platform.
        /// This checks if the certificate includes the required TEE Kind extension and validates its value.
        /// </summary>
        /// <param name="certificate">The X.509 certificate to inspect for platform attestation evidence.</param>
        /// <returns>
        /// Returns <c>true</c> if the certificate contains valid SEV-SNP attestation evidence,
        /// including the required TEE Kind extension and expected platform identifier.
        /// Returns <c>false</c> if the extension is missing, the value is incorrect, or validation fails.
        /// </returns>
        private static bool ValidateTeeKind(X509Certificate2 certificate)
        {
            try
            {
                var teeKindValue = Utils.GetExtensionValueAsUtf8String(certificate, Constants.MAA_EVIDENCE_TEEKIND_CERTIFICATE_OID);

                if (teeKindValue == null || teeKindValue != Constants.SevSnpTeeValue)
                {
                    Console.WriteLine($"ERROR: TEE Kind mismatch for certificate {certificate.Subject}. Expected '{Constants.SevSnpTeeValue}', got '{teeKindValue}'.");
                    return false;
                }

                Console.WriteLine("SUCCESS: Platform verified as ACI SEV-SNP.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: Failed to read TEE Kind extension from certificate {certificate.Subject}: {ex}");
            }
            return false;
        }

        /// <summary>
        /// Verifies the authenticity of an AMD SEV-SNP attestation report by validating the VCEK certificate chain
        /// and checking the report’s signature using the leaf VCEK ECDSA public key.
        /// </summary>
        /// <param name="snpReport">The parsed SEV-SNP attestation report object.</param>
        /// <param name="vcekChainPemString">
        /// A string containing one or more PEM-encoded X.509 certificates representing the VCEK certificate chain.
        /// The first certificate is expected to be the VCEK (leaf), and the last should be the AMD root.
        /// </param>
        /// <returns>
        /// <c>true</c> if the certificate chain is valid and the SEV-SNP report is properly signed by the VCEK key;
        /// otherwise, <c>false</c>.
        /// </returns>
        /// <remarks>
        /// This method performs the following steps:
        /// 1. Extracts certificates from the PEM string.
        /// 2. Ensures the root matches a known AMD trusted root key.
        /// 3. Validates the full chain from leaf to root.
        /// 4. Verifies the ECDSA P-384 signature over the SEV-SNP report.
        /// </remarks>
        private static bool VerifySnpReportSignature(SnpAttestationReport snpReport, string vcekChainPemString)
        {
            try
            {
                // Parse PEM chain.
                var certMatches = Regex.Matches(vcekChainPemString, "-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", RegexOptions.Singleline);
                if (certMatches.Count == 0)
                {
                    Console.WriteLine("ERROR: No certificates found in VCEK chain.");
                    return false;
                }

                var certificates = certMatches
                    .Select(match => new X509Certificate2(Encoding.ASCII.GetBytes(match.Value)))
                    .ToList();

                var leafCert = certificates.FirstOrDefault();
                var rootCert = certificates.LastOrDefault();
                if (leafCert == null || rootCert == null)
                {
                    Console.WriteLine("ERROR: Missing leaf or root certificate.");
                    return false;
                }

                // Step 1: Match against AMD root keys.
                bool matchedRoot = TrustedValues.AmdRootKeys.Any(pem =>
                {
                    using var trustedRsa = Utils.PemStringToRsa(pem);
                    using var rootRsa = rootCert.GetRSAPublicKey();
                    return Utils.AreEqual(trustedRsa, rootRsa);
                });

                if (!matchedRoot)
                {
                    Console.WriteLine("ERROR: VCEK root certificate does not match any known AMD trusted root.");
                    return false;
                }

                // Step 2: Validate chain.
                if (!Utils.BuildAndValidateCertChain(certificates, TrustedValues.AmdRootKeys.Select(Utils.PemStringToRsa).ToArray(), Utils.CertValidationTarget.Root))
                {
                    Console.WriteLine("ERROR: Failed to build or validate VCEK certificate chain.");
                    return false;
                }

                // Step 3: Verify SEV-SNP signature.
                var ecdsa = leafCert.GetECDsaPublicKey();
                if (ecdsa == null)
                {
                    Console.WriteLine("ERROR: Leaf certificate does not contain a valid ECDSA public key.");
                    return false;
                }

                byte[] reportDataToVerify = snpReport.GetSignedPortion();
                byte[] derEncodedSignature = snpReport.GetDerEncodedSignature();
                if (ecdsa.VerifyData(reportDataToVerify, derEncodedSignature, HashAlgorithmName.SHA384, DSASignatureFormat.Rfc3279DerSequence))
                {
                    Console.WriteLine("SUCCESS: VCEK certificate and SNP report signature verified.");
                    return true;
                }

                Console.WriteLine("ERROR: Signature on SEV-SNP report is invalid.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: Exception during SEV-SNP signature verification: {ex}");
            }
            return false;
        }

        /// <summary>
        /// Verifies that the launch measurement in the SEV-SNP attestation report matches the value endorsed in the UVM evidence.
        /// </summary>
        /// <param name="endorsementsValue">A JSON string containing UVM endorsement data, including the encoded COSE Sign1 payload.</param>
        /// <param name="snpReport">The parsed SEV-SNP attestation report.</param>
        /// <returns>
        /// <c>true</c> if the launch measurement in the attestation report matches the endorsed value from the UVM evidence; otherwise, <c>false</c>.
        /// </returns>
        private static bool VerifyLaunchMeasurement(string endorsementsValue, SnpAttestationReport snpReport)
        {
            try
            {
                CoseSign1Message sign1Message = CoseSign1.ExtractUvmEndorsement(endorsementsValue);
                var payload = sign1Message.Content ?? throw new Exception("COSE message payload is null.");
                using var payloadJson = JsonDocument.Parse(payload.ToArray());

                Console.WriteLine("\tUVM Payload (JSON):");
                Utils.PrintJsonWithTabs(JsonSerializer.Serialize(payloadJson, new JsonSerializerOptions { WriteIndented = true }));

                if (payloadJson.RootElement.TryGetProperty(Constants.SevSnpClaimNameLaunchMeasurement, out JsonElement measurement))
                {
                    string endorsedLaunchMeasurement = measurement.ToString();
                    var presentedLaunchMeasurement = snpReport.GetMeasurementHex();

                    if (string.Equals(endorsedLaunchMeasurement, presentedLaunchMeasurement, StringComparison.Ordinal))
                    {
                        Console.WriteLine("SUCCESS: Uvm endorsement launch measurement value matches SEVSNP report value Launch measurement.");
                        return true;
                    }
                    else
                    {
                        Console.WriteLine($"\tSEVSNP report launch measurement value :\t\t{presentedLaunchMeasurement}");
                        Console.WriteLine($"\tUvm endorsement '{Constants.SevSnpClaimNameLaunchMeasurement}' :\t{endorsedLaunchMeasurement}");
                        Console.WriteLine($"ERROR: Uvm endorsement '{Constants.SevSnpClaimNameLaunchMeasurement}' value does not match SEVSNP report value Launch measurement.");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("ERROR: Failed to verify launch measurement: " + ex);
            }
            return false;
        }

        /// <summary>
        /// Verifies a UVM endorsement embedded in an X.509 certificate extension.
        /// This includes validating the COSE_Sign1 signature, checking the certificate chain against known trust anchors,
        /// and enforcing Enhanced Key Usage (EKU) if required by the trust policy.
        /// </summary>
        /// <param name="endorsementsValue">A JSON string containing the UVM endorsement.</param>
        /// <returns>True if the endorsement is valid and trusted; otherwise, false.</returns>
        private static bool VerifyUvmEndorsement(string endorsementsValue)
        {
            try
            {
                CoseSign1Message sign1Message = CoseSign1.ExtractUvmEndorsement(endorsementsValue);
                var certificates = CoseSign1.ExtractX509Certificates(sign1Message);
                var signingCert = certificates.FirstOrDefault();
                var rootCert = certificates.LastOrDefault();

                if (signingCert == null || rootCert == null)
                    throw new Exception("Missing leaf or root certificate.");

                var publicKey = signingCert.GetRSAPublicKey()
                    ?? throw new Exception("No valid RSA public key found in signing certificate.");

                // Step 1: Verify COSE signature.
                if (!sign1Message.VerifyEmbedded(publicKey))
                {
                    Console.WriteLine("ERROR: COSE message signature is invalid.");
                    return false;
                }

                // Step 2: Find a matching trust anchor (based on root public key).
                var trustAnchor = TrustedValues.UvmEndorsementTrustAnchors.FirstOrDefault(anchor =>
                {
                    switch (anchor.Signer)
                    {
                        case CoseSign1.TrustedCertChainSigner chainSigner:
                            {
                                using var anchorRsa = Utils.PemStringToRsa(chainSigner.CertChain.PemRootCaPublicKey);
                                using var rootRsa = rootCert.GetRSAPublicKey();
                                return Utils.AreEqual(anchorRsa, rootRsa);
                            }

                        case CoseSign1.TrustedKeySigner keySigner:
                            {
                                using var anchorRsa = Utils.PemStringToRsa(keySigner.Key.PemSigningPublicKey);
                                using var leafRsa = signingCert.GetRSAPublicKey();
                                return Utils.AreEqual(anchorRsa, leafRsa);
                            }

                        default:
                            return false;
                    }
                });
                if (trustAnchor == null)
                {
                    Console.WriteLine("ERROR: UVM Endorsement signature failed: no trusted root matched.");
                    return false;
                }

                // Step 3: Validate full certificate chain (COSE Sign1 Object -> ProtectedHeaders -> x5chain).
                var trustedRoots = new[] { Utils.PemStringToRsa(((CoseSign1.TrustedCertChainSigner)trustAnchor.Signer).CertChain.PemRootCaPublicKey) };
                if (!Utils.BuildAndValidateCertChain(certificates, trustedRoots, Utils.CertValidationTarget.Root))
                {
                    Console.WriteLine("ERROR: Certificate chain validation failed.");
                    return false;
                }

                // Step 4: If EKU is required by trust anchor, check that leaf cert has it.
                if (trustAnchor.Signer is CoseSign1.TrustedCertChainSigner certChain &&
                    !string.IsNullOrEmpty(certChain.CertChain.LeafCertRequiredEku))
                {
                    if (!CoseSign1.HasEku(signingCert, certChain.CertChain.LeafCertRequiredEku!))
                    {
                        Console.WriteLine($"ERROR: Leaf certificate does not contain expected EKU: {certChain.CertChain.LeafCertRequiredEku}");
                        return false;
                    }
                }

                Console.WriteLine("SUCCESS: UVM Endorsement signature successfully verified against trusted C-ACI root.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: Failed to verify UVM endorsement signature: {ex}");
                return false;
            }
        }

        /// <summary>
        /// Verifies that the hostdata value from a SEV-SNP attestation report matches the expected SHA-256 hash of the current CCE policy.
        /// </summary>
        /// <param name="snpReport">The parsed SEV-SNP attestation report.</param>
        /// <returns>
        /// <c>true</c> if the hostdata value in the SNP report matches the expected CCE policy hash; otherwise, <c>false</c>.
        /// </returns>
        private static bool VerifyHostDataClaim(SnpAttestationReport snpReport)
        {
            try
            {
                // Latest CCE policy as of 1.29.2025.
                // Hash was confirmed by computing the SHA256 of the CCE policy.
                // CCE policy was extracted from the ARM template & base64 decoded using Linux style line ending.
                const string expectedHostDataValue = "0178240eff4ef968efdcd735b8bcee63578c4eb9e4264178f747df149bf57bff";
                var hostDataValueSnpReport = snpReport.GetHostDataHex();
                if (!string.IsNullOrEmpty(hostDataValueSnpReport) && expectedHostDataValue.Equals(hostDataValueSnpReport))
                {
                    Console.WriteLine($"SUCCESS: Hostdata value '{hostDataValueSnpReport}' from SNP report matches expected policy hash '{expectedHostDataValue}'");
                    return true;
                }
                Console.WriteLine($"ERROR: Hostdata is missing or invalid. Found: {hostDataValueSnpReport ?? "<null>"}. Expected: {expectedHostDataValue}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: Exception occurred while verifying hostdata: {ex}");
            }

            return false;
        }

        /// <summary>
        /// Verifies that SEVSNP.reportdata matches the SHA-256 hash of the signer's public key.
        /// This confirms that the attestation is bound to the holder of the corresponding private key.
        /// </summary>
        /// <param name="cert">The certificate containing the RSA public key.</param>
        /// <param name="snpReport">The SEV-SNP attestation report.</param>
        /// <returns>True if the reportdata matches the expected public key hash; otherwise, false.</returns>
        private static bool VerifyReportData(X509Certificate2 cert, SnpAttestationReport snpReport)
        {
            try
            {
                string expectedHashHex = HashPemWithNullTerminator(cert);
                string reportDataHex = snpReport.GetReportDataHex();
                byte[] reportDataBytes = Convert.FromHexString(reportDataHex);

                if (reportDataBytes.Length != 64)
                {
                    Console.WriteLine("ERROR: Invalid ReportData length. Expected 64 bytes.");
                    return false;
                }

                if (!reportDataBytes.Skip(32).All(b => b == 0x00))
                {
                    Console.WriteLine("ERROR: Upper 32 bytes of ReportData (bytes 32–63) must be zero.");
                    return false;
                }

                string actualHashHex = Convert.ToHexString(reportDataBytes.Take(32).ToArray()).ToLowerInvariant();
                if (!actualHashHex.Equals(expectedHashHex, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("ERROR: Lower 32 bytes of ReportData do not match the expected public key hash.");
                    Console.WriteLine($"Expected: {expectedHashHex}");
                    Console.WriteLine($"Actual:   {actualHashHex}");
                    return false;
                }

                Console.WriteLine("SUCCESS: SEVSNP.reportdata matches hash of expected public key.");
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"ERROR: Exception while verifying ReportData: {ex}");
                return false;
            }
        }

        /// <summary>
        /// Computes the SHA-256 hash of a PEM-encoded RSA public key with a null terminator, for use in
        /// validating the `report_data` field of an AMD SEV-SNP attestation report.
        ///
        /// <para>
        /// The `report_data` field in the SEV-SNP attestation report includes a 64-byte value, where the
        /// lower 32 bytes (bytes 0–31) may be set to the SHA-256 hash of the public key used to verify
        /// the payload's signature. This function generates a hash that can be compared against that
        /// `report_data` value to ensure the attestation is bound to the specific signing key.
        /// </para>
        ///
        /// <para>
        /// The input to the hash is constructed as follows:
        /// - The RSA public key is exported in SubjectPublicKeyInfo (SPKI) format.
        /// - It is Base64-encoded and wrapped in standard PEM boundaries:
        ///   <c>-----BEGIN PUBLIC KEY-----</c> and <c>-----END PUBLIC KEY-----</c>.
        /// - The Base64 content is split into 64-character lines.
        /// - All line endings use Unix-style LF (`\n`) — no CRLF (`\r\n`).
        /// - The final PEM string includes a newline (`\n`) after the END line.
        /// - A single null terminator byte (`0x00`) is appended to the PEM string.
        /// - The resulting UTF-8 byte array is passed to SHA-256.
        /// </para>
        ///
        /// <para>
        /// Example hashed content (line endings shown as \n):
        ///
        /// <code>
        /// -----BEGIN PUBLIC KEY-----\n
        /// MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs+AfUU1TfCR/oN72KXbl\n
        /// 4WHbnGsHvXabFlFrLcY/hbjwtexu5EzgCxeXvWYQIp6ZE4T38OHeJP28UEy1be98\n
        /// N8la6nTSnBQc7JNQDQNHMZXHfP43kCVX6ZvLjoeU4Tx+dSymDYKtp2wtsdDeTclp\n
        /// u3x9mbh6OkDxlJxcO6tts6EBd0foLRwX67wL25XcaoemnvATla+DO+5eOaClT5Xj\n
        /// 4f+Wi2ZGHe8Dsb2BDZa+ww/lAwQXf085lXlmeLk1YEMkTw5oRJulXQ0aanzhl0FG\n
        /// eIIXAlE0r3AxLcy++RHNQa9Ci7zKmnKV9+6BbX/r/AMIcxzzxOUeszAz1JpKJ8JZ\n
        /// dwIDAQAB\n
        /// -----END PUBLIC KEY-----\n
        /// \0
        /// </code>
        /// </para>
        ///
        /// <returns>
        /// A lowercase hexadecimal string representing the SHA-256 hash of the null-terminated PEM-formatted RSA key.
        /// This hash should match the lower 32 bytes of the SEV-SNP attestation `report_data` if the key was used
        /// as the report signer.
        /// </returns>
        private static string HashPemWithNullTerminator(X509Certificate2 cert)
        {
            RSA? rsa = cert.GetRSAPublicKey();
            if (rsa == null)
            {
                throw new Exception("HashPemWithNullTerminator - rsa is null.");
            }
            string pem = Utils.RsaToPem(rsa);

            byte[] pemBytes = Encoding.UTF8.GetBytes(pem);
            byte[] bytesWithNull = new byte[pemBytes.Length + 1];
            Buffer.BlockCopy(pemBytes, 0, bytesWithNull, 0, pemBytes.Length);
            bytesWithNull[^1] = 0;

            string pemHashHex = Convert.ToHexString(SHA256.HashData(bytesWithNull)).ToLowerInvariant();
            return pemHashHex;
        }
    }
}
