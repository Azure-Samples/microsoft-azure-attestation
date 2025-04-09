// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Security.Cryptography;
using System.Formats.Asn1;
using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;

namespace maa.jwt.verifier.sevsnp
{
    public static class Utils
    {
        /// <summary>
        /// Retrieves the JSON Web Key Set (JWKS) from the 'jku' (JWK Set URL) specified in the JWT header.
        /// </summary>
        /// <param name="jwt">The parsed JwtSecurityToken.</param>
        /// <returns>The raw JWKS JSON string.</returns>
        /// <exception cref="Exception">Throws if 'jku' header is missing, invalid, or if the endpoint cannot be retrieved.</exception>
        public static async Task<string> GetSigningCertificatesAsync(JwtSecurityToken jwt)
        {
            if (!jwt.Header.TryGetValue("jku", out object? jkuValue) || jkuValue is not string jkuUrl)
            {
                throw new Exception("Missing or invalid 'jku' header in JWT.");
            }

            Console.WriteLine($"\tJWT Signing Certificates Endpoint (jku): {jkuUrl}");

            using var httpClient = new HttpClient();
            string jwkSetJson = await httpClient.GetStringAsync(jkuUrl)
                ?? throw new Exception($"Failed to retrieve JWK set from the 'jku' endpoint: {jkuUrl}");

            return jwkSetJson;
        }

        public static List<X509Certificate2> RetrieveSelfSignedSigningCertificates(string certificatesString)
        {
            using var doc = JsonDocument.Parse(certificatesString);
            var root = doc.RootElement;

            List<X509Certificate2> certificates = [];

            if (root.TryGetProperty("keys", out JsonElement keys) && keys.ValueKind == JsonValueKind.Array)
            {
                foreach (var certEntry in keys.EnumerateArray())
                {
                    if (certEntry.TryGetProperty("x5c", out JsonElement x5cArray) &&
                        x5cArray.ValueKind == JsonValueKind.Array &&
                        x5cArray.GetArrayLength() > 0)
                    {
                        string certBase64 = x5cArray[0].GetString() ?? throw new Exception("Failed to get certificate string");

                        if (!string.IsNullOrEmpty(certBase64))
                        {
                            var certBytes = Convert.FromBase64String(certBase64);
                            var x509Certificate = new X509Certificate2(certBytes);

                            // Add only self-signed certificates
                            if (x509Certificate.Subject == x509Certificate.Issuer)
                            {
                                certificates.Add(x509Certificate);

                                // Optional logging or debug info:
                                if (certEntry.TryGetProperty("kid", out var kidProp))
                                {
                                    Console.WriteLine($"\tKey ID for self signed signing certificate: {kidProp.GetString()}");
                                }
                            }
                        }
                    }
                }
            }

            if (certificates.Count < 1)
            {
                throw new Exception($"Failed to find any senf signed certificates in {certificatesString}");
            }

            return certificates;
        }

        public static string GetPemFromX509Certificate2(X509Certificate2 cert)
        {
            string pem = RsaToPem(cert.GetRSAPublicKey());
            return pem;
        }

        public static string RsaToPem(RSA? rsa)
        {
            if (rsa == null)
            {
                throw new Exception("RsaToPem - rsa is null.");
            }

            var publicKey = rsa.ExportSubjectPublicKeyInfo();
            var base64 = Convert.ToBase64String(publicKey);

            const int LineLength = 64;
            var sb = new StringBuilder();

            sb.Append("-----BEGIN PUBLIC KEY-----\n");

            for (int i = 0; i < base64.Length; i += LineLength)
            {
                int chunkSize = Math.Min(LineLength, base64.Length - i);
                sb.Append(base64.Substring(i, chunkSize)).Append('\n');
            }

            sb.Append("-----END PUBLIC KEY-----\n");
            var pem = sb.ToString();
            return pem;
        }

        public static byte[] PemStringToRsaBytes(string pem)
        {
            using var rsa = PemStringToRsa(pem);
            return rsa.ExportSubjectPublicKeyInfo();
        }

        public static RSA PemStringToRsa(string pem)
        {
            var rsa = RSA.Create();
            rsa.ImportFromPem(pem.ToCharArray());
            return rsa;
        }

        public static bool AreEqual(RSA? a, RSA? b)
        {
            if (a == null || b == null)
            {
                return false;
            }

            var aParams = a.ExportParameters(false);
            var bParams = b.ExportParameters(false);

            return aParams.Modulus != null &&
                   bParams.Modulus != null &&
                   aParams.Exponent != null &&
                   bParams.Exponent != null &&
                   aParams.Modulus.SequenceEqual(bParams.Modulus) &&
                   aParams.Exponent.SequenceEqual(bParams.Exponent);
        }

        public static string GetExtensionValueAsUtf8String(X509Certificate2 certificate, string oid)
        {
            var extension = certificate.Extensions.Cast<X509Extension>().FirstOrDefault(ext => ext.Oid?.Value == oid)
                            ?? throw new Exception($"Failed to retrieve X509 certificate extension with OID {oid}.");
            var asnValue = new AsnReader(extension.RawData, AsnEncodingRules.DER);
            return asnValue.ReadCharacterString(UniversalTagNumber.UTF8String);
        }

        public static JsonElement GetExtensionValueAsJson(X509Certificate2 certificate, string oid)
        {
            var extensionValue = Utils.GetExtensionValueAsUtf8String(certificate, oid);
            using var doc = JsonDocument.Parse(extensionValue);
            return doc.RootElement.Clone();
        }

        public static string GetRawValueAsString(JsonElement json, string key)
        {
            if (!json.TryGetProperty(key, out JsonElement value) || value.ValueKind != JsonValueKind.String)
            {
                throw new Exception($"Failed to get value for the key '{key}'. It is missing or not a string in the JSON object.");
            }

            var stringValue = value.GetString();
            if (string.IsNullOrEmpty(stringValue))
            {
                throw new Exception($"Key '{key}' is present but the value is null or empty.");
            }

            return stringValue;
        }

        public static byte[] GetExtensionValueDecodedBytes(JsonElement json, string key)
        {
            string encoded = GetRawValueAsString(json, key);
            return Base64UrlEncoder.DecodeBytes(encoded);
        }

        public static string GetExtensionValueDecodedString(JsonElement json, string key)
        {
            string encoded = GetRawValueAsString(json, key);
            return Base64UrlEncoder.Decode(encoded);
        }

        public enum CertValidationTarget
        {
            Leaf,
            Root
        }

        public static bool BuildAndValidateCertChain(
            List<X509Certificate2>? certs,
            RSA[] trustedKeys,
            CertValidationTarget target)
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.AddRange(certs?.ToArray() ?? []);
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;

            var leafCert = certs?.FirstOrDefault();
            if (leafCert == null || !chain.Build(leafCert))
            {
                Console.WriteLine("ERROR: Failed to build certificate chain.");
                return false;
            }

            X509Certificate2 certToValidate = target switch
            {
                CertValidationTarget.Leaf => chain.ChainElements[0].Certificate,
                CertValidationTarget.Root => chain.ChainElements[^1].Certificate,
                _ => throw new InvalidOperationException("Unknown validation target")
            };

            var certPublicKey = certToValidate.GetRSAPublicKey();
            if (certPublicKey == null)
            {
                Console.WriteLine("ERROR: Selected certificate does not contain an RSA public key.");
                return false;
            }

            foreach (var trustedKey in trustedKeys)
            {
                if (Utils.AreEqual(certPublicKey, trustedKey))
                {
                    //Console.WriteLine("Certification chain is valid and roots to a trusted key.");
                    return true;
                }
            }

            return false;
        }

        public static void PrintJsonWithTabs(string json)
        {
            var formatted = JsonSerializer.Serialize(
                JsonDocument.Parse(json).RootElement,
                new JsonSerializerOptions { WriteIndented = true });

            foreach (var line in formatted.Split('\n'))
            {
                Console.WriteLine($"\t{line}");
            }
        }
    }
}
