// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.Cose;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;

namespace maa.jwt.verifier.sevsnp
{
    public static class CoseSign1
    {

        public class TrustedSigningCertChain
        {
            public string PemRootCaPublicKey { get; }
            public string? LeafCertRequiredEku { get; }

            public TrustedSigningCertChain(string pemRootCaPublicKey, string? leafCertRequiredEku = null)
            {
                PemRootCaPublicKey = pemRootCaPublicKey;
                LeafCertRequiredEku = leafCertRequiredEku;
            }
        }

        public class TrustedSigningKey
        {
            public string PemSigningPublicKey { get; }

            public TrustedSigningKey(string pemSigningPublicKey)
            {
                PemSigningPublicKey = pemSigningPublicKey;
            }
        }

        public abstract class TrustedSigner { }

        public class TrustedCertChainSigner : TrustedSigner
        {
            public TrustedSigningCertChain CertChain { get; }

            public TrustedCertChainSigner(TrustedSigningCertChain certChain)
            {
                CertChain = certChain;
            }
        }

        public class TrustedKeySigner : TrustedSigner
        {
            public TrustedSigningKey Key { get; }

            public TrustedKeySigner(TrustedSigningKey key)
            {
                Key = key;
            }
        }

        public class TrustAnchor
        {
            public string FriendlyName { get; }
            public TrustedSigner Signer { get; }
            public string? Issuer { get; }
            public string? Feed { get; }

            public TrustAnchor(
                string friendlyName,
                TrustedSigner signer,
                string? issuer = null,
                string? feed = null)
            {
                FriendlyName = friendlyName;
                Signer = signer;
                Issuer = issuer;
                Feed = feed;
            }
        }

        // ===== Methods for parsing, validating, matching COSE/CBOR will go here =====

        public static List<X509Certificate2> ExtractX509Certificates(CoseSign1Message message)
        {
            var x5chainLabel = new CoseHeaderLabel(33);
            if (!message.ProtectedHeaders.TryGetValue(x5chainLabel, out var header))
            {
                throw new Exception();
            }

            var reader = new CborReader(header.EncodedValue, CborConformanceMode.Canonical);
            var certificates = new List<X509Certificate2>();

            switch (reader.PeekState())
            {
                case CborReaderState.ByteString:
                    certificates.Add(ReadByteStringAsCertificate(reader));
                    break;

                case CborReaderState.StartArray:
                    int? count = reader.ReadStartArray();
                    for (int i = 0; i < count; i++)
                    {
                        certificates.Add(ReadByteStringAsCertificate(reader));
                    }
                    reader.ReadEndArray();
                    break;

                default:
                    throw new InvalidOperationException("x5chain must be a ByteString or an array of ByteStrings.");
            }

            return certificates;
        }

        /// <summary>
        /// Extracts a certificate from the ByteString on this <see cref="CborReader"/>.
        /// From https://github.com/microsoft/CoseSignTool/blob/main/CoseSign1.Certificates/Extensions/CborReaderExtensions.cs#L113
        /// </summary>
        /// <param name="reader">The <see cref="CborReader"/> to extract a certificate from presuming it's on a ByteString.</param>
        /// <returns>A <see cref="X509Certificate2"/> extracted from the ByteString.</returns>
        /// <exception cref="CoseX509FormatException">Thrown if the <paramref name="reader"/> is not on a ByteString, or if the extract ByteString cannot be converted into a <see cref="X509Certificate2"/>.</exception>
        public static X509Certificate2 ReadByteStringAsCertificate(this CborReader reader)
        {
            if (reader.PeekState() != CborReaderState.ByteString)
            {
                throw new Exception($"Certificate array must only contain ByteString on reader: {reader.GetHashCode()}");
            }
            byte[] certBytes = reader.ReadByteString();

            return certBytes.Length > 0
                ? new X509Certificate2(certBytes)
                : throw new Exception($"Failed to read certificate bytes from ByteString on CborReader: {reader.GetHashCode()} and convert to a certificate.");
        }

        public static CoseSign1Message ExtractUvmEndorsement(string endorsementsJsonString)
        {
            using var doc = JsonDocument.Parse(endorsementsJsonString);
            string uvmKey = "Uvm";
            if (!doc.RootElement.TryGetProperty(uvmKey, out var uvmArray) || uvmArray.ValueKind != JsonValueKind.Array || uvmArray.GetArrayLength() != 1)
            {
                throw new Exception($"Invalid '{uvmKey}' array in endorsements.");
            }

            // Uvm endorsement is expected to be a base64url-encoded COSE Sign1 document
            string uvmEncoded = uvmArray[0].GetString() ?? throw new Exception($"{uvmKey}[0] is null or not a string.");
            var coseSign1Bytes = Base64UrlEncoder.DecodeBytes(uvmEncoded);
            if (CoseMessage.DecodeSign1(coseSign1Bytes) is not CoseSign1Message sign1Message)
            {
                throw new Exception("ERROR: Failed to decode COSE Sign1 message or COSE message is not of type CoseSign1Message.");
            }
            return sign1Message;
        }

        public static bool HasEku(X509Certificate2 cert, string requiredEkuOid)
        {
            foreach (var ext in cert.Extensions)
            {
                if (ext is X509EnhancedKeyUsageExtension ekuExt)
                {
                    return ekuExt.EnhancedKeyUsages
                                 .Cast<Oid>()
                                 .Any(oid => oid.Value == requiredEkuOid);
                }
            }
            return false;
        }
    }
}
