//#define LOG_BOUNCY_CASTLE

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace validatequotes.Helpers
{
    class JwtValidationHelper
    {
        public static TokenValidationResult ValidateMaaJwt(string attestDnsName, string serviceJwt, bool includeDetails)
        {
            var tenantName = attestDnsName.Split('.')[0];
            var attestUri = $"https://{attestDnsName}";

            var jwksTrustedSigningKeys = RetrieveTrustedSigningKeys(serviceJwt, attestDnsName, tenantName, includeDetails);
            var jwksTrustedSigningKeysJWKS = new JsonWebKeySet(jwksTrustedSigningKeys);

            var validatedToken = ValidateSignedToken(serviceJwt, jwksTrustedSigningKeysJWKS, includeDetails);
            ValidateJwtIssuerIsTenant(validatedToken, attestUri, includeDetails);
            ValidateSigningCertIssuerMatchesJwtIssuer(validatedToken, includeDetails);

            X509SecurityKey signingKey = (X509SecurityKey)validatedToken.SecurityToken.SigningKey;
            X509Certificate2 signingCertificate = signingKey.Certificate;
            byte[] certificateBytes = signingCertificate.RawData;
            string x5c = Convert.ToBase64String(certificateBytes);

#if LOG_BOUNCY_CASTLE
            if (includeDetails)
            {
                var bouncyCertParser = new X509CertificateParser();
                var bouncyCert = bouncyCertParser.ReadCertificate(certificateBytes);
                var bouncyAsn1Sequence = (DerSequence)bouncyCert.CertificateStructure.ToAsn1Object();

                for (int i= 0; i<bouncyAsn1Sequence.Count; i++)
                {
                    var asn1 = bouncyAsn1Sequence[i];
                    Logger.WriteLine(53, 128, $"{asn1.GetType().ToString(),50} : ", BitConverter.ToString(asn1.GetEncoded()).Replace("-", ""));
                }
            }
#endif

            Logger.WriteBanner("VALIDATING MAA JWT TOKEN - MAA EMBEDDED QUOTE IN SIGNING CERTIFICATE FOR JWT");
            MaaQuoteValidator.ValidateMaaQuote(x5c, includeDetails);

            return validatedToken;
        }

#region Internal implementation details

        private static void ValidateSigningCertIssuerMatchesJwtIssuer(TokenValidationResult validatedToken, bool includeDetails)
        {
            var jwtTokenIssuerClaim = validatedToken.ClaimsIdentity.Claims.First(c => c.Type == "iss");

            // Ensure that the JWT signing certificate is issued by the same issuer as the JWT itself
            var validatedKey = validatedToken.SecurityToken.SigningKey;
            if (!(validatedKey is X509SecurityKey))
            {
                throw new ArgumentException("JWT is not valid (signing key is not an X509 security key)");
            }
            var signingCertificate = (validatedKey as X509SecurityKey).Certificate;
            if (!string.Equals(signingCertificate.Issuer, "CN=" + jwtTokenIssuerClaim.Value, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("JWT is not valid (signing certificate issuer does not match JWT issuer)");
            }
            Logger.WriteLine($"JWT signing cert issuer validation : True");
            if (includeDetails)
            {
                Logger.WriteLine($"    Signing certificate issuer     : {signingCertificate.Issuer}");
            }
        }

        private static void ValidateJwtIssuerIsTenant(TokenValidationResult validatedToken, string tenantAttestUri, bool includeDetails)
        {
            // Verify that the JWT issuer is indeed the tenantAttestUri (tenant specific URI)
            var jwtTokenIssuerClaim = validatedToken.ClaimsIdentity.Claims.First(c => c.Type == "iss");
            if (!string.Equals(tenantAttestUri, jwtTokenIssuerClaim.Value, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("JWT is not valid (iss claim does not match attest URI)");
            }
            Logger.WriteLine($"JWT issuer claim validation        : True");
            if (includeDetails)
            {
                Logger.WriteLine($"    JWT Issuer claim value         : {jwtTokenIssuerClaim.Value.ToString()}");
            }
        }

        private static TokenValidationResult ValidateSignedToken(string serviceJwt, JsonWebKeySet jwksTrustedSigningKeys, bool includeDetails)
        {
            // Now validate the JWT using the signing keys we just discovered
            TokenValidationParameters tokenValidationParams = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                IssuerSigningKeys = jwksTrustedSigningKeys.GetSigningKeys()
            };
            var jwtHandler = new JsonWebTokenHandler();
            var validatedToken = jwtHandler.ValidateToken(serviceJwt, tokenValidationParams);
            if (!validatedToken.IsValid)
            {
                throw new ArgumentException("JWT is not valid (signature verification failed)");
            }

            Logger.WriteLine($"JWT signature validation           : True");
            if (includeDetails)
            {
                X509SecurityKey signingKey = (X509SecurityKey)validatedToken.SecurityToken.SigningKey;
                var modulus = ((RSACng)signingKey.PublicKey).ExportParameters(false).Modulus;
                var exponent = ((RSACng)signingKey.PublicKey).ExportParameters(false).Exponent;
                Logger.WriteLine(37, 64, "    RSA signing key modulus        : ", BitConverter.ToString(modulus).Replace("-",""));
                Logger.WriteLine(37, 64, "    RSA signing key exponent       : ", BitConverter.ToString(exponent).Replace("-", ""));
            }
            return validatedToken;
        }

        private static string RetrieveTrustedSigningKeys(string serviceJwt, string attestDnsName, string tenantName, bool includeDetails)
        {
            var expectedCertificateDiscoveryEndpoint = $"https://{attestDnsName}/certs";

            // Parse attestation service trusted signing key discovery endpoint from JWT header jku field
            var jwt = new JsonWebToken(serviceJwt);
            var jsonHeaderBytes = Base64Url.DecodeBytes(jwt.EncodedHeader);
            var jsonHeaderString = Encoding.UTF8.GetString(jsonHeaderBytes);
            var jsonHeader = JObject.Parse(jsonHeaderString);
            var jkuUri = jsonHeader.SelectToken("jku");
            Uri certificateDiscoveryEndpoint = new Uri(jkuUri.ToString());

            // Validate that "jku" points to the expected certificate discovery endpoint
            if (!expectedCertificateDiscoveryEndpoint.Equals(certificateDiscoveryEndpoint.ToString(), StringComparison.InvariantCultureIgnoreCase))
            {
                throw new ArgumentException($"JWT JKU header not valid.  Value is '{certificateDiscoveryEndpoint.ToString()}'.  Expected value is '{expectedCertificateDiscoveryEndpoint}'");
            }
            Logger.WriteLine($"JWT JKU location validation        : True");
            if (includeDetails)
            {
                Logger.WriteLine($"    JWT JKU value                  : {certificateDiscoveryEndpoint.ToString()}");
            }

            // Retrieve trusted signing keys from the attestation service
            var webClient = new WebClient();
            webClient.Headers.Add("tenantName", tenantName.Length > 24 ? tenantName.Remove(24) : tenantName);
            var jwksValue = webClient.DownloadString(certificateDiscoveryEndpoint);

            return jwksValue;
        }

#endregion
    }
}
