//#define LOG_BOUNCY_CASTLE

using System.Text.Json;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.X509;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Azure.Security.Attestation;

namespace validatequotes.Helpers
{
    class JwtValidationHelper
    {
        public static bool ValidateMaaJwt(string attestDnsName, AttestationToken token, AttestationSigner signer, bool includeDetails)
        {
            var tenantName = attestDnsName.Split('.')[0];
            var attestUri = new Uri($"https://{attestDnsName}");

            AttestationResult result = token.GetBody<AttestationResult>();
            ValidateJwtIssuerIsTenant(result, attestUri, includeDetails);
            ValidateSigningCertIssuerMatchesJwtIssuer(result, signer, includeDetails);

            X509Certificate2 signingCertificate = signer.SigningCertificates[0];
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

            return true;
        }

        #region Internal implementation details

        private static void ValidateSigningCertIssuerMatchesJwtIssuer(AttestationResult result, AttestationSigner signer, bool includeDetails)
        {
            // Ensure that the JWT signing certificate is issued by the same issuer as the JWT itself
            var signingCertificate = signer.SigningCertificates[0];
            if (!string.Equals(signingCertificate.Issuer, "CN=" + result.Issuer.OriginalString, StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException("JWT is not valid (signing certificate issuer does not match JWT issuer)");
            }
            Logger.WriteLine($"JWT signing cert issuer validation : True");
            if (includeDetails)
            {
                Logger.WriteLine($"    Signing certificate issuer     : {signingCertificate.Issuer}");
            }
        }

        private static void ValidateJwtIssuerIsTenant(AttestationResult result, Uri tenantAttestUri, bool includeDetails)
        {
            // Verify that the JWT issuer is indeed the tenantAttestUri (tenant specific URI)
            if (Uri.Compare(tenantAttestUri, result.Issuer, UriComponents.AbsoluteUri, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) != 0)
            {
                throw new ArgumentException("JWT is not valid (iss claim does not match attest URI)");
            }
            Logger.WriteLine($"JWT issuer claim validation        : True");
            if (includeDetails)
            {
                Logger.WriteLine($"    JWT Issuer claim value         : {result.Issuer}");
            }
        }
#endregion
    }
}
