using Azure.Security.Attestation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace validatequotes.Helpers
{
    class JwtValidationHelper
    {
        public static bool ValidateMaaJwt(string attestDnsName, AttestationToken serviceToken, AttestationSigner tokenSigner, bool includeDetails)
        {
            var tenantName = attestDnsName.Split('.')[0];
            var attestUri = new Uri($"https://{attestDnsName}");

            AttestationResult result = serviceToken.GetBody<AttestationResult>();
            ValidateJwtIssuerIsTenant(result, attestUri, includeDetails);
            ValidateSigningCertIssuerMatchesJwtIssuer(result, tokenSigner, includeDetails);

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
