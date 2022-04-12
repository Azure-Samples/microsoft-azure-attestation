using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace maa.signing.tool.utils
{
    public class JwtUtils
    {
        public static string GenerateSignedPolicyJsonWebToken(string policy, RSA signingKey, X509Certificate2 signingCert)
        {

            if (!policy.StartsWith('"'))
            {
                policy = policy.Replace("\n", @"\n");
                policy = policy.Replace("\r", @"\r");
                policy = policy.Replace("\"", "\\\"");
                policy = "\"" + policy + "\"";
                Tracer.TraceVerbose($"Updated policy to be signed = \n{policy}\n");
            }
            return GenerateSingleClaimJsonWebToken("AttestationPolicy", policy, signingKey, signingCert);
        }

        public static string GenerateSignedCertificateJsonWebToken(X509Certificate2 embeddedCertificate, RSA signingKey, X509Certificate2 signingCert)
        {
            var exportedCert = embeddedCertificate.Export(X509ContentType.Cert);
            string jwkToAdd = $"{{\"kty\":\"RSA\", \"x5c\":[\"{System.Convert.ToBase64String(exportedCert)}\"]}}";
            return GenerateSingleClaimJsonWebToken("maa-policyCertificate", jwkToAdd, signingKey, signingCert);
        }

        public static string FormatJwt(string raw)
        {
            StringBuilder sb = new StringBuilder();
            string[] stringTokens = raw.Split(new char[] { '.', '\t', ' ', '\n', '\r' });

            foreach (var tf in stringTokens)
            {
                try
                {
                    // We'll assume a base 64 URL encoded string that's a JSON structure.  If not, it's
                    // OK to thrown an exception and move along.
                    byte[] theBytes = Convert.FromBase64String(Pad(tf.Replace('-', '+').Replace('_', '/')));
                    var obj = JsonConvert.DeserializeObject(System.Text.Encoding.UTF8.GetString(theBytes));
                    if (obj != null)
                    {
                        sb.AppendFormat("{0}\n", obj.ToString());
                    }
                }
                catch (Exception)
                {
                    //sb.AppendFormat("Non JSON Field ignored\n");
                }
            }

            return sb.ToString();
        }

        private static string Pad(string input)
        {
            var count = 3 - ((input.Length + 3) % 4);

            if (count == 0)
            {
                return input;
            }

            return input + new string('=', count);
        }

        private static string GenerateSignedJsonWebToken(string jwtBody, RSA signingKey, X509Certificate2 signingCert)
        {
            // Encode header and body
            string encodedHeader = Base64Url.Encode(Encoding.UTF8.GetBytes(FormatJoseHeader(signingCert)));
            string encodedBody = Base64Url.Encode(Encoding.UTF8.GetBytes(jwtBody));

            // Sign
            var rawSignature = signingKey.SignData(Encoding.UTF8.GetBytes(encodedHeader + "." + encodedBody), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // Return JWT 
            return encodedHeader + "." + encodedBody + "." + Base64Url.Encode(rawSignature);
        }

        private static string GenerateSingleClaimJsonWebToken(string claimName, string claimValue, RSA signingKey, X509Certificate2 signingCert)
        {
            string jwtBody = "";
            jwtBody += "{";
            jwtBody += $"\"{claimName}\":{claimValue}";
            jwtBody += "}";

            return GenerateSignedJsonWebToken(jwtBody, signingKey, signingCert);
        }

        private static string FormatJoseHeader(X509Certificate2 signingCertificate)
        {
            string exportedCert = Convert.ToBase64String(signingCertificate.Export(X509ContentType.Cert));

            string joseHeader = "{ \"alg\":\"RS256\", \"x5c\": [";
            joseHeader += "\"" + exportedCert + "\"";
            joseHeader += "]}";
            return joseHeader;
        }
    }
}
