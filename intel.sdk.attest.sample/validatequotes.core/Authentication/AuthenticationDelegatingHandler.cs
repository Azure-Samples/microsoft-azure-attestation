using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace validatequotes
{
    public class AuthenticationDelegatingHandler : DelegatingHandler
    {
        private Dictionary<string, string> TenantLookup;
        private const string TenantLookupFileName = "tenantlookup.bin";

        public AuthenticationDelegatingHandler()
            : base(new SocketsHttpHandler())
        {
            TenantLookup = SerializationHelper.ReadFromFile<Dictionary<string, string>>(TenantLookupFileName);
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            string aadTenant = null;
            string accessToken = null;
            string hostName = request.RequestUri.Host;

            // Get access token if we already know the tenant for the attestation provider
            if (TenantLookup.ContainsKey(hostName))
            {
                aadTenant = TenantLookup[hostName];
                accessToken = await Authentication.AcquireAccessTokenAsync(aadTenant);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            }

            // Call service
            var response = await base.SendAsync(request, cancellationToken);

            // Retry one time on unauthorized -- it's either because:
            //   * We didn't know the AAD tenant and didn't include a bearer token
            //   * The token expired and we need to refresh it from AAD
            // So, take note of current AAD tenant value, re-authenticate and retry
            if ((response.StatusCode == System.Net.HttpStatusCode.Unauthorized))
            {
                // Always record AAD tenant for hostname (in edge cases it can move)
                aadTenant = ParseAadTenant(response.Headers.GetValues("WWW-Authenticate").FirstOrDefault());
                TenantLookup[hostName] = aadTenant;
                SerializationHelper.WriteToFile(TenantLookupFileName, TenantLookup);

                // Authenticate with AAD
                accessToken = await Authentication.AcquireAccessTokenAsync(aadTenant);

                // Retry one time
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                response = await base.SendAsync(request, cancellationToken);
            }

            return response;
        }

        private string ParseAadTenant(string headerValue)
        {
            // Bearer authorization_uri="https://login.windows.net/72f988bf-86f1-41af-91ab-2d7cd011db47", resource="https://attest.azure.net"
            const string startString = "login.windows.net/";
            const string endString = "\"";

            var startIndex = headerValue.IndexOf(startString) + startString.Length;
            var endIndex = headerValue.IndexOf(endString, startIndex);

            return headerValue.Substring(startIndex, endIndex - startIndex);
        }
    }
}
