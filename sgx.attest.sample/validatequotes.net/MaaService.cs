using Newtonsoft.Json;
using System;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace validatequotes
{
    public class MaaService
    {
        private string providerDnsName;
        private static HttpClient theHttpClient;

        static MaaService()
        {
            theHttpClient = new HttpClient(new AuthenticationDelegatingHandler());
        }

        public MaaService(string providerDnsName)
        {
            this.providerDnsName = providerDnsName;
        }

        public async Task<string> AttestOpenEnclaveAsync(AttestOpenEnclaveRequestBody requestBody)
        {
            // Build request
            var uri = $"https://{providerDnsName}:443/attest/Tee/OpenEnclave?api-version=2018-09-01-preview";
            var request = new HttpRequestMessage(HttpMethod.Post, uri);
            request.Content = new StringContent(JsonConvert.SerializeObject(requestBody));

            // Send request
            var response = await theHttpClient.SendAsync(request);

            // Analyze failures
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                var body = await response.Content.ReadAsStringAsync();
                throw new Exception($"AttestOpenEnclaveAsync: MAA service status code {(int)response.StatusCode}.  Details: '{body}'");
            }

            // Return result
            var jwt = await response.Content.ReadAsStringAsync();
            return jwt.Trim('"');
        }
    }
}
