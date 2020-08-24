using Microsoft.IdentityModel.Clients.ActiveDirectory;
using System.Threading.Tasks;

namespace validatequotes
{
    public class Authentication
    {
        private const string resource = "https://attest.azure.net";
        private const string clientId = "1950a258-227b-4e31-a9cf-717495945fc2";
        private const string TokenCacheFileName = "tokencache.bin";
        private static TokenCache _tokenCache;

        private class ByteArrayWrapper
        {
            public byte[] theBytes;
        }

        static Authentication()
        {
            var baw = SerializationHelper.ReadFromFile<ByteArrayWrapper>(TokenCacheFileName);
            _tokenCache = new TokenCache();
            _tokenCache.DeserializeAdalV3(baw.theBytes);
        }

        public static async Task<string> AcquireAccessTokenAsync(string tenant)
        {
            string accessToken = null;

            var ctx = new AuthenticationContext($"https://login.windows.net/{tenant}", _tokenCache);
            
            try
            {
                accessToken = (await ctx.AcquireTokenSilentAsync(resource, clientId)).AccessToken;
            }
            catch (AdalException x)
            {
                Logger.WriteLine($"Silent token acquisition failed.");
                Logger.WriteLine($"ADAL Exception: {x.Message}");
                Logger.WriteLine($"Retrieving token via device code authentication now.");
                
                DeviceCodeResult codeResult = await ctx.AcquireDeviceCodeAsync(resource, clientId);
                Logger.WriteLine("Please sign into your AAD account.");
                Logger.WriteLine($"{codeResult.Message}");
                Logger.WriteLine("");
                accessToken = (await ctx.AcquireTokenByDeviceCodeAsync(codeResult)).AccessToken;
                SerializationHelper.WriteToFile(TokenCacheFileName, new ByteArrayWrapper { theBytes = _tokenCache.SerializeAdalV3() });
            }

            return accessToken;
        }
    }
}
