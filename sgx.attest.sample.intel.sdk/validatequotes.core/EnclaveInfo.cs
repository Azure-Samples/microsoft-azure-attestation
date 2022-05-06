using System;
using System.Linq;
using System.Threading.Tasks;
using Azure.Security.Attestation;

namespace validatequotes
{
    public class EnclaveInfo
    {
        public int Type { get; set; }
        public string MrEnclaveHex { get; set; }
        public string MrSignerHex { get; set; }
        public string ProductIdHex { get; set; }
        public uint SecurityVersion { get; set; }
        public ulong Attributes { get; set; }
        public string QuoteHex { get; set; }
        public string EnclaveHeldDataHex { get; set; }

        public async static Task<EnclaveInfo> CreateFromFileAsync(string filePath)
        {
            return await SerializationHelper.ReadFromFileAsync<EnclaveInfo>(filePath);
        }

        public void CompareToMaaServiceJwtToken(AttestationResult serviceResult, bool includeDetails)
        {
            //if (includeDetails)
            //{
            //    Logger.WriteLine("");
            //    Logger.WriteLine("Claims in MAA Service JWT Token");
            //    Logger.WriteLine($"{jwtBody.ToString()}");
            //    Logger.WriteLine("");
            //}

            var isDebuggable = (Attributes & 2) != 0; // In SGX, DEBUG flag is equal to 0x0000000000000002ULL
            var isdpassed = isDebuggable == serviceResult.IsDebuggable;
            Logger.WriteLine($"IsDebuggable match                 : {isdpassed}");
            if (includeDetails)
            {
                Logger.WriteLine($"    We think   : {isDebuggable}");
                Logger.WriteLine($"    MAA service: {serviceResult.IsDebuggable}");
            }

            var mrepassed = MrEnclaveHex.ToLower().Equals(serviceResult.MrEnclave);
            Logger.WriteLine($"MRENCLAVE match                    : {mrepassed}");
            if (includeDetails)
            {
                Logger.WriteLine($"    We think   : {MrEnclaveHex.ToLower()}");
                Logger.WriteLine($"    MAA service: {serviceResult.MrEnclave}");
            }

            var mrspassed = MrSignerHex.ToLower().Equals(serviceResult.MrSigner.ToLower());
            Logger.WriteLine($"MRSIGNER match                     : {mrspassed}");
            if (includeDetails)
            {
                Logger.WriteLine($"    We think   : {MrSignerHex.ToLower()}");
                Logger.WriteLine($"    MAA service: {serviceResult.MrSigner}");
            }

            var pidpassed = BitConverter.ToUInt64(HexHelper.ConvertHexToByteArray(ProductIdHex), 0) == (ulong)serviceResult.ProductId;
            Logger.WriteLine($"ProductID match                    : {pidpassed}");
            if (includeDetails)
            {
                Logger.WriteLine($"    We think   : {BitConverter.ToUInt64(HexHelper.ConvertHexToByteArray(ProductIdHex), 0)}");
                Logger.WriteLine($"    MAA service: {serviceResult.ProductId}");
            }

            var svnPassed = SecurityVersion == (uint)serviceResult.Svn;
            Logger.WriteLine($"Security Version match             : {svnPassed}");
            if (includeDetails)
            {
                Logger.WriteLine($"    We think   : {SecurityVersion}");
                Logger.WriteLine($"    MAA service: {serviceResult.Svn}");
            }

            var ehdExpected = HexHelper.ConvertHexToByteArray(EnclaveHeldDataHex);
            var ehdActual = serviceResult.EnclaveHeldData;
            var ehdPassed = ehdExpected.SequenceEqual(ehdActual.ToArray());
            Logger.WriteLine($"Enclave Held Data match            : {ehdPassed}");
            if (includeDetails)
            {
                Logger.WriteLine(17, 100, "    We think   : ", Convert.ToBase64String(ehdExpected));
                Logger.WriteLine(17, 100, "    MAA service: ", Convert.ToBase64String(serviceResult.EnclaveHeldData));
            }

            Logger.WriteLine("");
        }
    }
}
