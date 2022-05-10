using Azure.Security.Attestation;
using System;
using System.Linq;

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

        public static EnclaveInfo CreateFromFile(string filePath)
        {
            return SerializationHelper.ReadFromFile<EnclaveInfo>(filePath);
        }

        public AttestOpenEnclaveRequestBody GetMaaBody()
        {
            var maaBody = new AttestOpenEnclaveRequestBody
            {
                Quote = HexHelper.ConvertHexToBase64Url(QuoteHex),
                EnclaveHeldData = HexHelper.ConvertHexToBase64Url(EnclaveHeldDataHex)
            };
            return maaBody;
        }

        public void CompareToMaaServiceJwtToken(AttestationResult attestationResult, bool includeDetails)
        {
            //if (includeDetails)
            //{
            //    Logger.WriteLine("");
            //    Logger.WriteLine("Claims in MAA Service JWT Token");
            //    Logger.WriteLine($"{jwtBody.ToString()}");
            //    Logger.WriteLine("");
            //}

            var isDebuggable = (Attributes & 1) == 1;
            var isdpassed = isDebuggable == attestationResult.IsDebuggable;
            Logger.WriteLine($"IsDebuggable match                 : {isdpassed}");
            if (includeDetails)
            {
                Logger.WriteLine($"    We think   : {isDebuggable}");
                Logger.WriteLine($"    MAA service: {attestationResult.IsDebuggable}");
            }

            var mrepassed = MrEnclaveHex.ToLower().Equals(attestationResult.MrEnclave);
            Logger.WriteLine($"MRENCLAVE match                    : {mrepassed}");
            if (includeDetails)
            {
                Logger.WriteLine($"    We think   : {MrEnclaveHex.ToLower()}");
                Logger.WriteLine($"    MAA service: {attestationResult.MrEnclave}");
            }

            var mrspassed = MrSignerHex.ToLower().Equals(attestationResult.MrSigner.ToLower());
            Logger.WriteLine($"MRSIGNER match                     : {mrspassed}");
            if (includeDetails)
            {
                Logger.WriteLine($"    We think   : {MrSignerHex.ToLower()}");
                Logger.WriteLine($"    MAA service: {attestationResult.MrSigner}");
            }

            var pidpassed = BitConverter.ToUInt64(HexHelper.ConvertHexToByteArray(ProductIdHex), 0) == (ulong)attestationResult.ProductId;
            Logger.WriteLine($"ProductID match                    : {pidpassed}");
            if (includeDetails)
            {
                Logger.WriteLine($"    We think   : {BitConverter.ToUInt64(HexHelper.ConvertHexToByteArray(ProductIdHex), 0)}");
                Logger.WriteLine($"    MAA service: {attestationResult.ProductId}");
            }

            var svnPassed = SecurityVersion == (uint)attestationResult.Svn;
            Logger.WriteLine($"Security Version match             : {svnPassed}");
            if (includeDetails)
            {
                Logger.WriteLine($"    We think   : {SecurityVersion}");
                Logger.WriteLine($"    MAA service: {attestationResult.Svn}");
            }

            var ehdExpected = HexHelper.ConvertHexToByteArray(EnclaveHeldDataHex);
            var ehdActual = attestationResult.EnclaveHeldData;
            var ehdPassed = ehdExpected.SequenceEqual(ehdActual.ToArray());
            Logger.WriteLine($"Enclave Held Data match            : {ehdPassed}");
            if (includeDetails)
            {
                Logger.WriteLine(17, 100, "    We think   : ", Base64Url.EncodeBytes(ehdExpected));
                Logger.WriteLine(17, 100, "    MAA service: ", Base64Url.EncodeBytes(attestationResult.EnclaveHeldData.ToArray()));
            }

            Logger.WriteLine("");
        }
    }
}
