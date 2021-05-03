using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace validatequotes
{
    [Guid("46981BEA-6938-4D6F-8339-40C4CAC66E5B")]
    [ComImport]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IMetadataVerifier
    {
        bool VerifyQuoteInCertificate(
            [MarshalAs(UnmanagedType.LPStr)]string base64encodedCertificate);

        uint SecurityVersion();
        void ProductId(ref int productIdSize, ref IntPtr productId);
        void UniqueId(ref int uniqueIdSize, ref IntPtr uniqueId);
        void SignerId(ref int signerIdSize, ref IntPtr signerId);
    }

    public class VerifyMetadataCertificates
    {
        [DllImport("VerifyMetadataCertificates.dll")]
        public static extern int GetMetadataCertificateVerifier([Out]out IMetadataVerifier verifier);
    }


    class MaaQuoteValidator
    {
        static private byte[] ToByteArray(int size, IntPtr array)
        {
            byte[] byteArray = new byte[size];
            Marshal.Copy(array, byteArray, 0, size);
            Marshal.FreeCoTaskMem(array);
            return byteArray;
        }

        static public void ValidateMaaQuote(string x5c, bool includeDetails)
        {
            IMetadataVerifier certificateVerifier;
            VerifyMetadataCertificates.GetMetadataCertificateVerifier(out certificateVerifier);
            bool embeddedQuoteLocated = false;

            bool foundMaaQuoteInCertificate = false;
            X509Certificate2 maaCertificate = new X509Certificate2(Convert.FromBase64String(x5c));
            foreach (var extension in maaCertificate.Extensions)
            {
                if (extension.Oid.Value == "1.3.6.1.4.1.311.105.1")
                {
                    foundMaaQuoteInCertificate = true;
                    break;
                }
            }

            if (!foundMaaQuoteInCertificate)
            {
                Logger.WriteLine($"Could not find Attestation Quote Extension in certificate: {maaCertificate.Subject}");
                return;
            }
            try
            {
                if (certificateVerifier.VerifyQuoteInCertificate(x5c))
                {
                    embeddedQuoteLocated = true;
                }
            }
            catch (Exception x)
            {
                Logger.WriteLine($"Exception thrown locating quote in certificate: {x.Message}");
            }
            if (!embeddedQuoteLocated)
            {
                Logger.WriteLine($"Could not find quote in attestation certificate!");
            }

            if (includeDetails)
            {
                uint version = certificateVerifier.SecurityVersion();
                Logger.WriteLine($"    Security Version               : {version}");

                {
                    int productIdSize = 0;
                    IntPtr productIdRaw = IntPtr.Zero;
                    certificateVerifier.ProductId(ref productIdSize, ref productIdRaw);
                    byte[] productId = ToByteArray(productIdSize, productIdRaw);

                    Logger.WriteLine(37, 64, "    Product ID                     : ", BitConverter.ToString(productId).Replace("-", ""));
                }
                {
                    int signerIdSize = 0;
                    IntPtr signerIdRaw = IntPtr.Zero;
                    certificateVerifier.SignerId(ref signerIdSize, ref signerIdRaw);
                    byte[] signerId = ToByteArray(signerIdSize, signerIdRaw);

                    Logger.WriteLine(37, 64, "    Signer ID                      : ", BitConverter.ToString(signerId).Replace("-", ""));
                }

                {
                    int uniqueIdSize = 0;
                    IntPtr uniqueIdRaw = IntPtr.Zero;
                    certificateVerifier.UniqueId(ref uniqueIdSize, ref uniqueIdRaw);
                    byte[] uniqueId = ToByteArray(uniqueIdSize, uniqueIdRaw);

                    Logger.WriteLine(37, 64, "    Enclave ID                     : ", BitConverter.ToString(uniqueId).Replace("-", ""));
                }
            }
        }
    }
}
