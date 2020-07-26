using System;
using System.Runtime.InteropServices;

namespace validatequotes
{
    [Guid("46981BEA-6938-4D6F-8339-40C4CAC66E5B")]
    [ComImport]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    public interface IMetadataVerifier
    {
        bool VerifyQuoteExtensionInCertificate(
            [MarshalAs(UnmanagedType.LPStr)]string base64encodedCertificate);
        bool VerifyQuoteInExtension();
        bool VerifyCertificateKeyMatchesHash();

        uint SecurityVersion();
        void ProductId(ref int productIdSize, ref IntPtr productId);
        void UniqueId(ref int uniqueIdSize, ref IntPtr uniqueId);
        void SignerId(ref int signerIdSize, ref IntPtr signerId);
        void ReportData(ref int reportDataSize, ref IntPtr reportData);
        void PublicKeyHash(ref int publicKeyHashSize, ref IntPtr publicKeyHash);
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

            try
            {
                if (certificateVerifier.VerifyQuoteExtensionInCertificate(x5c))
                {
                    embeddedQuoteLocated = true;
                }
            }
            catch (Exception x)
            {
                //Logger.WriteLine($"Exception thrown locating quote in certificate: {x.ToString()}");
            }

            Logger.WriteLine($"Embedded quote found in certificate: {embeddedQuoteLocated}");
            if (!embeddedQuoteLocated)
            {
                return;
            }

            var quoteVerifiedByIntel = certificateVerifier.VerifyQuoteInExtension();
            Logger.WriteLine($"Quote verified by Intel            : {quoteVerifiedByIntel}");
            if (!quoteVerifiedByIntel)
            {
                return;
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

                {
                    int reportDataSize = 0;
                    IntPtr reportDataRaw = IntPtr.Zero;
                    certificateVerifier.ReportData(ref reportDataSize, ref reportDataRaw);
                    byte[] reportData = ToByteArray(reportDataSize, reportDataRaw);

                    Logger.WriteLine(37, 64, "    Report data                    : ", BitConverter.ToString(reportData).Replace("-", ""));
                }

                {
                    int publicKeyHashSize = 0;
                    IntPtr publicKeyHashRaw = IntPtr.Zero;
                    certificateVerifier.PublicKeyHash(ref publicKeyHashSize, ref publicKeyHashRaw);
                    byte[] publicKeyHash = ToByteArray(publicKeyHashSize, publicKeyHashRaw);

                    Logger.WriteLine(37, 64, "    Public key hash                : ", BitConverter.ToString(publicKeyHash).Replace("-", ""));
                }
            }

            var signingCertKeyMatchesHash = certificateVerifier.VerifyCertificateKeyMatchesHash();
            Logger.WriteLine($"Signing cert key matches hash      : {signingCertKeyMatchesHash}");
        }
    }
}
