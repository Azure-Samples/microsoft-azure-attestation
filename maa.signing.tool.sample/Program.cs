using CommandLine;
using maa.signing.tool.utils;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace maa.signing.tool
{
    public class Program
    {
        public static void Main(string[] args)
        {
            new Program().Run(args);
        }

        public void Run(string[] args)
        {
            try
            {
                Parser.Default.ParseArguments<SignPolicyOptions, SignCertOptions, CreateSigningCertOptions>(args)
                  .MapResult(
                    (SignPolicyOptions options) => { InitTracing(options); return SignPolicy(options); },
                    (SignCertOptions options) => { InitTracing(options); return SignCert(options); },
                    (CreateSigningCertOptions options) => { InitTracing(options); return CreateSigningCert(options); },
                    errors => 1);
            }
            catch (ValidationFailedException)
            {
                // Ignore since error has already been reported
            }
        }

        private int SignPolicy(SignPolicyOptions options)
        {
            var (signingKey, signingCert) = GetSigningKeyAndCert(options);

            // Get policy
            ValidateFileExists(options.PolicyFileName, "Policy file is not accessable");
            var policy = File.ReadAllText(options.PolicyFileName);
            Tracer.TraceVerbose($"Policy to be signed = \n{policy}\n");

            // Sign policy
            var policyJwt = JwtUtils.GenerateSignedPolicyJsonWebToken(policy, signingKey, signingCert);
            Tracer.TraceVerbose($"Generated signed JWT = \n{JwtUtils.FormatJwt(policyJwt)}\n");

            // Report JWT
            if (!string.IsNullOrEmpty(options.JwtFileName))
            {
                File.WriteAllText(options.JwtFileName, policyJwt);
            }
            Console.WriteLine();
            Console.WriteLine($"Policy JWT:");
            Console.WriteLine($"{policyJwt}");
            Console.WriteLine();

            return 0;
        }

        private int SignCert(SignCertOptions options)
        {
            var (signingKey, signingCert) = GetSigningKeyAndCert(options);

            // Get certificate
            ValidateFileExists(options.CertFileName, "Certificate file is not accessable");
            var cert = new X509Certificate2(options.CertFileName);

            // Sign certificate
            var certJwt = JwtUtils.GenerateSignedCertificateJsonWebToken(cert, signingKey, signingCert);
            Tracer.TraceVerbose($"Generated signed JWT = \n{JwtUtils.FormatJwt(certJwt)}\n");

            // Report JWT
            if (!string.IsNullOrEmpty(options.JwtFileName))
            {
                File.WriteAllText(options.JwtFileName, certJwt);
            }
            Console.WriteLine();
            Console.WriteLine($"Cert JWT:");
            Console.WriteLine($"{certJwt}");
            Console.WriteLine();

            return 0;
        }

        private int CreateSigningCert(CreateSigningCertOptions options)
        {
            Console.WriteLine();
            Console.WriteLine($"To create a signing key and certificate files follow these steps:");
            Console.WriteLine();
            Console.WriteLine($"    1. Locate an environment with access to the openssl tool (e.g. WSL shell, Linux Bash)");
            Console.WriteLine();
            Console.WriteLine($"    2. Switch to a directory where you will store the two generated files");
            Console.WriteLine();
            Console.WriteLine($"    3. For a password protected key file, run this command:");
            Console.WriteLine($"           openssl req -newkey rsa:2048 -keyout mycert.key -x509 -days 36500 -out mycert.crt");
            Console.WriteLine();
            Console.WriteLine($"    4. For a non password protected key file, run this command:");
            Console.WriteLine($"           openssl req -newkey rsa:2048 -nodes -keyout mycert.key -x509 -days 36500 -out mycert.crt");
            Console.WriteLine();

            return 0;
        }

        private void InitTracing(TraceOptions options)
        {
            if (options.Verbose)
            {
                Tracer.CurrentTracingLevel = TracingLevel.Verbose;
            }
        }

        private void ValidateFileExists(string path, string errorMessage)
        {
            if (!File.Exists(path))
            {
                Tracer.TraceError(errorMessage);
                throw new ValidationFailedException(errorMessage);
            }
        }

        private (RSA signingKey, X509Certificate2 signingCert) GetSigningKeyAndCert(SharedOptions options)
        {
            // Validate access to both files
            ValidateFileExists(options.KeyFileName, "Signing key file is not accessable");
            ValidateFileExists(options.SigningCertFileName, "Signing certificate file is not accessable");

            // Import signing key
            var signingKeyPemText = File.ReadAllText(options.KeyFileName);
            var signingKey = RSA.Create();
            if (string.IsNullOrEmpty(options.KeyFilePassword))
            {
                signingKey.ImportFromPem(signingKeyPemText.ToCharArray());
            }
            else
            {
                signingKey.ImportFromEncryptedPem(signingKeyPemText, options.KeyFilePassword);
            }

            // Import signing certificate
            var signingCert = new X509Certificate2(options.SigningCertFileName);

            return (signingKey, signingCert);
        }

        private class ValidationFailedException : Exception
        {
            public ValidationFailedException(string message) : base(message) { }
        }
    }
}