using CommandLine;

namespace maa.signing.tool
{
    public class TraceOptions
    {
        [Option('v', "verbose", Required = false, HelpText = "Enable verbose tracing")]
        public bool Verbose { get; set; } = false;

    }

    public class SharedOptions : TraceOptions
    {
        [Option('k', "keyfile", Required = true, HelpText = "Path to PEM formatted file that contains your 2048 bit RSA private key")]
        public string KeyFileName { get; set; } = string.Empty;

        [Option('x', "password", Required = false, HelpText = "Password required to decrypt a PEM formatted key file that is encrypted")]
        public string KeyFilePassword { get; set; } = string.Empty;

        [Option('s', "signingcertfile", Required = true, HelpText = "Path to PEM formatted file that contains your signing certificate")]
        public string SigningCertFileName { get; set; } = string.Empty;

        [Option('j', "jwtfile", Required = false, HelpText = "Path to store generated JWT")]
        public string JwtFileName { get; set; } = string.Empty;
    }

    [Verb("signpolicy", HelpText = "Create a signed policy JWT for upload to an MAA Isolated mode attestation provider")]
    public class SignPolicyOptions : SharedOptions
    {
        [Option('p', "policyfile", Required = true, HelpText = "Path to text file that contains the MAA policy to be signed into a MAA policy JWT")]
        public string PolicyFileName { get; set; } = string.Empty;
    }

    [Verb("signcert", HelpText = "Create a signed certificate JWT for upload to an MAA Isolated mode attestation provider")]
    public class SignCertOptions : SharedOptions
    {
        [Option('c', "certfile", Required = true, HelpText = "Path to certificate file to be signed into a MAA certificate JWT")]
        public string CertFileName { get; set; } = string.Empty;
    }

    [Verb("createsigningcert", HelpText = "Create a signing key and certificate")]
    public class CreateSigningCertOptions : TraceOptions
    {
    }
}
