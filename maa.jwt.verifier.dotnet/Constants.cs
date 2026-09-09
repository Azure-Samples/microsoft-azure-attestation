// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

namespace maa.jwt.verifier.sevsnp
{
    public static class Constants
    {
        // -----------------------------------------------------------------------------------
        // Evidence OID constants used for extracting SEV-SNP claims from x.509 certificates
        // -----------------------------------------------------------------------------------

        /// <summary>
        /// OID used to locate MAA evidence extension embedded in certificates.
        /// </summary>
        public const string MAA_EVIDENCE_CERTIFICATE_EXTENSION_OID = "1.3.6.1.4.1.311.105.1000.1";

        /// <summary>
        /// OID used to indicate the TEE kind (e.g., SEV-SNP) in the x.509 certificate.
        /// </summary>
        public const string MAA_EVIDENCE_TEEKIND_CERTIFICATE_OID = "1.3.6.1.4.1.311.105.1000.2";

        // -----------------------------------------------------------------------------------
        // SEV-SNP JSON claim names and values
        // -----------------------------------------------------------------------------------

        public const string SevSnpClaimNameLaunchMeasurement = "x-ms-sevsnpvm-launchmeasurement";
        public const string SevSnpTeeValue = "acisevsnp";
    }
}
