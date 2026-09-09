// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using static maa.jwt.verifier.sevsnp.CoseSign1;

namespace maa.jwt.verifier.sevsnp
{
    public static class TrustedValues
    {
        // -----------------------------------------------------------------------------------
        // Trusted AMD root keys
        // -----------------------------------------------------------------------------------

        /// <summary>
        /// AMD root key for validating UVM endorsements. Provided by AMD.
        /// Contact AMD for updates or rotated root keys.
        /// </summary>
        public const string AmdRootKey = @"-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsV
mD7FktuotWwX1fNgW41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU
0V5tkKiU1EesNFta1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S
1ju8X93+6dxDUrG2SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI5
2Naz5m2B+O+vjsC060d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3K
FYXP59XmJgtcog05gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd
/y8KxX7jksTEzAOgbKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBk
gnlENEWx1UcbQQrs+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V
9TJQqnN3Q53kt5viQi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnq
z55I0u33wh4r0ZNQeTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+Og
pCCoMNit2uLo9M18fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXo
QPHfbkH0CyPfhl1jWhJFZasCAwEAAQ==
-----END PUBLIC KEY-----";

        /// <summary>
        /// AMD Genoa-specific root key for validating UVM endorsements from Genoa platforms.
        /// Contact AMD for updates or rotated root keys.
        /// </summary>
        public const string AmdRootKeyGenoa = @"-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA3Cd95S/uFOuRIskW9vz9
VDBF69NDQF79oRhL/L2PVQGhK3YdfEBgpF/JiwWFBsT/fXDhzA01p3LkcT/7Ldjc
RfKXjHl+0Qq/M4dZkh6QDoUeKzNBLDcBKDDGWo3v35NyrxbA1DnkYwUKU5AAk4P9
4tKXLp80oxt84ahyHoLmc/LqsGsp+oq1Bz4PPsYLwTG4iMKVaaT90/oZ4I8oibSr
u92vJhlqWO27d/Rxc3iUMyhNeGToOvgx/iUo4gGpG61NDpkEUvIzuKcaMx8IdTpW
g2DF6SwF0IgVMffnvtJmA68BwJNWo1E4PLJdaPfBifcJpuBFwNVQIPQEVX3aP89H
JSp8YbY9lySS6PlVEqTBBtaQmi4ATGmMR+n2K/e+JAhU2Gj7jIpJhOkdH9firQDn
mlA2SFfJ/Cc0mGNzW9RmIhyOUnNFoclmkRhl3/AQU5Ys9Qsan1jT/EiyT+pCpmnA
+y9edvhDCbOG8F2oxHGRdTBkylungrkXJGYiwGrR8kaiqv7NN8QhOBMqYjcbrkEr
0f8QMKklIS5ruOfqlLMCBw8JLB3LkjpWgtD7OpxkzSsohN47Uom86RY6lp72g8eX
HP1qYrnvhzaG1S70vw6OkbaaC9EjiH/uHgAJQGxon7u0Q7xgoREWA/e7JcBQwLg8
0Hq/sbRuqesxz7wBWSY254cCAwEAAQ==
-----END PUBLIC KEY-----";

        public static readonly List<string> AmdRootKeys = new()
        {
            TrustedValues.AmdRootKey,
            TrustedValues.AmdRootKeyGenoa
        };

        // -----------------------------------------------------------------------------------
        // UVM Endorsement Signing Keys
        // -----------------------------------------------------------------------------------

        /// <summary>
        /// Root CA public key for PRSS signing certificates used by AMD C-ACI.
        /// Endorsements chaining to this root must contain EKU 1.3.6.1.4.1.311.76.59.1.2.
        /// </summary>
        public const string UvmEndorsementSigningKeyPrssCA = @"
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAniUBZhkfZDTBnTkjYh1x
i1bqJdKbH+8nAYK/d9iUM4MYSJtQnnuWZMLQw19F/zKc6BcXvXjtdZhfOgYIKxw3
m0ZKkAqwr0aSPjOJKvq45zJj8yPHbtIU+yZY7v4GhFT6wR83qtvU7FYqv0m9zOsC
7cZO/KwZtRI1aRWJF02jaOpsHimaCfPOeiHGCdEZ6o8wRmk7aAQrfIot1mNd6m3W
OZ69Bj5b7i8RWyhrp1KkaF5MpOquziO/TDZx2oFFUI7Khs7/U8O4Q7Mk7gd6orT6
xwode8ZSNTHsCB+EgJJb+LHaOdbJ5+WJBH5Rf/TmamRHSer47Kb2oENT/trDIyTY
JdoTLCq3P5TedxxMeBxq+ZqP62oVd3etSYTOEEDHmUgP1ZYegJxzoTihA2/TTSDQ
tUPk9y54D073vL9l2m2QC1u/3uonJ5lk+Dl8cz3WIdLu1vNTES5Vw9zq8SlX3lGh
eHOQCy/1yXU2643SbY55XboaOP/fGQGo0sjR1vLrivUu0cyTE5uckHhlY3kExPGe
n4w682QM/pgdk+KPVqVjUyO4bnMWRRq293sPzaQy/1r+lo3hh3jbcIOoJIVpIMJt
Eg3lefYqWc/Wq+eB5qCxiC0IjAuxz9dsNq+e+QNn2UFzqatFuHFgWBjUFixlutEF
3pLFUBARkM5HzPuvvyPAnwUCAwEAAQ==
-----END PUBLIC KEY-----";

        // -----------------------------------------------------------------------------------
        // Trusted UVM endorsement anchors
        // -----------------------------------------------------------------------------------

        /// <summary>
        /// List of trusted trust anchors for verifying UVM endorsements. These represent
        /// either trusted signing keys or root CA public keys and their required EKU (if applicable).
        /// </summary>
        public static readonly List<TrustAnchor> UvmEndorsementTrustAnchors = new()
        {
            new TrustAnchor(
                friendlyName: "ACI Root CA Trust Anchor",
                signer: new TrustedCertChainSigner(new TrustedSigningCertChain(
                    UvmEndorsementSigningKeyPrssCA,
                    "1.3.6.1.4.1.311.76.59.1.2"  // EKU required in leaf cert
                ))
            ),
        };
    }
}
