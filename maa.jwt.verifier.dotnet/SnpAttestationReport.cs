// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using System.Runtime.InteropServices;
using System.Formats.Asn1;

namespace maa.jwt.verifier.sevsnp
{
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct SnpSignature
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 72)]
        public byte[] RComponent;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 72)]
        public byte[] SComponent;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 368)]
        public byte[] RSVD;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct SnpAttestationReportStruct
    {
        public uint Version;
        public uint GuestSvn;
        public ulong Policy;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] FamilyId;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ImageId;

        public uint Vmpl;
        public uint SignatureAlgo;
        public ulong PlatformVersion;
        public ulong PlatformInfo;
        public uint AuthorKeyEn;
        public uint Reserved1;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] ReportData;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 48)]
        public byte[] Measurement;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] HostData;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 48)]
        public byte[] IdKeyDigest;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 48)]
        public byte[] AuthorKeyDigest;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] ReportId;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] ReportIdMa;

        public ulong ReportedTcb;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)]
        public byte[] Reserved2;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
        public byte[] ChipId;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] CommittedSvn;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] CommittedVersion;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] LaunchSvn;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 168)]
        public byte[] Reserved3;

        public SnpSignature Signature;
    }

    public class SnpAttestationReport
    {
        public byte[] RawBytes { get; private set; } = Array.Empty<byte>();
        public SnpAttestationReportStruct Struct { get; private set; }

        public static SnpAttestationReport Parse(byte[] data)
        {
            if (data.Length != 0x4A0)
            {
                throw new ArgumentException($"Expected report length of 0x4A0 (1184) bytes, got {data.Length}.");
            }

            GCHandle handle = GCHandle.Alloc(data, GCHandleType.Pinned);
            try
            {
                var parsedStruct = Marshal.PtrToStructure<SnpAttestationReportStruct>(handle.AddrOfPinnedObject());
                return new SnpAttestationReport
                {
                    RawBytes = data,
                    Struct = parsedStruct
                };
            }
            finally
            {
                handle.Free();
            }
        }

        public byte[] GetSignedPortion()
        {
            var result = new byte[0x4A0 - 512];
            Buffer.BlockCopy(RawBytes, 0, result, 0, result.Length);
            return result;
        }

        public string GetReportDataHex() => ToHex(Struct.ReportData);
        public string GetMeasurementHex() => ToHex(Struct.Measurement);
        public string GetHostDataHex() => ToHex(Struct.HostData);
        public string GetIdKeyDigestHex() => ToHex(Struct.IdKeyDigest);

        public byte[] GetDerEncodedSignature()
        {
            byte[] rComponent = (byte[])Struct.Signature.RComponent.Clone();
            byte[] sComponent = (byte[])Struct.Signature.SComponent.Clone();

            Array.Reverse(rComponent);
            Array.Reverse(sComponent);

            rComponent = TrimLeadingZeroes(rComponent);
            sComponent = TrimLeadingZeroes(sComponent);

            var writer = new AsnWriter(AsnEncodingRules.DER);
            writer.PushSequence();
            writer.WriteIntegerUnsigned(rComponent);
            writer.WriteIntegerUnsigned(sComponent);
            writer.PopSequence();

            return writer.Encode();
        }

        private static byte[] TrimLeadingZeroes(byte[] input)
        {
            int index = 0;
            while (index < input.Length - 1 && input[index] == 0)
            {
                index++;
            }
            return input[index..];
        }

        private static string ToHex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
    }
}
