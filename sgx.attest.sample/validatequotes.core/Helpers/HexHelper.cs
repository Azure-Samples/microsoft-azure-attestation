using System;
using System.Collections.Generic;

namespace validatequotes
{
    public class HexHelper
    {
        public static string ConvertHexToBase64Url(string hexString)
        {
            byte[] hexBytes = ConvertHexToByteArray(hexString);
            return Base64Url.EncodeBytes(hexBytes);
        }

        public static byte[] ConvertHexToByteArray(string hexString)
        {
            if (hexString.Length % 2 == 1)
            {
                throw new Exception("ConvertHexToByteArray: Odd number of characters presented!");
            }

            List<byte> bytes = new List<byte>();

            var upperHexString = hexString.ToUpper();
            for (int i = 0; i < upperHexString.Length; i = i + 2)
            {
                bytes.Add(CalculateByteValue(upperHexString[i], upperHexString[i + 1]));
            }

            return bytes.ToArray();
        }

        private static byte CalculateByteValue(char c1, char c2)
        {
            return (byte)((CalculateNibbleValue(c1) << 4) + CalculateNibbleValue(c2));
        }

        private static byte CalculateNibbleValue(char c)
        {
            byte value;

            if ((c >= 'A') && (c <= 'F'))
            {
                value = (byte)(c - 'A' + 10);
            }
            else if ((c >= '0') && (c <= '9'))
            {
                value = (byte)(c - '0');
            }
            else
            {
                throw new Exception($"CalculateNibbleValue: Character out of bounds! ({c})");
            }
            return value;
        }
    }
}
