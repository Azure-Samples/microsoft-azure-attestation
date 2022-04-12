namespace maa.signing.tool.utils
{
    /// <summary>
    /// Converts to/from Base64URL encoding, per http://www.rfc-editor.org/rfc/rfc4648.txt.
    /// </summary>
    public static class Base64Url
    {
        /// <summary>Encode a byte array as a Base64URL encoded string.</summary>
        /// <param name="bytes">Raw byte input buffer.</param>
        /// <returns>The bytes, encoded as a Base64URL string.</returns>
        public static string Encode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        /// <summary>Converts a Base64URL encoded string to a byte array</summary>
        /// <param name="encoded">The Base64Url encoded string</param>
        /// <returns>The byte array represented by the Base64URL encoded string</returns>
        public static byte[] Decode(string encoded)
        {
            encoded = encoded.Replace('-', '+').Replace('_', '/');
            encoded = FixPadding(encoded);
            return Convert.FromBase64String(encoded);
        }

        /// <summary>Adds missing padding to a Base64 encoded string.</summary>
        /// <param name="unpadded">The unpadded input string.</param>
        /// <returns>The padded string</returns>
        private static string FixPadding(string unpadded)
        {
            var count = 3 - ((unpadded.Length + 3) % 4);
            return unpadded + new string('=', count);
        }
    }
}
