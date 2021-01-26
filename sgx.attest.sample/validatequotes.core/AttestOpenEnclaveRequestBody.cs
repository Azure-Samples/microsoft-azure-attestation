namespace validatequotes
{
    public class AttestOpenEnclaveRequestBody
    {
        public class AttestedData
        {
            public string Data { get; set; }
            public string DataType { get; set; }
        }

        public AttestOpenEnclaveRequestBody(EnclaveInfo enclaveInfo)
        {
            Report = HexHelper.ConvertHexToBase64Url(enclaveInfo.QuoteHex);
            RuntimeData = new AttestedData()
            {
                Data = HexHelper.ConvertHexToBase64Url(enclaveInfo.EnclaveHeldDataHex),
                DataType = "Binary"
            };
        }

        public string Report { get; set; }
        public AttestedData RuntimeData { get; set; }
        public AttestedData InittimeData { get; set; }
        public string DraftPolicyForAttestation { get; set; }
    }
}
