using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using static PrivacyIDEAADFSProvider.PrivacyIDEA_Client.PIConstants;

namespace PrivacyIDEAADFSProvider.PrivacyIDEA_Client
{
    public class PIEnrollResponse
    {
        public string Raw { get; set; } = "";
        public string ErrorMessage { get; set; } = "";
        public int ErrorCode { get; set; } = 0;
        public bool Status { get; set; } = false;
        public bool Value { get; set; } = false;
        public string Serial { get; set; } = "";
        public string TotpUrl { get; set; } = "";
        public string Base64TotpImage { get; set; } = "";

        private PIEnrollResponse() { }

        public static PIEnrollResponse FromJSON(string json, PrivacyIDEA privacyIDEA)
        {
            if (string.IsNullOrEmpty(json))
            {
                privacyIDEA?.Error("Json to parse is empty!");
                return null;
            }

            PIEnrollResponse ret = new PIEnrollResponse
            {
                Raw = json
            };
            try
            {
                JObject jobj = JObject.Parse(json);
                JToken result = jobj[RESULT];
                if (result != null)
                {
                    ret.Status = (bool)result[STATUS];

                    JToken jVal = result[VALUE];
                    if (jVal != null)
                    {
                        ret.Value = (bool)jVal;
                    }

                    JToken error = result[ERROR];
                    if (error != null)
                    {
                        ret.ErrorCode = (int)error[CODE];
                        ret.ErrorMessage = (string)error[MESSAGE];
                    }
                }

                JToken detail = jobj[DETAIL];
                if (detail != null && detail.Type != JTokenType.Null)
                {
                    
                    // ret.Type = (string)detail["type"];
                    ret.Serial = (string)detail[SERIAL];

                    JToken googleTotp = detail[GOOGLEURL];
                    if (googleTotp != null && googleTotp.Type != JTokenType.Null)
                    {
                        ret.TotpUrl = (string)googleTotp[VALUE];
                        ret.Base64TotpImage = (string)googleTotp[IMAGE];
                    }
                }
            }
            catch (JsonException je)
            {
                privacyIDEA?.Error(je);
                return null;
            }

            return ret;
        }

    }
}
