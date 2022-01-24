using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace PrivacyIDEASDK
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
                if (privacyIDEA != null)
                {
                    privacyIDEA.Error("Json to parse is empty!");
                }
                return null;
            }

            PIEnrollResponse ret = new PIEnrollResponse();
            ret.Raw = json;
            try
            {
                JObject jobj = JObject.Parse(json);
                JToken result = jobj["result"];
                if (result != null)
                {
                    ret.Status = (bool)result["status"];

                    JToken jVal = result["value"];
                    if (jVal != null)
                    {
                        ret.Value = (bool)jVal;
                    }

                    JToken error = result["error"];
                    if (error != null)
                    {
                        ret.ErrorCode = (int)error["code"];
                        ret.ErrorMessage = (string)error["message"];
                    }
                }

                JToken detail = jobj["detail"];
                if (detail != null && detail.Type != JTokenType.Null)
                {
                    
                    // ret.Type = (string)detail["type"];
                    ret.Serial = (string)detail["serial"];

                    JToken googleTotp = detail["googleurl"];
                    if (googleTotp != null && googleTotp.Type != JTokenType.Null)
                    {
                        ret.TotpUrl = (string)googleTotp["value"];
                        ret.Base64TotpImage = (string)googleTotp["img"];
                    }
                }
            }
            catch (JsonException je)
            {
                if (privacyIDEA != null)
                {
                    privacyIDEA.Error(je);
                }
                return null;
            }

            return ret;
        }

    }
}
