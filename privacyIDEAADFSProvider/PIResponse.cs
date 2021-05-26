using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SDKNS;

namespace SDK
{
    public class PIResponse
    {
        //string transactionID = "", message = "", errorMessage = "", type = "";

        public string TransactionID { get; set; } = "";
        public string Message { get; set; } = "";
        public string ErrorMessage { get; set; } = "";
        public string Type { get; set; } = "";
        public int ErrorCode { get; set; } = 0;
        public bool Status { get; set; } = false;
        public bool Value { get; set; } = false;

        public string Raw { get; set; } = "";
        public List<PIChallenge> MultiChallenge { get; set; } = new List<PIChallenge>(); 
        private PIResponse() {}

        public List<string> TriggeredTokenTypes()
        {
            return MultiChallenge.Select(challenge => challenge.Type).Distinct().ToList();
        }

        public string PushMessage()
        {
            return MultiChallenge.First(challenge => challenge.Type == "push").Message;
        }

        public static PIResponse FromJSON(string json, PrivacyIDEA privacyIDEA)
        {
            if (string.IsNullOrEmpty(json))
            {
                privacyIDEA.Error("Json to parse is empty!");
                return null;
            }

            PIResponse ret = new PIResponse();
            ret.Raw = json;
            try
            {
                JObject jobj = JObject.Parse(json);
                JToken result = jobj["result"];
                if (result != null)
                {
                    ret.Status = (bool)jobj["result"]["status"];
                    ret.Value = (bool)jobj["result"]["value"];

                    JToken error = result["error"];
                    if (error != null)
                    {
                        ret.ErrorCode = (int)error["code"];
                        ret.ErrorMessage = (string)error["message"];
                    }
                }
                JToken detail = jobj["detail"];
                if (detail != null)
                {
                    ret.TransactionID = (string)detail["transaction_id"];
                    ret.Message = (string)detail["message"];
                    ret.Type = (string)detail["type"];

                    JToken multiChallenge = detail["multi_challenge"];
                    if (multiChallenge!= null)
                    {
                        ret.MultiChallenge = multiChallenge.ToObject<List<PIChallenge>>();
                    }
                }

            }
            catch (JsonException je)
            {
                privacyIDEA.Error(je);
                return null;
            }

            return ret;
        }

    }
}
