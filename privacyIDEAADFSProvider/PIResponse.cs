using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace PrivacyIDEASDK
{
    public class PIResponse
    {
        public string TransactionID { get; set; } = "";
        public string Message { get; set; } = "";
        public string ErrorMessage { get; set; } = "";
        public string Type { get; set; } = "";
        public int ErrorCode { get; set; } = 0;
        public bool Status { get; set; } = false;
        public bool Value { get; set; } = false;

        public string Raw { get; set; } = "";
        public List<PIChallenge> MultiChallenge { get; set; } = new List<PIChallenge>();
        private PIResponse() { }

        public List<string> TriggeredTokenTypes()
        {
            return MultiChallenge.Select(challenge => challenge.Type).Distinct().ToList();
        }

        public string PushMessage()
        {
            return MultiChallenge.First(challenge => challenge.Type == "push").Message;
        }

        public string WebAuthnSignRequest()
        {
            // Currently get only the first one that was triggered
            string ret = "";
            foreach (PIChallenge challenge in MultiChallenge)
            {
                if (challenge.Type == "webauthn")
                {
                    ret = (challenge as PIWebAuthnSignRequest).WebAuthnSignRequest;
                    break;
                }
            }

            return ret;
        }

        public static PIResponse FromJSON(string json, PrivacyIDEA privacyIDEA)
        {
            if (string.IsNullOrEmpty(json))
            {
                if (privacyIDEA != null)
                {
                    privacyIDEA.Error("Json to parse is empty!");
                }
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

                    JArray multiChallenge = detail["multi_challenge"] as JArray;
                    if (multiChallenge != null)
                    {
                        foreach (JToken element in multiChallenge.Children())
                        {
                            string message = (string)element["message"];
                            string transactionid = (string)element["transaction_id"];
                            string type = (string)element["type"];
                            string serial = (string)element["serial"];
                            if (type == "webauthn")
                            {
                                PIWebAuthnSignRequest tmp = new PIWebAuthnSignRequest();
                                JToken attr = element["attributes"];
                                tmp.WebAuthnSignRequest = attr["webAuthnSignRequest"].ToString(Formatting.None);
                                tmp.WebAuthnSignRequest.Replace("\n", "");
                                tmp.Message = message;
                                tmp.Serial = serial;
                                tmp.TransactionID = transactionid;
                                tmp.Type = type;
                                ret.MultiChallenge.Add(tmp);
                            }
                            else
                            {
                                PIChallenge tmp = new PIChallenge();
                                tmp.Message = message;
                                tmp.Serial = serial;
                                tmp.TransactionID = transactionid;
                                tmp.Type = type;
                                ret.MultiChallenge.Add(tmp);
                            }
                        }
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
