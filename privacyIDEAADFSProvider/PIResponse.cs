using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;

namespace PrivacyIDEASDK
{
    public class PIResponse
    {
        public string TransactionID { get; set; } = "";
        public string Message { get; set; } = "";
        public string ErrorMessage { get; set; } = "";
        public string Type { get; set; } = "";
        public string Serial { get; set; } = "";
        public int ErrorCode { get; set; } = 0;
        public bool Status { get; set; } = false;
        public bool Value { get; set; } = false;

        public string Raw { get; set; } = "";
        public List<PIChallenge> Challenges { get; set; } = new List<PIChallenge>();
        private PIResponse() { }

        public List<string> TriggeredTokenTypes()
        {
            return Challenges.Select(challenge => challenge.Type).Distinct().ToList();
        }

        public string PushMessage()
        {
            return Challenges.First(challenge => challenge.Type == "push").Message;
        }

        public string MergedSignRequest()
        {
            List<string> webAuthnSignRequests = WebAuthnSignRequests();

            if (webAuthnSignRequests.Count < 1)
            {
                return "";
            }
            else if (webAuthnSignRequests.Count == 1)
            {
                return webAuthnSignRequests[0];
            }
            else
            {
                // Extract allowCredentials from every WebAuthn sign request and store in JArray list.
                List<JArray> extracted = new List<JArray>();
                foreach (string signRequest in webAuthnSignRequests)
                {
                    JObject jobj = JObject.Parse(signRequest);
                    JArray jarray = jobj["allowCredentials"] as JArray;

                    extracted.Add(jarray);
                }
                // Get WebAuthn sign request as JSON object
                JObject webAuthnSignRequest = JObject.Parse(webAuthnSignRequests[0]);

                // Set extracted allowCredentials section from every triggered WebAuthn device into one JSON array.
                JArray allowCredentials = new JArray();

                foreach (var x in extracted)
                {
                    foreach (var item in x)
                    {
                        allowCredentials.Add(item);
                    }
                };

                // Save extracted info in WebAuthn Sign Request
                webAuthnSignRequest.Remove("allowCredentials");
                webAuthnSignRequest.Add("allowCredentials", allowCredentials);

                return webAuthnSignRequest.ToString();
            }
        }

        public List<string> WebAuthnSignRequests()
        {
            List<string> ret = new List<string>();
            foreach (PIChallenge challenge in Challenges)
            {
                if (challenge.Type == "webauthn")
                {
                    string temp = (challenge as PIWebAuthnSignRequest).WebAuthnSignRequest;
                    ret.Add(temp);
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
                    ret.TransactionID = (string)detail["transaction_id"];
                    ret.Message = (string)detail["message"];
                    ret.Type = (string)detail["type"];
                    ret.Serial = (string)detail["serial"];

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

                                if (attr.Type != JTokenType.Null)
                                {
                                    var signRequest = attr["webAuthnSignRequest"];
                                    if (signRequest != null)
                                    {
                                        tmp.WebAuthnSignRequest = signRequest.ToString(Formatting.None); // todo System.InvalidOperationException: Cannot access child value on Newtonsoft.Json.Linq.JValue.
                                        tmp.WebAuthnSignRequest.Replace("\n", "");
                                    }
                                }

                                tmp.Message = message;
                                tmp.Serial = serial;
                                tmp.TransactionID = transactionid;
                                tmp.Type = type;
                                ret.Challenges.Add(tmp);
                            }
                            else
                            {
                                PIChallenge tmp = new PIChallenge();
                                tmp.Message = message;
                                tmp.Serial = serial;
                                tmp.TransactionID = transactionid;
                                tmp.Type = type;
                                ret.Challenges.Add(tmp);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                if (privacyIDEA != null)
                {
                    privacyIDEA.Error(ex);
                }
                return null;
            }
            return ret;
        }
    }
}
