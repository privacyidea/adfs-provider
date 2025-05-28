using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
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
        public PIAuthenticationStatus AuthenticationStatus { get; set; } = PIAuthenticationStatus.UNDEFINED;
        public string PreferredClientMode { get; set; } = "";

        public string Raw { get; set; } = "";
        public List<PIChallenge> Challenges { get; set; } = new List<PIChallenge>();
        public string PasskeyChallenge { get; set; } = "";
        public string Username { get; set; } = "";
        public string EnrollmentLink { get; set; } = "";
        public string PasskeyRegistration { get; set; } = "";

        public string WebAuthnTransactionID { get; set; } = "";
        public string OTPTransactionID { get; set; } = "";
        public string PushTransactionID { get; set; } = "";
        public string PasskeyTransactionID { get; set; } = "";

        private PIResponse() { }

        public List<string> TriggeredTokenTypes()
        {
            return Challenges.Select(challenge => challenge.Type).Distinct().ToList();
        }

        public string PushMessage()
        {
            foreach (PIChallenge c in Challenges)
            {
                if (c.Type == "push")
                {
                    return c.Message;
                }
            }
            return null;
        }

        public bool isAuthenticationSuccessful()
        {
            if (AuthenticationStatus != PIAuthenticationStatus.UNDEFINED)
            {
                return AuthenticationStatus == PIAuthenticationStatus.ACCEPT;
            }
            else
            {
                return Value && Challenges.Count == 0;
            }
        }

        public string MergedSignRequest()
        {
            List<string> webAuthnSignRequests = WebAuthnSignRequests();

            if (webAuthnSignRequests.Count < 1)
            {
                return null;
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
                }

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
                privacyIDEA?.Error("Json to parse is empty!");
                return null;
            }

            PIResponse ret = new PIResponse
            {
                Raw = json
            };
            try
            {
                JObject jobj = JObject.Parse(json);

                if (jobj.ContainsKey("result") && jobj["result"] is JToken result)
                {
                    if (result["status"] is JToken status)
                    {
                        ret.Status = (bool)status;
                    }

                    if (result["value"] is JToken value)
                    {
                        ret.Value = (bool)value;
                    }

                    if (result["authentication"] is JToken authentication)
                    {
                        if (Enum.TryParse((string)authentication, out PIAuthenticationStatus authStatus))
                        {
                            ret.AuthenticationStatus = authStatus;
                        }
                        else
                        {
                            privacyIDEA?.Error($"Unknown authentication status: {authentication["status"]}");
                        }
                    }

                    if (result.Contains("error"))
                    {
                        JToken error = result["error"];
                        if (error.Contains("code"))
                        {
                            ret.ErrorCode = (int)error["code"];
                        }
                        if (error.Contains("message"))
                        {
                            ret.ErrorMessage = (string)error["message"];
                        }
                    }
                }

                if (jobj.ContainsKey("detail") && jobj["detail"] is JToken detail)
                {
                    ret.TransactionID = (string)detail["transaction_id"];
                    ret.Message = (string)detail["message"];
                    ret.Type = (string)detail["type"];
                    ret.Serial = (string)detail["serial"];

                    if (detail["username"] is JToken username)
                    {
                        ret.Username = (string)username;
                    }

                    // Check if the response contains "preferred_client_mode" (PI >=3.8). If so, translate the values that use other names
                    if (detail["preferred_client_mode"] is JToken pcm)
                    {
                        string prefClientMode = (string)pcm;
                        if (prefClientMode == "interactive")
                        {
                            ret.PreferredClientMode = "otp";
                        }
                        else if (prefClientMode == "poll")
                        {
                            ret.PreferredClientMode = "push";
                        }
                        else
                        {
                            ret.PreferredClientMode = prefClientMode;
                        }
                    }
                    if (detail["passkey"] is JObject passkey)
                    {
                        ret.PasskeyChallenge = passkey.ToString(Formatting.None);
                        if (passkey["transaction_id"] is JToken txid)
                        {
                            ret.PasskeyTransactionID = (string)txid;
                        }
                    }

                    if (detail["multi_challenge"] is JArray multiChallenge)
                    {
                        foreach (JToken challenge in multiChallenge.Children())
                        {
                            string message = (string)challenge["message"];
                            string transactionid = (string)challenge["transaction_id"];
                            string type = (string)challenge["type"];
                            string serial = (string)challenge["serial"];
                            string clientMode = (string)challenge["client_mode"];
                            string image = "";

                            if (challenge["image"] != null && challenge["image"].Type != JTokenType.Null
                                && !string.IsNullOrEmpty((string)challenge["image"]))
                            {
                                image = (string)challenge["image"];
                            }

                            if (challenge["passkey_registration"] is JToken passkeyRegistration)
                            {
                                ret.PasskeyRegistration = passkeyRegistration.ToString(Formatting.None);
                            }
                            if (challenge["link"] is JToken link)
                            {
                                ret.EnrollmentLink = (string)link;
                            }

                            if (type == "webauthn")
                            {
                                ret.WebAuthnTransactionID = transactionid;
                                PIWebAuthnSignRequest tmp = new PIWebAuthnSignRequest
                                {
                                    Message = message,
                                    Serial = serial,
                                    TransactionID = transactionid,
                                    Type = type,
                                    ClientMode = clientMode,
                                    Image = image
                                };

                                if (challenge["attributes"] is JToken attr && attr.Type != JTokenType.Null)
                                {
                                    if (attr["webAuthnSignRequest"] is JToken signRequest)
                                    {
                                        tmp.WebAuthnSignRequest = signRequest.ToString(Formatting.None);
                                        tmp.WebAuthnSignRequest.Replace("\n", "");
                                    }
                                }
                                ret.Challenges.Add(tmp);
                            }
                            else
                            {
                                if (type == "push")
                                {
                                    ret.PushTransactionID = transactionid;
                                }
                                else
                                {
                                    ret.OTPTransactionID = transactionid;
                                }

                                PIChallenge tmp = new PIChallenge
                                {
                                    Message = message,
                                    Serial = serial,
                                    TransactionID = transactionid,
                                    Type = type,
                                    ClientMode = clientMode,
                                    Image = image
                                };
                                ret.Challenges.Add(tmp);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                privacyIDEA?.Error(ex);
                return null;
            }
            return ret;
        }
    }
}
