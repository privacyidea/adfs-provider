using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using static PrivacyIDEAADFSProvider.PrivacyIDEA_Client.PIConstants;

namespace PrivacyIDEAADFSProvider.PrivacyIDEA_Client
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
        public bool IsEnrollmentViaMultichallenge { get; set; } = false;
        public bool IsEnrollmentViaMultichallengeOptional { get; set; } = false;

        private PIResponse() { }

        public List<string> TriggeredTokenTypes()
        {
            return Challenges.Select(challenge => challenge.Type).Distinct().ToList();
        }

        public string PushMessage()
        {
            foreach (PIChallenge c in Challenges)
            {
                if (c.Type == TOKEN_TYPE_PUSH)
                {
                    return c.Message;
                }
            }
            return null;
        }

        public bool IsAuthenticationSuccessful()
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
                    JArray jarray = jobj[ALLOW_CREDENTIALS] as JArray;

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
                webAuthnSignRequest.Remove(ALLOW_CREDENTIALS);
                webAuthnSignRequest.Add(ALLOW_CREDENTIALS, allowCredentials);

                return webAuthnSignRequest.ToString();
            }
        }

        public List<string> WebAuthnSignRequests()
        {
            List<string> ret = new List<string>();
            foreach (PIChallenge challenge in Challenges)
            {
                if (challenge.Type == TOKEN_TYPE_WEBAUTHN)
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

                if (jobj.ContainsKey(RESULT) && jobj[RESULT] is JToken result)
                {
                    if (result[STATUS] is JToken status)
                    {
                        ret.Status = (bool)status;
                    }

                    if (result[VALUE] is JToken value)
                    {
                        ret.Value = (bool)value;
                    }

                    if (result[AUTHENTICATION] is JToken authentication)
                    {
                        if (Enum.TryParse((string)authentication, out PIAuthenticationStatus authStatus))
                        {
                            ret.AuthenticationStatus = authStatus;
                        }
                        else
                        {
                            privacyIDEA?.Error($"Unknown authentication status: {authentication[STATUS]}");
                        }
                    }

                    if (result.Contains(ERROR))
                    {
                        JToken error = result[ERROR];
                        if (error.Contains(CODE))
                        {
                            ret.ErrorCode = (int)error[CODE];
                        }
                        if (error.Contains(MESSAGE))
                        {
                            ret.ErrorMessage = (string)error[MESSAGE];
                        }
                    }
                }

                if (jobj.ContainsKey(DETAIL) && jobj[DETAIL] is JToken detail)
                {
                    ret.TransactionID = (string)detail[TRANSACTION_ID];
                    ret.Message = (string)detail[MESSAGE];
                    ret.Type = (string)detail[TYPE];
                    ret.Serial = (string)detail[SERIAL];

                    if (detail[USERNAME] is JToken username)
                    {
                        ret.Username = (string)username;
                    }
                    if (detail[ENROLLMENT_VIA_MULTICHALLENGE] is JToken enrollmentViaMultichallenge)
                    {
                        ret.IsEnrollmentViaMultichallenge = (bool)enrollmentViaMultichallenge;

                    }
                    if (detail[ENROLLMENT_VIA_MULTICHALLENGE_OPTIONAL] is JToken enrollmentViaMultichallengeOptional)
                    {
                        ret.IsEnrollmentViaMultichallengeOptional = (bool)enrollmentViaMultichallengeOptional;
                    }

                    // Check if the response contains "preferred_client_mode" (PI >=3.8). If so, translate the values that use other names
                    if (detail[PREFERRED_CLIENT_MODE] is JToken pcm)
                    {
                        string prefClientMode = (string)pcm;
                        if (prefClientMode == INTERACTIVE)
                        {
                            ret.PreferredClientMode = OTP;
                        }
                        else if (prefClientMode == POLL)
                        {
                            ret.PreferredClientMode = TOKEN_TYPE_PUSH;
                        }
                        else
                        {
                            ret.PreferredClientMode = prefClientMode;
                        }
                    }
                    if (detail[PASSKEY] is JObject passkey)
                    {
                        ret.PasskeyChallenge = passkey.ToString(Formatting.None);
                        if (passkey[TRANSACTION_ID] is JToken txid)
                        {
                            ret.PasskeyTransactionID = (string)txid;
                        }
                    }

                    if (detail[MULTI_CHALLENGE] is JArray multiChallenge)
                    {
                        foreach (JToken challenge in multiChallenge.Children())
                        {
                            string message = (string)challenge[MESSAGE];
                            string transactionid = (string)challenge[TRANSACTION_ID];
                            string type = (string)challenge[TYPE];
                            string serial = (string)challenge[SERIAL];
                            string clientMode = (string)challenge[CLIENT_MODE];
                            string image = "";

                            if (challenge[IMAGE] != null && challenge[IMAGE].Type != JTokenType.Null
                                && !string.IsNullOrEmpty((string)challenge[IMAGE]))
                            {
                                image = (string)challenge[IMAGE];
                            }

                            if (challenge[PASSKEY_REGISTRATION] is JToken passkeyRegistration)
                            {
                                ret.PasskeyRegistration = passkeyRegistration.ToString(Formatting.None);
                            }
                            if (challenge[LINK] is JToken link)
                            {
                                ret.EnrollmentLink = (string)link;
                            }

                            if (type == TOKEN_TYPE_WEBAUTHN)
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

                                if (challenge[ATTRIBUTES] is JToken attr && attr.Type != JTokenType.Null)
                                {
                                    if (attr[WEBAUTHNSIGNREQUEST] is JToken signRequest)
                                    {
                                        tmp.WebAuthnSignRequest = signRequest.ToString(Formatting.None);
                                        tmp.WebAuthnSignRequest.Replace("\n", "");
                                    }
                                }
                                ret.Challenges.Add(tmp);
                            }
                            else
                            {
                                if (type == TOKEN_TYPE_PUSH)
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
