using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;

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

        // PI returns the same transaction_id across detail.transaction_id and every multi_challenge[i].transaction_id
        // within one response, so TransactionID covers OTP/push/webauthn/passkey-registration alike.
        // PasskeyTransactionID is the genuinely separate one: it comes from detail.passkey.transaction_id
        // and only appears in the /validate/initialize response that starts a usernameless passkey login.
        public string PasskeyTransactionID { get; set; } = "";
        public bool EnrollmentOptional { get; set; } = false;

        private PIResponse() { }

        public List<string> TriggeredTokenTypes()
        {
            return Challenges.Select(challenge => challenge.Type).Distinct().ToList();
        }

        // Returns "" (not null) when no pollable push challenge is present, matching the rest of PIResponse's
        // string defaults. Only poll-mode push counts: a code_to_phone push is type=push but client_mode=interactive
        // (the user types the code shown on the phone) and can never be answered by polling, so it must not surface
        // the "Push" poll option.
        public string PushMessage()
        {
            foreach (PIChallenge c in Challenges)
            {
                if (c.Type == PITokenType.Push && c.ClientMode == PIClientMode.Poll)
                {
                    return c.Message;
                }
            }
            return "";
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
                // Take the first sign request as the template and replace its allowCredentials
                // with the union of allowCredentials across every triggered WebAuthn device.
                List<JObject> parsed = webAuthnSignRequests.Select(JObject.Parse).ToList();
                JArray merged = new JArray();
                foreach (JObject obj in parsed)
                {
                    if (obj["allowCredentials"] is JArray creds)
                    {
                        foreach (JToken cred in creds) merged.Add(cred);
                    }
                }

                JObject template = parsed[0];
                template["allowCredentials"] = merged;
                return template.ToString();
            }
        }

        public List<string> WebAuthnSignRequests()
        {
            List<string> ret = new List<string>();
            foreach (PIChallenge challenge in Challenges)
            {
                if (challenge.Type == PITokenType.WebAuthn)
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
                        string authValue = (string)authentication;
                        if (Enum.TryParse(authValue, ignoreCase: true, out PIAuthenticationStatus authStatus))
                        {
                            ret.AuthenticationStatus = authStatus;
                        }
                        else
                        {
                            privacyIDEA?.Error($"Unknown authentication status: {authValue}");
                        }
                    }

                    if (result["error"] is JObject error)
                    {
                        if (error["code"] is JToken code)
                        {
                            ret.ErrorCode = (int)code;
                        }
                        if (error["message"] is JToken message)
                        {
                            ret.ErrorMessage = (string)message;
                        }
                    }
                }

                if (jobj["detail"] is JObject detail)
                {
                    ret.TransactionID = (string)detail["transaction_id"];
                    ret.Message = (string)detail["message"];
                    ret.Type = (string)detail["type"];
                    ret.Serial = (string)detail["serial"];

                    if (detail["username"] is JToken username)
                    {
                        ret.Username = (string)username;
                    }

                    if (detail["enroll_via_multichallenge_optional"] is JToken evmcOptional
                        && evmcOptional.Type == JTokenType.Boolean)
                    {
                        ret.EnrollmentOptional = (bool)evmcOptional;
                    }

                    // preferred_client_mode is PI >=3.8; translate aliased values to our internal mode strings.
                    if (detail["preferred_client_mode"] is JToken pcm)
                    {
                        string prefClientMode = (string)pcm;
                        if (prefClientMode == PIClientMode.Interactive)
                        {
                            ret.PreferredClientMode = PITokenType.Otp;
                        }
                        else if (prefClientMode == PIClientMode.Poll)
                        {
                            ret.PreferredClientMode = PITokenType.Push;
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

                            if (type == PITokenType.WebAuthn)
                            {
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
                                    }
                                }
                                ret.Challenges.Add(tmp);
                            }
                            else
                            {
                                ret.Challenges.Add(new PIChallenge
                                {
                                    Message = message,
                                    Serial = serial,
                                    TransactionID = transactionid,
                                    Type = type,
                                    ClientMode = clientMode,
                                    Image = image
                                });
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
