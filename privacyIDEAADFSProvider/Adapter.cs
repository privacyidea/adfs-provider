using Microsoft.IdentityServer.Web.Authentication.External;
using PrivacyIDEASDK;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Linq;
using System.Net;
using Claim = System.Security.Claims.Claim;

namespace privacyIDEAADFSProvider
{
    public class Adapter : IAuthenticationAdapter, IPILog
    {
        private readonly string version = typeof(Adapter).Assembly.GetName().Version.ToString();

        private bool _UseUPN = false;
        private bool _TriggerChallenge = false;
        private bool _SendEmptyPassword = false;
        private bool _EnrollmentEnabled = false;
        private string _OtpHint = "";
        private string _PreferredTokenType = "otp";
        private List<string> _ForwardHeaders = new List<string>();
        private PrivacyIDEA _PrivacyIDEA;
        private bool _DebugLog = false;

        public IAuthenticationAdapterMetadata Metadata
        {
            get
            {
                AdapterMetadata meta = new AdapterMetadata();
                meta.AdapterMetadataInit();
                meta.AdapterVersion = version;
                return meta;
            }
        }

        /// <summary>
        /// Initiates a new authentication process and returns our form to the AD FS system.
        /// </summary>
        /// <param name="identityClaim">Claim information from the ADFS</param>
        /// <param name="request">The http request</param>
        /// <param name="authContext">The context for the authentication</param>
        /// <returns>new instance of IAdapterPresentationForm</returns>
        public IAdapterPresentation BeginAuthentication(Claim identityClaim, HttpListenerRequest request,
            IAuthenticationContext authContext)
        {
            Log("BeginAuthentication: identityClaim: " + identityClaim.Value);
            string username, domain, upn = "";
            // separates the username from the domain
            string[] tmp = identityClaim.Value.Split('\\');

            if (tmp.Length > 1)
            {
                username = tmp[1];
                domain = tmp[0];
                if (_UseUPN)
                {
                    // get UPN from sAMAccountName
                    Log("Getting UPN for user:" + username + " and domain: " + domain + "...");
                    PrincipalContext ctx = new PrincipalContext(ContextType.Domain, domain);
                    UserPrincipal user = UserPrincipal.FindByIdentity(ctx, username);
                    upn = user.UserPrincipalName;
                    Log("Found UPN: " + upn);
                }
                else
                {
                    upn = "not used";
                }
            }
            else
            {
                username = tmp[0];
                upn = tmp[0];
                domain = "";
            }

            Log("UPN value: " + upn + ", Domain value: " + domain);

            // use upn or sam as loginname attribute
            if (_UseUPN)
            {
                username = upn;
            }

            // Prepare the form
            var form = new AdapterPresentationForm();
            form.OtpHint = _OtpHint;

            // Collect headers to forward with next PI request
            List<KeyValuePair<string, string>> headers = GetHeadersToForward(request);

            // trigger challenges with service account or empty pass if configured
            PIResponse response = null;
            if (_PrivacyIDEA != null)
            {
                if (_TriggerChallenge)
                {
                    response = _PrivacyIDEA.TriggerChallenges(username, domain, headers);
                }
                else if (_SendEmptyPassword)
                {
                    response = _PrivacyIDEA.ValidateCheck(username, "", domain: domain, headers: headers);
                }
            }
            else
            {
                Error("privacyIDEA not initialized!");
            }

            // Evaluate the response for triggered token and prepare the form accordingly
            if (response != null)
            {
                if (response.Challenges.Count > 0)
                {
                    form = ExtractChallengeDataToForm(response, form, authContext);
                }
                else if (response.Value)
                {
                    // Success in step 1, carry this over to the second step so that step will be skipped
                    authContext.Data.Add("authSuccess", "1");
                    form.AutoSubmit = "1";
                }
                else
                {
                    if (!string.IsNullOrEmpty(response.ErrorMessage))
                    {
                        Error("Error in first step: " + response.ErrorMessage);
                        form.ErrorMessage = response.ErrorMessage;
                    }
                    else
                    {
                        Error("Sent something in first step and got failure without message");
                    }
                }
            }

            if (String.IsNullOrEmpty(form.Mode))
            {
                form.Mode = "otp";
            }
            authContext.Data.Add("userid", username);
            authContext.Data.Add("domain", domain);

            // Perform optional user enrollment
            // If a challenge was triggered previously, checking if the user has a token is skipped
            if (_EnrollmentEnabled &&
                (response != null && string.IsNullOrEmpty(response.TransactionID) || (response == null)) &&
                !_PrivacyIDEA.UserHasToken(username, domain))
            {
                PIEnrollResponse res = _PrivacyIDEA.TokenInit(username, domain);
                form.EnrollmentUrl = res.TotpUrl;
                form.EnrollmentImg = res.Base64TotpImage;
            }

            return form;
        }

        /// <summary>
        /// Called when our form is submitted.
        /// </summary>
        /// <param name="authContext"></param>
        /// <param name="proofData"></param>
        /// <param name="request"></param>
        /// <param name="outgoingClaims"></param>
        /// <returns></returns>
        public IAdapterPresentation TryEndAuthentication(IAuthenticationContext authContext, IProofData proofData,
            HttpListenerRequest request, out Claim[] outgoingClaims)
        {
            Log("TryEndAuthentication");
            // Early exit if step 2 can be skipped
            if (authContext != null)
            {
                if ((string)GetFromDict(authContext.Data, "authSuccess", "") == "1")
                {
                    outgoingClaims = Claims();
                    return null;
                }
            }
            outgoingClaims = new Claim[0];

            if (proofData == null || proofData.Properties == null)
            {
                throw new ExternalAuthenticationException("Error - ProofData is empty", authContext);
            }

            if (_PrivacyIDEA == null)
            {
                Error("PrivacyIDEA is not initialized!");
                throw new ExternalAuthenticationException("PrivacyIDEA is not initialized!", authContext);
            }

            Dictionary<string, object> contextDict = authContext.Data;
            Dictionary<string, object> proofDict = proofData.Properties;
            Log("ProofData: " + string.Join(", ", proofData.Properties));
            Log("AuthContext: " + string.Join(", ", authContext.Data));

            // Prepare form to return, fill with values from proofData
            var form = new AdapterPresentationForm();
            string otp = (string)GetFromDict(proofDict, "otp");
            string mode = (string)GetFromDict(proofDict, "mode");
            string modeChanged = (string)GetFromDict(proofDict, "modeChanged");
            string pushAvailable = (string)GetFromDict(proofDict, "pushAvailable");
            string message = (string)GetFromDict(proofDict, "message");
            string webAuthnSignRequest = (string)GetFromDict(proofDict, "webAuthnSignRequest");
            string domain = (string)GetFromDict(proofDict, "domain");

            string strAuthCounter = (string)GetFromDict(proofDict, "authCounter", "0");
            if (!string.IsNullOrEmpty(strAuthCounter))
            {
                form.AuthCounter = (int.Parse(strAuthCounter) + 1).ToString();
            }

            form.Message = message;
            form.Mode = mode;
            form.PushAvailable = pushAvailable;

            if (!string.IsNullOrEmpty(webAuthnSignRequest))
            {
                form.WebAuthnSignRequest = webAuthnSignRequest;
            }

            string transactionid = (string)GetFromDict(contextDict, "transactionid");
            string user = (string)GetFromDict(contextDict, "userid");

            if (modeChanged == "1")
            {
                return form;
            }

            // Collect headers to forward with next PI request
            List<KeyValuePair<string, string>> headers = GetHeadersToForward(request);

            // Do the authentication according to the mode we are in
            PIResponse response = null;
            if (mode == "push")
            {
                if (_PrivacyIDEA.PollTransaction(transactionid))
                {
                    // Push confirmed, finish the authentication via /validate/check using an empty otp
                    // https://privacyidea.readthedocs.io/en/latest/tokens/authentication_modes.html#outofband-mode
                    response = _PrivacyIDEA.ValidateCheck(user, "", transactionid, domain, headers);
                }
                else
                {
                    // Else push not confirmed yet
                    form.ErrorMessage = "Authenication not confirmed yet!";
                }
            }
            else if (mode == "webauthn")
            {
                string origin = (string)GetFromDict(proofDict, "origin");
                string webauthnresponse = (string)GetFromDict(proofDict, "webAuthnSignResponse");

                if (string.IsNullOrEmpty(origin) || string.IsNullOrEmpty(webauthnresponse))
                {
                    Error("Incomplete data for WebAuthn authentication: WebAuthnSignResponse or Origin is missing!");
                    form.ErrorMessage = "Could not complete WebAuthn authentication. Try again or use another token type.";
                }
                else
                {
                    response = _PrivacyIDEA.ValidateCheckWebAuthn(user, transactionid, webauthnresponse, origin, domain, headers);
                }
            }
            else
            {
                // Mode == OTP
                response = _PrivacyIDEA.ValidateCheck(user, otp, transactionid, domain, headers);
            }

            // If we get this far, the login data provided was wrong, an error occured or another challenge was triggered.
            bool newChallenge = false;
            if (response != null)
            {
                if (response.Challenges.Count > 0)
                {
                    newChallenge = true;
                    form = ExtractChallengeDataToForm(response, form, authContext);
                }
                else if (response.Value)
                {
                    outgoingClaims = Claims();
                    return null;
                }
                else
                {
                    Log("Response value was false!");
                    // Set the error message from the response or a default
                    form.ErrorMessage = (!string.IsNullOrEmpty(response.ErrorMessage)) ? response.ErrorMessage + " (" + response.ErrorCode + ")"
                        : "Wrong OTP value!";
                }
            }
            else
            {
                // In case of unconfirmed push response will be null too. Therefore, set the message only if there is none yet.
                if (string.IsNullOrEmpty(form.ErrorMessage))
                {
                    form.ErrorMessage = "The authentication server could not be reached.";
                    Error("Reponse from server was null!");
                }
            }

            // Set a generic error if none was set yet and no new challenge was triggered
            if (string.IsNullOrEmpty(form.ErrorMessage) && !newChallenge)
            {
                form.ErrorMessage = "An error occured.";
            }
            // Return form with error or new challenge
            return form;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="identityClaim"></param>
        /// <param name="authContext"></param>
        /// <returns></returns>
        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext authContext)
        {
            // Available for all users
            return true;
        }

        /// <summary>
        /// Called when the provider is loaded by the AD FS service. The config will be loaded in this function.
        /// </summary>
        /// <param name="configData"></param>
        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        {
            Log("OnAuthenticationPipelineLoad: Provider Version " + version);

            var registryReader = new RegistryReader(Log);

            // Read logging entry first to be able to log the reading of the rest if needed
            _DebugLog = registryReader.Read("debug_log") == "1";

            // Read the other defined keys into a dict
            List<string> configKeys = new List<string>(new string[]
            { "use_upn", "url", "disable_ssl", "tls_version", "enable_enrollment", "service_user", "service_pass", "service_realm",
                "realm", "trigger_challenges", "send_empty_pass", "otp_hint", "forward_headers", "preferred_token_type" });

            var configDict = new Dictionary<string, string>();
            configKeys.ForEach(key =>
            {
                string value = registryReader.Read(key);
                Log("Read value '" + value + "' for key '" + key + "'");
                configDict[key] = value;
            });

            string url = GetFromDict(configDict, "url");
            if (string.IsNullOrEmpty(url))
            {
                Error("No server URL configured. Can not initialize privacyIDEA without a server URL.");
                throw new Exception("No server URL configured. Can not initialize privacyIDEA without a server URL.");
            }

            // Note: the config asks if ssl verify should be disabled, while the constructor parameter indicates if ssl verify should be enabled!
            bool shouldUseSSL = GetFromDict(configDict, "disable_ssl", "0") != "1";

            // Check if TLS version should be overwritten
            string tlsVersion = GetFromDict(configDict, "tls_version", "");
            if (!string.IsNullOrEmpty(tlsVersion))
            {
                if (tlsVersion.Contains("tls11"))
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11;
                    Log("Setting TLS version to 1.1");
                }
                else if (tlsVersion.Contains("tls12"))
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                    Log("Setting TLS version to 1.2");
                }
                else if (tlsVersion.Contains("tls13"))
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls13;
                    Log("Setting TLS version to 1.3");
                }
                else
                {
                    Log($"Given TLS version ({tlsVersion}) has wrong format! Use default version from system.");
                }
            }

            // Check if headers to forward are set
            string headersToForward = GetFromDict(configDict, "forward_headers", "");
            headersToForward.Replace(" ", "");
            if (!string.IsNullOrEmpty(headersToForward))
            {
                _ForwardHeaders = headersToForward.Split(',').ToList();
            }

            _PrivacyIDEA = new PrivacyIDEA(url, "PrivacyIDEA-ADFS", shouldUseSSL)
            {
                Logger = this
            };

            string serviceUser = GetFromDict(configDict, "service_user", "");
            string servicePass = GetFromDict(configDict, "service_pass", "");

            if (!string.IsNullOrEmpty(serviceUser) && !string.IsNullOrEmpty(servicePass))
            {
                _PrivacyIDEA.SetServiceAccount(serviceUser, servicePass, GetFromDict(configDict, "service_realm"));
            }
            _OtpHint = GetFromDict(configDict, "otp_hint", "");
            _PreferredTokenType = GetFromDict(configDict, "preferred_token_type", "otp");
            _UseUPN = GetFromDict(configDict, "use_upn", "0") == "1";

            _EnrollmentEnabled = GetFromDict(configDict, "enable_enrollment", "0") == "1";

            _TriggerChallenge = GetFromDict(configDict, "trigger_challenges", "0") == "1";
            if (!_TriggerChallenge)
            {
                // Only if triggerChallenge is disabled, sendEmptyPassword COULD be set
                _SendEmptyPassword = GetFromDict(configDict, "send_empty_pass", "0") == "1";
            }
            _PrivacyIDEA.Realm = GetFromDict(configDict, "realm", "");
            var realmmap = registryReader.GetRealmMapping();
            Log("realmmapping: " + string.Join(" , ", realmmap));
            _PrivacyIDEA.RealmMap = realmmap;
        }

        /// <summary>
        /// cleanup function
        /// </summary>
        public void OnAuthenticationPipelineUnload()
        {
            _PrivacyIDEA.Dispose();
        }

        /// <summary> 
        /// Called on error and represents the authform with a error message
        /// </summary>
        /// <param name="request">the http request object</param>
        /// <param name="ex">exception message</param>
        /// <returns>new instance of IAdapterPresentationForm derived class</returns>
        public IAdapterPresentation OnError(HttpListenerRequest request, ExternalAuthenticationException ex)
        {
            Log("OnError, ExternalAuthenticationException: " + ex.Message);
            var form = new AdapterPresentationForm();
            form.ErrorMessage = ex.Message;
            return form;
        }

        private AdapterPresentationForm ExtractChallengeDataToForm(PIResponse response, AdapterPresentationForm form, IAuthenticationContext authContext)
        {
            // explicitly overwrite here. If another challenge was triggered, it will have a different transaction_id.
            authContext.Data["transactionid"] = response.TransactionID;

            form.Message = response.Message;

            if (response.TriggeredTokenTypes().Contains("push"))
            {
                form.PushAvailable = "1";
                form.PushMessage = response.PushMessage();
            }

            if (response.TriggeredTokenTypes().Contains("webauthn"))
            {
                string webAuthnSignRequest = response.MergedSignRequest();
                form.WebAuthnSignRequest = webAuthnSignRequest;
                form.Mode = "webauthn";
            }

            if (response.TriggeredTokenTypes().Contains(_PreferredTokenType))
            {
                form.Mode = _PreferredTokenType;
            }

            if (form.Mode == "webauthn" && (form.WebAuthnSignRequest == null || string.IsNullOrEmpty(form.WebAuthnSignRequest)))
            {
                form.Mode = "otp";
            }

            return form;
        }

        /// <summary>
        /// Check if wanted header exists in requestHeaders collection.
        /// </summary>
        /// <param name="request">the http request object</param>
        /// <returns>KeyValuePair list of headers and their values or empty KeyValuePair list </string></returns>
        private List<KeyValuePair<string, string>> GetHeadersToForward(HttpListenerRequest request)
        {
            NameValueCollection requestHeaders = request.Headers;
            List<KeyValuePair<string, string>> headersToForward = new List<KeyValuePair<string, string>>();

            foreach (string header in _ForwardHeaders)
            {
                string[] headerValues = requestHeaders.GetValues(header);

                if (headerValues != null)
                {
                    string tmp = string.Join(",", headerValues);
                    headersToForward.Add(new KeyValuePair<string, string>(header, tmp));
                }
                else
                {
                    Log("No values for header " + header + " found.");
                }
            }
            return headersToForward;
        }

        /// <summary>
        /// Return the required authentication method claim, indicating the particular authentication method used.
        /// </summary>
        /// <returns>Claims for this authentication method</returns>
        private Claim[] Claims()
        {
            return new[] {
                     new Claim(
                            "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod",
                            "http://schemas.microsoft.com/ws/2012/12/authmethod/otp")
                        };
        }

        private T GetFromDict<T>(Dictionary<string, T> dict, string key, T defaultValue = default(T))
        {
            if (dict.ContainsKey(key))
            {
                return (T)dict[key];
            }
            Log("Key '" + key + "' could not be found in dict, returning default value '" + defaultValue + "'.");
            return defaultValue;
        }

        public void Log(string message)
        {
            string formatted = "[" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH\\:mm\\:ss") + "] " + message;
            LogImpl(formatted);
        }

        public void Error(string message)
        {
            string formatted = "[" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH\\:mm\\:ss") + "] " + message;
            // write error to both
            EventError(formatted);
            LogImpl(formatted);
        }

        public void Error(Exception exception)
        {
            string message = exception.Message + ":\n" + exception.ToString();
            string formatted = "[" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH\\:mm\\:ss") + "] " + message;
            // Write error to both
            EventError(formatted);
            LogImpl(formatted);
        }

        private void EventError(string message)
        {
            using (EventLog eventLog = new EventLog("AD FS/Admin"))
            {
                eventLog.Source = "privacyIDEAProvider";
                eventLog.WriteEntry(message, EventLogEntryType.Error, 9901, 0);
            }
        }

        public async void LogImpl(string msg)
        {
            if (_DebugLog)
            {
                try
                {
                    using (StreamWriter streamWriter = new StreamWriter("C:\\PrivacyIDEA-ADFS log.txt", append: true))
                    {
                        await streamWriter.WriteLineAsync(msg);
                    }
                }
                catch (Exception e)
                {
                    EventError("Error while trying to write to logfile: " + e.Message);
                }
            }
        }
    }
}
