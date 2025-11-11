using Microsoft.IdentityServer.Web.Authentication.External;
using Newtonsoft.Json;
using PrivacyIDEAADFSProvider;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Principal;
using Claim = System.Security.Claims.Claim;

namespace privacyIDEAADFSProvider
{
    public class Adapter : IAuthenticationAdapter, IPILog
    {
        private readonly string _version = typeof(Adapter).Assembly.GetName().Version.ToString();

        private PrivacyIDEA _privacyIDEA;
        private Configuration _config;
        private bool _debugLog = true;

        public IAuthenticationAdapterMetadata Metadata
        {
            get
            {
                AdapterMetadata meta = new AdapterMetadata();
                meta.AdapterMetadataInit();
                meta.AdapterVersion = _version;
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
            Dictionary<string, string> customParameters = new Dictionary<string, string>();
            if (_config.ForwardClientIP)
            {
                customParameters.Add("client", GetClientIPAddress(request));
                //Log("Client IP address: " + customParameters["client"]);
            }
            if (_config.ForwardClientUserAgent)
            {
                customParameters.Add("client_user_agent", request.Headers["User-Agent"]);
                //Log("Client User-Agent: " + customParameters["client_user_agent"]);
            }

            string username = "", domain = "";
            Log("BeginAuthentication: identityClaim: " + identityClaim.Value);

            // Separate the username from the domain
            string[] tmp = identityClaim.Value.Split('\\');
            string upn;
            if (tmp.Length > 1)
            {
                username = tmp[1];
                domain = tmp[0];
                if (_config.UseUPN)
                {
                    // Get the UPN from the sAMAccountName
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
            if (_config.UseUPN)
            {
                username = upn;
            }

            var form = new AdapterPresentationForm(Log)
            {
                OtpHint = _config.OtpHint,
                AutoSubmitLength = _config.AutoSubmitLength,
                DisablePasskey = _config.DisablePasskey ? "1" : "0"
            };

            List<KeyValuePair<string, string>> headers = GetHeadersToForward(request);

            // Trigger challenges with service account or empty pass if configured
            PIResponse response = null;
            if (_privacyIDEA != null)
            {
                if (_config.TriggerChallenge)
                {
                    response = _privacyIDEA.TriggerChallenges(username, domain, headers, customParameters);
                }
                else if (_config.SendEmptyPassword)
                {
                    response = _privacyIDEA.ValidateCheck(username, "", domain, headers:headers, customParameters:customParameters);
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
                else if (response.isAuthenticationSuccessful())
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
                }
            }

            if (string.IsNullOrEmpty(form.Mode))
            {
                form.Mode = "otp";
            }
            authContext.Data.Add("userid", username);
            authContext.Data.Add("domain", domain);

            // Perform optional token enrollment
            // If a challenge was triggered previously, checking if the user has a token is skipped
            if (_config.EnrollmentEnabled &&
                (response != null && string.IsNullOrEmpty(response.TransactionID) || (response == null)) &&
                !_privacyIDEA.UserHasToken(username, domain, customParameters))
            {
                PIEnrollResponse res = _privacyIDEA.TokenInit(username, domain, customParameters);
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
                if (GetString(authContext.Data, "authSuccess", "") == "1")
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

            if (_privacyIDEA == null)
            {
                Error("PrivacyIDEA is not initialized!");
                throw new ExternalAuthenticationException("PrivacyIDEA is not initialized!", authContext);
            }
            Dictionary<string, object> contextDict = authContext.Data;
            Dictionary<string, object> proofDict = proofData.Properties;
            Log("ProofData: " + string.Join(", ", proofData.Properties));
            Log("AuthContext: " + string.Join(", ", authContext.Data));

            // Get the form data and prepare the next form
            var form = new AdapterPresentationForm(Log)
            {
                OtpHint = _config.OtpHint,
                AutoSubmitLength = _config.AutoSubmitLength,
                DisablePasskey = _config.DisablePasskey ? "1" : "0"
            };
            // Restore enrollment data if there was any
            if (proofDict.TryGetValue("enrollmentImg", out object enrollmentImg))
            {
                form.EnrollmentImg = (string)enrollmentImg;
            }
            if (proofDict.TryGetValue("enrollmentLink", out object enrollmentLink))
            {
                form.EnrollmentLink = (string)enrollmentLink;
            }
            if (proofDict.TryGetValue("disableOTP", out object disableOtp))
            {
                form.DisableOTP = (string)disableOtp;
            }

            // FormResult
            if (!proofDict.TryGetValue("formResult", out object formResult))
            {
                form.ErrorMessage = "Internal error. Please try again.";
                return form;
            }
            FormResult fr = JsonConvert.DeserializeObject<FormResult>((string)formResult);
            bool modeChanged = fr.ModeChanged;
            string mode = modeChanged ? fr.NewMode : GetString(proofDict, "mode", "otp");
            string otp = GetString(proofDict, "otp");
            form.Message = GetString(proofDict, "message");
            form.Mode = mode;
            form.PushAvailable = GetString(proofDict, "pushAvailable");

            if (proofDict.TryGetValue("webAuthnSignRequest", out object signRequest))
            {
                form.WebAuthnSignRequest = (string)signRequest;
            }
            if (proofDict.TryGetValue("authCounter", out object authCounter))
            {
                form.AuthCounter = (int.Parse((string)authCounter) + 1).ToString();
            }

            // Params from context
            string transactionid = GetString(contextDict, "transactionid");
            string user = GetString(contextDict, "userid");
            string domain = GetString(contextDict, "domain");
            string pushTransactionid = GetString(contextDict, "push_transaction_id");
            string webauthnTransactionid = GetString(contextDict, "webauthn_transaction_id");
            string passkeyTransactionid = GetString(contextDict, "passkey_transaction_id");
            string otpTransactionid = GetString(contextDict, "otp_transaction_id");

            // Restore the previous response to set the challenges again in case of error
            PIResponse previousResponse = null;
            if (contextDict.TryGetValue("previousResponse", out object prevResponse))
            {
                previousResponse = PIResponse.FromJSON((string)prevResponse, _privacyIDEA);
            }

            if (modeChanged)
            {
                return form;
            }

            // Prepare custom parameters
            Dictionary<string, string> customParameters = new Dictionary<string, string>();
            if (_config.ForwardClientIP)
            {
                customParameters.Add("client", GetClientIPAddress(request));
                //Log("Client IP address: " + customParameters["client"]);
            }
            if (_config.ForwardClientUserAgent)
            {
                customParameters.Add("client_user_agent", request.Headers["User-Agent"]);
                //Log("Client User-Agent: " + customParameters["client_user_agent"]);
            }

            // Collect headers to forward with next PI request
            List<KeyValuePair<string, string>> headers = GetHeadersToForward(request);
            PIResponse response = null;
            // Passkey login requested
            if (fr.PasskeyLoginRequested)
            {
                response = _privacyIDEA.ValidateInitialize("passkey", headers, customParameters);
                if (response != null)
                {
                    form.PasskeyChallenge = response.PasskeyChallenge;
                    authContext.Data.Add("passkey_transaction_id", response.PasskeyTransactionID);
                    return form;
                }
            }

            // Do the authentication according to the mode or data present
            // Passkey Authentication
            if (!string.IsNullOrEmpty(fr.PasskeySignResponse))
            {
                if (string.IsNullOrEmpty(fr.Origin))
                {
                    Error("Incomplete data for Passkey authentication: Origin is missing!");
                    form.ErrorMessage = "Could not complete Passkey authentication. Try again or use another token type.";
                }
                else
                {
                    response = _privacyIDEA.ValidateCheckPasskey(passkeyTransactionid, fr.PasskeySignResponse, fr.Origin,
                        domain, headers, customParameters);
                }
            }
            // Passkey Registration (enroll_via_multichallenge)
            else if (!string.IsNullOrEmpty(fr.PasskeyRegistrationResponse))
            {
                var serial = GetString(contextDict, "passkey_registration_serial");
                var transactionId = GetString(contextDict, "transactionid");
                if (string.IsNullOrEmpty(serial) || string.IsNullOrEmpty(transactionId) || string.IsNullOrEmpty(fr.Origin))
                {
                    Error($"Incomplete data for Passkey registration: Serial {serial}, transactionid {transactionId} " +
                        $"or origin {fr.Origin} missing!");
                    form.ErrorMessage = "Could not complete Passkey registration. Try again or use another token type.";
                }
                else
                {
                    response = _privacyIDEA.ValidateCheckCompletePasskeyRegistration(transactionId, serial, user,
                        fr.PasskeyRegistrationResponse, fr.Origin, headers: null, customParameters:customParameters);
                }
            }
            // Push
            else if (mode == "push")
            {
                if (_privacyIDEA.PollTransaction(pushTransactionid, customParameters))
                {
                    // Push confirmed, finish the authentication via /validate/check using an empty otp
                    // https://privacyidea.readthedocs.io/en/latest/tokens/authentication_modes.html#outofband-mode
                    response = _privacyIDEA.ValidateCheck(user, "", pushTransactionid, domain, headers, customParameters);
                }
                else
                {
                    // Else push not confirmed yet
                    form.ErrorMessage = "Authenication not confirmed yet!";
                }
            }
            // WebAuthn
            else if (!string.IsNullOrEmpty(fr.WebAuthnSignResponse))
            {
                if (string.IsNullOrEmpty(fr.Origin))
                {
                    Error("Incomplete data for WebAuthn authentication: Origin is missing!");
                    form.ErrorMessage = "Could not complete WebAuthn authentication. Try again or use another token type.";
                }
                else
                {
                    response = _privacyIDEA.ValidateCheckWebAuthn(user, webauthnTransactionid, fr.WebAuthnSignResponse, fr.Origin,
                        domain, headers, customParameters);
                }
            }
            else
            {
                // Mode == OTP
                response = _privacyIDEA.ValidateCheck(user, otp, otpTransactionid, domain, headers, customParameters);
            }

            // Evaluate the response
            bool newChallenge = false;
            if (response != null)
            {
                if (response.Challenges.Count > 0)
                {
                    newChallenge = true;
                    form = ExtractChallengeDataToForm(response, form, authContext);
                    authContext.Data.Add("previousResponse", response.Raw);
                }
                else if (response.isAuthenticationSuccessful())
                {
                    if (!string.IsNullOrEmpty(response.Username) && response.Username != user)
                    {
                        Log("Passkey Authentication: Usernames do not match! User from privacyidea: " + response.Username +
                            ", user from context: " + user);
                        form.ErrorMessage = "The passkey is not for the user trying to log in!";
                        return form;
                    }
                    else
                    {
                        outgoingClaims = Claims();
                        return null;
                    }
                }
                else
                {
                    if (previousResponse != null)
                    {
                        form = ExtractChallengeDataToForm(previousResponse, form, authContext);
                    }

                    // Set the error message from the response or a default
                    if (!string.IsNullOrEmpty(response.ErrorMessage))
                    {
                        form.ErrorMessage = response.ErrorMessage + " (" + response.ErrorCode + ")";
                    }
                    else
                    {
                        form.ErrorMessage = response.Message;
                    }
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
        /// Get the client IP address from the request, considering possible proxy headers.
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        private string GetClientIPAddress(HttpListenerRequest request)
        {
            // Check X-Forwarded-For header first (for clients behind proxy)
            string clientIP = request.Headers["X-Forwarded-For"];
            if (string.IsNullOrEmpty(clientIP))
            {
                // If no X-Forwarded-For, use RemoteEndPoint
                clientIP = request.RemoteEndPoint?.Address?.ToString();
            }
            return clientIP ?? "unknown";
        }

        /// <summary>
        /// Called when the provider is loaded by the AD FS service. The config will be loaded in this function.
        /// </summary>
        /// <param name="configData"></param>
        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        {
            Log("PrivacyIDEA AD FS Plugin " + _version + " - OnAuthenticationPipelineLoad");

            _config = new Configuration(Log);
            if (string.IsNullOrEmpty(_config.Url))
            {
                Error("No server URL configured. Can not initialize privacyIDEA without a server URL.");
                throw new Exception("No server URL configured. Can not initialize privacyIDEA without a server URL.");
            }

            _privacyIDEA = new PrivacyIDEA(_config.Url, "PrivacyIDEA-ADFS/" + _version, !_config.DisableSSL)
            {
                Logger = this
            };

            if (!string.IsNullOrEmpty(_config.Realm))
            {
                _privacyIDEA.Realm = _config.Realm;
            }

            if (_config.ServiceAccountAvailable())
            {
                _privacyIDEA.SetServiceAccount(_config.ServiceUser, _config.ServicePass, _config.ServiceRealm);
            }

            if (_config.RealmMap.Count > 0)
            {
                _privacyIDEA.RealmMap = _config.RealmMap;
            }
        }

        /// <summary>
        /// cleanup function
        /// </summary>
        public void OnAuthenticationPipelineUnload()
        {
            _privacyIDEA.Dispose();
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
            var form = new AdapterPresentationForm(Log)
            {
                ErrorMessage = ex.Message
            };
            return form;
        }

        /// This function should only be used if the response contains challenges that were triggered.
        private AdapterPresentationForm ExtractChallengeDataToForm(PIResponse response, AdapterPresentationForm form,
            IAuthenticationContext authContext)
        {
            if (response == null)
            {
                return form;
            }

            // Reset values
            form.WebAuthnSignRequest = "";
            form.Mode = "otp";
            form.PushAvailable = "0";
            form.EnrollmentImg = "";
            form.EnrollmentLink = "";
            form.DisableOTP = "0";

            // New values
            form.Message = response.Message;

            if (response.PushMessage() is string pushMessage)
            {
                form.PushAvailable = "1";
                form.PushMessage = pushMessage;
            }

            if (response.MergedSignRequest() is string webAuthnSignRequest)
            {
                form.WebAuthnSignRequest = webAuthnSignRequest;
            }

            if (!string.IsNullOrEmpty(response.PreferredClientMode))
            {
                form.Mode = response.PreferredClientMode;
            }

            if (form.Mode == "webauthn" && (form.WebAuthnSignRequest == null || string.IsNullOrEmpty(form.WebAuthnSignRequest)))
            {
                form.Mode = "otp";
            }

            // Check for an image, which indicates enroll_via_multichallenge
            var challengeWithImage = response.Challenges.FirstOrDefault(challenge => !string.IsNullOrEmpty(challenge.Image));
            if (challengeWithImage != null)
            {
                form.EnrollmentImg = challengeWithImage.Image;
                form.EnrollmentLink = response.EnrollmentLink;
                form.Mode = challengeWithImage.Type;
                if (form.Mode == "push")
                {
                    form.DisableOTP = "1"; // Disable OTP input if it is push
                }
            }

            if (!string.IsNullOrEmpty(response.PasskeyRegistration))
            {
                form.PasskeyRegistration = response.PasskeyRegistration;
                form.PasskeyChallenge = "";
                authContext.Data["passkey_registration_serial"] = response.Serial;
            }
            // Transaction IDs
            authContext.Data["transactionid"] = response.TransactionID;
            if (!string.IsNullOrEmpty(response.OTPTransactionID))
            {
                authContext.Data["otp_transaction_id"] = response.OTPTransactionID;
            }
            if (!string.IsNullOrEmpty(response.PasskeyTransactionID))
            {
                authContext.Data["passkey_transaction_id"] = response.PasskeyTransactionID;
            }
            if (!string.IsNullOrEmpty(response.PushTransactionID))
            {
                authContext.Data["push_transaction_id"] = response.PushTransactionID;
            }
            if (!string.IsNullOrEmpty(response.WebAuthnTransactionID))
            {
                authContext.Data["webauthn_transaction_id"] = response.WebAuthnTransactionID;
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

            foreach (string header in _config.ForwardHeaders)
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

        private string GetString(Dictionary<string, object> dict, string key, string defaultValue = "")
        {
            if (dict.ContainsKey(key))
            {
                return (string)dict[key];
            }
            Log("Key '" + key + "' could not be found in dict, returning default value '" + defaultValue + "'.");
            return defaultValue;
        }

        public void Log(string message)
        {
            string formatted = "[" + DateTime.Now.ToString("yyyy-MM-ddTHH\\:mm\\:ss") + "] " + message;
            LogImpl(formatted);
        }

        public void Error(string message)
        {
            string formatted = "[" + DateTime.Now.ToString("yyyy-MM-ddTHH\\:mm\\:ss") + "] " + message;
            // write error to both
            EventError(formatted);
            LogImpl(formatted);
        }

        public void Error(Exception exception)
        {
            string message = exception.Message + ":\n" + exception.ToString();
            string formatted = "[" + DateTime.Now.ToString("yyyy-MM-ddTHH\\:mm\\:ss") + "] " + message;
            // Write error to both
            EventError(formatted);
            LogImpl(formatted);
        }

        private void EventError(string message)
        {
            using EventLog eventLog = new EventLog("AD FS/Admin");
            eventLog.Source = "privacyIDEAProvider";
            eventLog.WriteEntry(message, EventLogEntryType.Error, 9901, 0);
        }

        public async void LogImpl(string msg)
        {
            if (_debugLog)
            {
                try
                {
                    using StreamWriter streamWriter = new StreamWriter("C:\\PrivacyIDEA-ADFS log.txt", append: true);
                    await streamWriter.WriteLineAsync(msg);
                }
                catch (Exception e)
                {
                    EventError("Error while trying to write to logfile: " + e.Message);
                }
            }
        }
    }
}
