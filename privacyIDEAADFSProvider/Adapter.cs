using System.Net;
using Microsoft.IdentityServer.Web.Authentication.External;
using Claim = System.Security.Claims.Claim;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Xml.Serialization;
using System.DirectoryServices.AccountManagement;
using System;
using SDKNS;
using SDK;
using System.Collections.Generic;

namespace privacyIDEAADFSProvider
{
    public class Adapter : IAuthenticationAdapter, PILog
    {
        private string version = typeof(Adapter).Assembly.GetName().Version.ToString();
        public string realm;
        private bool use_upn = false;

        //public UITranslation[] uitranslations;

        private bool triggerChallenge = false;
        private bool sendEmptyPassword = false;

        private PrivacyIDEA privacyIDEA;
        private bool debuglog = false;

        // TODO disable debug logging
        public IAuthenticationAdapterMetadata Metadata
        {
            //get { return new <instance of IAuthenticationAdapterMetadata derived class>; }
            get
            {
                AdapterMetadata meta = new AdapterMetadata();
                meta.AdapterMetadataInit();
                meta.adapterversion = version;
                return meta;
            }
        }
        /// <summary>
        /// Initiates a new authentication process and returns to the ADFS system.
        /// </summary>
        /// <param name="identityClaim">Claim information from the ADFS</param>
        /// <param name="request">The http request</param>
        /// <param name="authContext">The context for the authentication</param>
        /// <returns>new instance of IAdapterPresentationForm</returns>
        public IAdapterPresentation BeginAuthentication(Claim identityClaim, HttpListenerRequest request,
            IAuthenticationContext authContext)
        {
            Log("BeginAuthentication: identityClaim: " + identityClaim.Value);

            // seperates the username from the domain
            // TODO: Map the domain to the PI realm
            string username, domain, upn = "";
            string[] tmp = identityClaim.Value.Split('\\');

            if (tmp.Length > 1)
            {
                username = tmp[1];
                domain = tmp[0];
                if (use_upn)
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
                domain = realm;
            }

            Log("UPN value: " + upn + ", Domain value: " + domain);

            // use upn or sam as loginname attribute
            if (use_upn)
            {
                username = upn;
            }

            // Prepare the form
            var form = new AdapterPresentationForm();

            // trigger challenges
            // string webAuthnSignRequest = "";
            PIResponse response = null;

            if (privacyIDEA != null)
            {
                if (triggerChallenge)
                {
                    response = privacyIDEA.TriggerChallenges(username);
                }
                else if (sendEmptyPassword)
                {
                    // TODO get the password from first step, if not possible send empty pass?
                    response = privacyIDEA.ValidateCheck(username, "");
                }
            }
            else
            {
                Error("privacyIDEA not initialized!");
            }

            if (response != null)
            {
                if (response.MultiChallenge.Count > 0)
                {
                    authContext.Data.Add("transactionid", response.TransactionID);
                    form.Message = response.Message;
                    if (response.TriggeredTokenTypes().Contains("push"))
                    {
                        form.PushAvailable = "1";
                        form.PushMessage = response.PushMessage();
                    }
                }
                else if (response.Value)
                {
                    // Success in step 1, carry this over to the second step so that it will be skipped
                    authContext.Data.Add("authSuccess", "1");
                    form.AutoSubmit = "1";
                }
                else
                {
                    // TODO
                    Error("Sent somehting in first step and got failure back");
                }
            }

            form.Mode = "otp";
            authContext.Data.Add("userid", username);
            authContext.Data.Add("realm", realm);

            return form;
        }

        /// <summary>
        /// Function call after the user hits submit
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

            Dictionary<string, object> contextDict = authContext.Data;
            Dictionary<string, object> proofDict = proofData.Properties;


            Log("ProofData: " + string.Join(", " , proofData.Properties));
            Log("AuthContext: " + string.Join(" ," , authContext.Data));
            // Prepare form to return, fill with values from proofData
            var form = new AdapterPresentationForm();

            string otp = (string)GetFromDict(proofDict, "otp");
            string mode = (string)GetFromDict(proofDict, "mode");
            string modeChanged = (string)GetFromDict(proofDict, "modeChanged");
            string pushAvailable = (string)GetFromDict(proofDict, "pushAvailable");
            string message = (string)GetFromDict(proofDict, "message");

            string strAuthCounter = (string)GetFromDict(proofDict, "authCounter", "0");
            if (!string.IsNullOrEmpty(strAuthCounter))
            {
                form.AuthCounter = (int.Parse(strAuthCounter) + 1).ToString();
            }

            form.Message = message;
            form.Mode = mode;
            form.PushAvailable = pushAvailable;

            string transactionid = (string)GetFromDict(contextDict, "transactionid");
            // TODO realm usage
            string realm = (string)GetFromDict(contextDict, "realm");
            string user = (string)GetFromDict(contextDict, "userid");

            if (modeChanged == "1")
            {
                return form;
            }

            // Do the authentication according to the mode we are in
            if (privacyIDEA != null)
            {
                PIResponse response = null;
                if (mode == "push")
                {
                    if (privacyIDEA.PollTransaction(transactionid))
                    {
                        // Push confirmed, finish the authentication via /validate/check using an empty otp
                        // https://privacyidea.readthedocs.io/en/latest/tokens/authentication_modes.html#outofband-mode
                        response = privacyIDEA.ValidateCheck(user, "", transactionid);
                        if (response != null && response.Value)
                        {
                            outgoingClaims = Claims();
                            return null;
                        }
                    }
                    else
                    {
                        // Else push not confirmed yet
                        form.ErrorMessage = "Authenication not confirmed yet!";
                    }
                }
                else if (mode == "webauthn")
                {
                    // TODO webauthn implementaiton
                }
                else
                {
                    // Mode == OTP
                    response = privacyIDEA.ValidateCheck(user, otp, transactionid);
                    if (response != null && response.Value)
                    {
                        outgoingClaims = Claims();
                        return null;
                    }
                }

                // If we get this far, the login data provided was wrong or an error occured.
                if (response != null)
                {
                    Error("Response value was false!");
                    // Set the error message from the response or a default
                    form.ErrorMessage = (!string.IsNullOrEmpty(response.ErrorMessage)) ? response.ErrorMessage + " (" + response.ErrorCode + ")"
                        : "Wrong OTP value!";
                }
                else
                {
                    // In case of unconfirmed push, response will be null too. Therefore, set the message only if there is none yet.
                    if (string.IsNullOrEmpty(form.ErrorMessage))
                    {
                        form.ErrorMessage = "The authentication server could not be reached.";
                        Error("Reponse from server was null!");
                    }
                }
            }
            else
            {
                Error("privacyIDEA not initalized!");
            }

            // Set a generic error if none was set yet
            if (string.IsNullOrEmpty(form.ErrorMessage))
            {
                form.ErrorMessage = "An error occured.";
            }
            // Return form with error
            return form;
        }

        // Return the required authentication method claim, indicating the particular authentication method used.
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

        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext authContext)
        {
            // Available for all users
            return true;
        }

        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        {
            System.Reflection.Assembly assembly = System.Reflection.Assembly.GetExecutingAssembly();
            System.Diagnostics.FileVersionInfo fvi = System.Diagnostics.FileVersionInfo.GetVersionInfo(assembly.Location);
            string realversion = fvi.FileVersion;
            Log("OnAuthenticationPipelineLoad: Provider Version " + realversion);

            List<string> configKeys = new List<string>(new string[] 
            { "use_upn", "url", "disable_ssl", "service_user", "service_pass", "service_realm",
                "realm", "trigger_challenges", "send_empty_pass", "debug_log" });
            var configDict = new Dictionary<string, string>();
            LogFunction log = Log;
            RegistryReader rr = new RegistryReader(log);
            configKeys.ForEach(key =>
            {
                string value = rr.Read(key);
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

            this.privacyIDEA = new PrivacyIDEA(url, "PrivacyIDEA-ADFS", shouldUseSSL);

            string serviceUser = GetFromDict(configDict, "service_user", "");
            string servicePass = GetFromDict(configDict, "service_pass", "");

            if (!string.IsNullOrEmpty(serviceUser) && !string.IsNullOrEmpty(servicePass))
            {
                this.privacyIDEA.SetServiceAccount(serviceUser, servicePass, GetFromDict(configDict, "service_realm"));
            }

            this.use_upn = GetFromDict(configDict, "use_upn", "0") == "1";
            this.debuglog = GetFromDict(configDict, "debug_log", "0") == "1";

            this.triggerChallenge = GetFromDict(configDict, "trigger_challenges", "0") == "1";
            if (!this.triggerChallenge)
            {
                // Only if triggerChallenge is disabled, sendEmptyPassword COULD be set
                this.sendEmptyPassword = GetFromDict(configDict, "send_empty_pass", "0") == "1";
            }
            this.realm = GetFromDict(configDict, "realm", "");
        }

        /// <summary>
        /// cleanup function
        /// </summary>
        public void OnAuthenticationPipelineUnload()
        {
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
            return new AdapterPresentationForm();
        }
        public void Log(string message)
        {
            this.LogImpl(message);
        }

        public void Error(string message)
        {
            this.EventError(message);
        }

        public void Error(Exception exception)
        {
            this.EventError(exception.Message + ":\n" +
                exception.StackTrace);
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
            if (this.debuglog || true)
            {
                // TODO catch missing file access etc
                try
                {
                    using (StreamWriter streamWriter = new StreamWriter("C:\\PrivacyIDEA-ADFS log.txt", append: true))
                    {
                        await streamWriter.WriteLineAsync(msg);
                    }
                }
                catch (Exception e)
                {
                    Error("Error while trying to write to logfile: " + e.Message);
                }
            }
        }

    }
}
