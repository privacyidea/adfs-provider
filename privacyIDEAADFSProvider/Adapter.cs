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
        private bool _debugLog = false;
        private AdapterMetadata _metadata;

        public IAuthenticationAdapterMetadata Metadata =>
            _metadata ??= new AdapterMetadata { AdapterVersion = _version };

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

            var (username, domain, upn) = ResolveIdentity(identityClaim);
            Log("UPN value: " + upn + ", Domain value: " + domain);
            if (_config.UseUPN)
            {
                username = upn;
            }

            var form = new AdapterPresentationForm()
            {
                OtpHint = _config.OtpHint,
                AutoSubmitLength = _config.AutoSubmitLength,
                DisablePasskey = _config.DisablePasskey ? "1" : "0"
            };

            var context = new PIRequestContext
            {
                Domain = domain,
                Headers = GetHeadersToForward(request),
                CustomParameters = CollectCustomParams(request),
            };

            PIResponse response = null;
            if (_privacyIDEA != null)
            {
                if (_config.TriggerChallenge)
                {
                    response = _privacyIDEA.TriggerChallenges(username, context);
                }
                else if (_config.SendEmptyPassword)
                {
                    response = _privacyIDEA.ValidateCheck(username, "", context: context);
                }
            }
            else
            {
                Error("privacyIDEA not initialized!");
            }

            if (response != null)
            {
                if (response.Challenges.Count > 0)
                {
                    form = ExtractChallengeDataToForm(response, form, authContext);
                }
                else if (response.isAuthenticationSuccessful())
                {
                    // Step 1 already passed (no challenges). Skip step 2.
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
                form.Mode = PITokenType.Otp;
            }
            authContext.Data.Add("userid", username);
            authContext.Data.Add("domain", domain);

            // Optional token enrollment: skip the UserHasToken probe when a challenge already fired,
            // since a triggered challenge implies the user has a token already.
            if (_privacyIDEA != null && _config.EnrollmentEnabled &&
                (response == null || string.IsNullOrEmpty(response.TransactionID)) &&
                !_privacyIDEA.UserHasToken(username, context))
            {
                PIEnrollResponse res = _privacyIDEA.TokenInit(username, context);
                // TokenInit returns null when /token/init is unreachable or returns an unparseable body.
                if (res != null)
                {
                    form.EnrollmentUrl = res.TotpUrl;
                    form.EnrollmentImg = res.Base64TotpImage;
                }
            }

            return form;
        }

        /// <summary>Called when our form is submitted.</summary>
        public IAdapterPresentation TryEndAuthentication(IAuthenticationContext authContext, IProofData proofData,
            HttpListenerRequest request, out Claim[] outgoingClaims)
        {
            Log("TryEndAuthentication");
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

            var form = new AdapterPresentationForm()
            {
                OtpHint = _config.OtpHint,
                AutoSubmitLength = _config.AutoSubmitLength,
                DisablePasskey = _config.DisablePasskey ? "1" : "0"
            };
            form.EnrollmentImg = GetString(proofDict, "enrollmentImg");
            form.EnrollmentLink = GetString(proofDict, "enrollmentLink");
            form.DisableOTP = GetString(proofDict, "disableOTP", "0");
            // Carry the optional-enrollment flag across poll reloads, otherwise the "Not Now"
            // skip button (gated on enrollmentOptional=="1" in the page JS) disappears after the first poll.
            form.EnrollmentOptional = GetString(proofDict, "enrollmentOptional", "0");

            if (!proofDict.TryGetValue("formResult", out object formResult))
            {
                form.ErrorMessage = "Internal error. Please try again.";
                return form;
            }
            FormResult fr = JsonConvert.DeserializeObject<FormResult>((string)formResult);
            bool modeChanged = fr.ModeChanged;
            string mode = modeChanged ? fr.NewMode : GetString(proofDict, "mode", PITokenType.Otp);
            string otp = GetString(proofDict, "otp");
            form.Message = GetString(proofDict, "message");
            form.Mode = mode;
            form.PushAvailable = GetString(proofDict, "pushAvailable");

            form.WebAuthnSignRequest = GetString(proofDict, "webAuthnSignRequest");
            // authCounter is a client-submitted hidden field; parse defensively so a tampered/garbled
            // value can't throw out of TryEndAuthentication (the JS side uses the same tolerant Number()||0).
            if (proofDict.TryGetValue("authCounter", out object authCounter)
                && int.TryParse(authCounter as string, out int counter))
            {
                form.AuthCounter = (counter + 1).ToString();
            }

            string user = GetString(contextDict, "userid");
            string domain = GetString(contextDict, "domain");

            // The prior response is the single source of truth for transaction IDs and the data
            // needed to repopulate challenges on validation error. PI groups challenges by one
            // transaction_id, so TransactionID covers OTP/push/webauthn/passkey-registration.
            PIResponse previousResponse = null;
            if (contextDict.TryGetValue("previousResponse", out object prevResponse))
            {
                previousResponse = PIResponse.FromJSON((string)prevResponse, _privacyIDEA);
            }
            string transactionid = previousResponse?.TransactionID ?? "";
            // Passkey login's transaction id is kept under its own key: the /validate/initialize response
            // that starts a passkey login must NOT overwrite previousResponse, or an OTP/push/webauthn
            // challenge offered alongside the passkey button would lose its transaction id.
            string passkeyTransactionid = GetString(contextDict, "passkeyTransactionId");

            if (modeChanged)
            {
                return form;
            }

            var context = new PIRequestContext
            {
                Domain = domain,
                Headers = GetHeadersToForward(request),
                CustomParameters = CollectCustomParams(request),
            };
            PIResponse response = null;

            // Optional enroll-via-multichallenge: user clicked "Not Now"
            if (fr.EnrollmentCancelled)
            {
                response = _privacyIDEA.CancelEnrollment(transactionid, context);
                if (response != null && response.isAuthenticationSuccessful())
                {
                    outgoingClaims = Claims();
                    return null;
                }
                form.ErrorMessage = response?.Message ?? "Failed to cancel enrollment.";
                return form;
            }

            // Passkey login requested
            if (fr.PasskeyLoginRequested)
            {
                response = _privacyIDEA.ValidateInitialize(PITokenType.Passkey, context);
                if (response != null)
                {
                    form.PasskeyChallenge = response.PasskeyChallenge;
                    // Persist only the passkey transaction id (not the whole response), so the original
                    // challenge's previousResponse — and its OTP/push/webauthn options — survives.
                    authContext.Data["passkeyTransactionId"] = response.PasskeyTransactionID;
                    return form;
                }
                // ValidateInitialize failed (e.g. the server was unreachable). Surface it instead of
                // falling through to the final else, which would fire an empty-pass /validate/check.
                Error("Failed to initialize Passkey authentication: no response from the server.");
                form.ErrorMessage = "Could not start Passkey authentication. Try again or use another token type.";
                return form;
            }

            if (!string.IsNullOrEmpty(fr.PasskeySignResponse))
            {
                if (string.IsNullOrEmpty(fr.Origin))
                {
                    Error("Incomplete data for Passkey authentication: Origin is missing!");
                    form.ErrorMessage = "Could not complete Passkey authentication. Try again or use another token type.";
                }
                else
                {
                    response = _privacyIDEA.ValidateCheckPasskey(passkeyTransactionid, fr.PasskeySignResponse, fr.Origin, context);
                }
            }
            // Passkey Registration (enroll_via_multichallenge)
            else if (!string.IsNullOrEmpty(fr.PasskeyRegistrationResponse))
            {
                string serial = previousResponse?.Serial ?? "";
                if (string.IsNullOrEmpty(serial) || string.IsNullOrEmpty(transactionid) || string.IsNullOrEmpty(fr.Origin))
                {
                    Error($"Incomplete data for Passkey registration: Serial {serial}, transactionid {transactionid} " +
                        $"or origin {fr.Origin} missing!");
                    form.ErrorMessage = "Could not complete Passkey registration. Try again or use another token type.";
                }
                else
                {
                    response = _privacyIDEA.ValidateCheckCompletePasskeyRegistration(transactionid, serial, user,
                        fr.PasskeyRegistrationResponse, fr.Origin, context);
                }
            }
            else if (mode == PITokenType.Push)
            {
                if (_privacyIDEA.PollTransaction(transactionid, context))
                {
                    // Outofband-mode finalize: empty otp + the pushed transaction id.
                    // https://privacyidea.readthedocs.io/en/latest/tokens/authentication_modes.html#outofband-mode
                    response = _privacyIDEA.ValidateCheck(user, "", transactionid, context);
                }
                else
                {
                    // enroll_via_multichallenge poll (smartphone/push token enrollment) carries a QR image;
                    // a plain push-token login does not. Word the "still waiting" message accordingly.
                    form.ErrorMessage = !string.IsNullOrEmpty(form.EnrollmentImg)
                        ? "Registration not completed yet!"
                        : "Authentication not confirmed yet!";
                }
            }
            else if (!string.IsNullOrEmpty(fr.WebAuthnSignResponse))
            {
                if (string.IsNullOrEmpty(fr.Origin))
                {
                    Error("Incomplete data for WebAuthn authentication: Origin is missing!");
                    form.ErrorMessage = "Could not complete WebAuthn authentication. Try again or use another token type.";
                }
                else
                {
                    response = _privacyIDEA.ValidateCheckWebAuthn(user, transactionid, fr.WebAuthnSignResponse, fr.Origin, context);
                }
            }
            else
            {
                response = _privacyIDEA.ValidateCheck(user, otp, transactionid, context);
            }

            bool newChallenge = false;
            if (response != null)
            {
                if (response.Challenges.Count > 0)
                {
                    newChallenge = true;
                    form = ExtractChallengeDataToForm(response, form, authContext);
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

            if (string.IsNullOrEmpty(form.ErrorMessage) && !newChallenge)
            {
                form.ErrorMessage = "An error occurred.";
            }
            return form;
        }

        public bool IsAvailableForUser(Claim identityClaim, IAuthenticationContext authContext)
        {
            return true;
        }

        /// <summary>
        /// Splits the identity claim into username/domain and, when UseUPN is enabled, resolves the UPN
        /// from the sAMAccountName via an LDAP lookup (which also rewrites the domain to the UPN suffix).
        /// </summary>
        private (string username, string domain, string upn) ResolveIdentity(Claim identityClaim)
        {
            string[] tmp = identityClaim.Value.Split('\\');
            if (tmp.Length <= 1)
            {
                return (tmp[0], "", tmp[0]);
            }

            string username = tmp[1];
            string domain = tmp[0];
            if (!_config.UseUPN)
            {
                return (username, domain, "not used");
            }

            // Get the UPN from the sAMAccountName
            Log("Getting UPN for user:" + username + " and domain: " + domain + "...");
            using PrincipalContext ctx = new PrincipalContext(ContextType.Domain, domain);
            using UserPrincipal user = UserPrincipal.FindByIdentity(ctx, username);
            if (user == null)
            {
                Error("Could not find user '" + username + "' in domain '" + domain + "'.");
                return (username, domain, username);
            }

            string upn = user.UserPrincipalName;
            if (string.IsNullOrEmpty(upn))
            {
                // userPrincipalName is optional in AD (only sAMAccountName is mandatory); fall back to the username.
                Error("User '" + username + "' in domain '" + domain + "' has no UPN set. Falling back to username.");
                return (username, domain, username);
            }
            Log("Found UPN: " + upn);
            // Set domain to UPN suffix instead of NetBIOS domain
            domain = upn.Contains("@") ? upn.Split('@')[1] : domain;
            Log("Domain for " + upn + ": " + domain);
            return (username, domain, upn);
        }

        /// <summary>Collect custom parameters to forward to privacyIDEA based on configuration.</summary>
        private Dictionary<string, string> CollectCustomParams(HttpListenerRequest request)
        {
            Dictionary<string, string> customParameters = new Dictionary<string, string>();
            if (_config.ForwardClientIP)
            {
                customParameters.Add("client", GetClientIPAddress(request));
            }
            if (_config.ForwardClientUserAgent)
            {
                string userAgent = request.Headers?["User-Agent"];
                customParameters.Add("client_user_agent", userAgent ?? string.Empty);
            }

            return customParameters;
        }

        private string GetClientIPAddress(HttpListenerRequest request)
        {
            string peer = request.RemoteEndPoint?.Address?.ToString();
            string forwardedFor = request.Headers["X-Forwarded-For"];
            if (string.IsNullOrEmpty(forwardedFor))
            {
                return peer ?? "unknown";
            }

            // X-Forwarded-For is set by the client and therefore spoofable. privacyIDEA can use the
            // forwarded IP for policy decisions (geo-fencing, IP allow/deny), so a request reaching AD FS
            // directly could forge this header to bypass those policies. Only honor it when the direct TCP
            // peer is a configured trusted proxy. With no trusted_proxies configured we keep the legacy
            // behavior of trusting XFF (documented as insecure) so existing deployments don't silently break.
            // TODO(next major): make secure-by-default — ignore XFF unless a trusted proxy is configured.
            if (_config.TrustedProxies.Count == 0 || IsTrustedProxy(peer))
            {
                // "client, proxy1, proxy2" — the left-most entry is the originating client.
                string forwardedClient = forwardedFor.Split(',')[0].Trim();
                if (!string.IsNullOrEmpty(forwardedClient))
                {
                    return forwardedClient;
                }
            }
            return peer ?? "unknown";
        }

        /// <summary>True if the given IP matches any configured trusted-proxy entry (exact IP or CIDR).</summary>
        private bool IsTrustedProxy(string peerIp)
        {
            if (string.IsNullOrEmpty(peerIp) || !IPAddress.TryParse(peerIp, out IPAddress peer))
            {
                return false;
            }
            foreach (string entry in _config.TrustedProxies)
            {
                if (IpMatches(peer, entry))
                {
                    return true;
                }
            }
            return false;
        }

        /// <summary>
        /// Matches an address against a trusted-proxy entry that is either a bare IP ("10.0.0.5") or a
        /// CIDR range ("10.0.0.0/24"). Works for both IPv4 and IPv6; a v4/v6 family mismatch never matches.
        /// </summary>
        private static bool IpMatches(IPAddress address, string entry)
        {
            string[] parts = entry.Split('/');
            if (!IPAddress.TryParse(parts[0], out IPAddress network))
            {
                return false;
            }
            byte[] addrBytes = address.GetAddressBytes();
            byte[] netBytes = network.GetAddressBytes();
            if (addrBytes.Length != netBytes.Length)
            {
                return false; // different address families (IPv4 vs IPv6)
            }
            if (parts.Length == 1)
            {
                return addrBytes.SequenceEqual(netBytes);
            }
            if (!int.TryParse(parts[1], out int prefix) || prefix < 0 || prefix > addrBytes.Length * 8)
            {
                return false;
            }
            int fullBytes = prefix / 8;
            for (int i = 0; i < fullBytes; i++)
            {
                if (addrBytes[i] != netBytes[i])
                {
                    return false;
                }
            }
            int remainingBits = prefix % 8;
            if (remainingBits > 0)
            {
                int mask = 0xFF << (8 - remainingBits) & 0xFF;
                if ((addrBytes[fullBytes] & mask) != (netBytes[fullBytes] & mask))
                {
                    return false;
                }
            }
            return true;
        }

        public void OnAuthenticationPipelineLoad(IAuthenticationMethodConfigData configData)
        {
            // EventWarn (not Log) for the secret-at-rest sink: Log writes to the debug file, which is not
            // open yet at this point and only exists when debug_log=1. The event log is always available.
            _config = new Configuration(Log, EventWarn);
            _debugLog = _config.DebugLog;
            Log("PrivacyIDEA AD FS Plugin " + _version + " - OnAuthenticationPipelineLoad");

            if (string.IsNullOrEmpty(_config.Url))
            {
                Error("No server URL configured. Can not initialize privacyIDEA without a server URL.");
                throw new Exception("No server URL configured. Can not initialize privacyIDEA without a server URL.");
            }

            _privacyIDEA = new PrivacyIDEA(_config.Url, "PrivacyIDEA-ADFS/" + _version, !_config.DisableSSL)
            {
                Logger = this,
                LogServerResponse = _config.DebugLog
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

        public void OnAuthenticationPipelineUnload()
        {
            _privacyIDEA?.Dispose();
        }

        public IAdapterPresentation OnError(HttpListenerRequest request, ExternalAuthenticationException ex)
        {
            Log("OnError, ExternalAuthenticationException: " + ex.Message);
            var form = new AdapterPresentationForm()
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

            form.WebAuthnSignRequest = "";
            form.Mode = PITokenType.Otp;
            form.PushAvailable = "0";
            form.EnrollmentImg = "";
            form.EnrollmentLink = "";
            form.DisableOTP = "0";

            form.Message = response.Message;

            string pushMessage = response.PushMessage();
            if (!string.IsNullOrEmpty(pushMessage))
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

            if (form.Mode == PITokenType.WebAuthn && string.IsNullOrEmpty(form.WebAuthnSignRequest))
            {
                form.Mode = PITokenType.Otp;
            }

            // An image on a challenge indicates enroll_via_multichallenge.
            var challengeWithImage = response.Challenges.FirstOrDefault(challenge => !string.IsNullOrEmpty(challenge.Image));
            if (challengeWithImage != null)
            {
                form.EnrollmentImg = challengeWithImage.Image;
                form.EnrollmentLink = response.EnrollmentLink;
                // client_mode=poll (push enrollment, smartphone container enrollment) has no
                // OTP input — the client polls until the phone finishes registration. Route
                // those into the existing push polling path; otherwise key off challenge type.
                if (challengeWithImage.ClientMode == PIClientMode.Poll)
                {
                    form.Mode = PITokenType.Push;
                    form.DisableOTP = "1";
                }
                else
                {
                    form.Mode = challengeWithImage.Type;
                }
            }

            form.EnrollmentOptional = response.EnrollmentOptional ? "1" : "0";

            if (!string.IsNullOrEmpty(response.PasskeyRegistration))
            {
                form.PasskeyRegistration = response.PasskeyRegistration;
                form.PasskeyChallenge = "";
            }

            // Single source of truth across requests: TryEndAuthentication re-parses this to derive
            // transaction IDs, the passkey-registration serial, and to repopulate the form on errors.
            authContext.Data["previousResponse"] = response.Raw;
            return form;
        }

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
            return dict.TryGetValue(key, out object value) ? (string)value : defaultValue;
        }

        private static string Stamp(string message) =>
            "[" + DateTime.Now.ToString("yyyy-MM-ddTHH\\:mm\\:ss") + "] " + message;

        public void Log(string message) => LogImpl(Stamp(message));

        public void Error(string message)
        {
            string formatted = Stamp(message);
            EventError(formatted);
            LogImpl(formatted);
        }

        public void Error(Exception exception) =>
            Error(exception.Message + ":\n" + exception);

        // Cached so each error doesn't reopen the event log. Writes are serialized:
        // EventLog instance members are not guaranteed thread-safe and ADFS calls in from many threads.
        // We log to the standard Windows "Application" log, NOT "AD FS/Admin": the latter is an ETW
        // channel, and addressing it through the classic EventLog API makes Windows create a bogus
        // HKLM\SYSTEM\CurrentControlSet\Services\EventLog\AD FS/Admin key that shadows the channel and
        // breaks AD FS event logging (and Windows Update). The "privacyIDEAProvider" source is
        // registered in the Application log by Install.ps1.
        private static readonly EventLog s_eventLog = new EventLog("Application") { Source = "privacyIDEAProvider" };

        private void EventError(string message) => WriteEvent(message, EventLogEntryType.Error, 9901);

        // Warning-level event-log writes for notable-but-non-fatal conditions, e.g. the one-time
        // migration of a plaintext secret to encrypted-at-rest (and its failures). Independent of the
        // debug log so these are always visible.
        private void EventWarn(string message) => WriteEvent(message, EventLogEntryType.Warning, 9902);

        // Writes are serialized (EventLog instance members are not guaranteed thread-safe and ADFS calls
        // in from many threads) and never throw: logging must not be able to abort provider load or an
        // authentication. WriteEntry can throw (e.g. the source is registered under a different log on a
        // machine the installer hasn't reconciled yet), so swallow it.
        private static void WriteEvent(string message, EventLogEntryType type, int eventId)
        {
            try
            {
                lock (s_eventLog)
                {
                    s_eventLog.WriteEntry(message, type, eventId, 0);
                }
            }
            catch
            {
                // Nothing safe to do here — the event log is our last-resort sink.
            }
        }

        // Serializes writes across concurrent ADFS worker threads; static so all Adapter instances share it.
        private static readonly object _logLock = new object();
        // Tracks whether the last log write failed, so a persistently unwritable log_path produces ONE
        // event-log entry per failure streak instead of one per debug line (which floods the event log).
        // Reset on the first successful write, so logging still self-heals if the path becomes writable.
        private static bool _logWriteFailed;

        public void LogImpl(string msg)
        {
            if (!_debugLog) return;
            lock (_logLock)
            {
                try
                {
                    // Open per write: the file is not held exclusively while AD FS runs (admins can read,
                    // tail, or delete it), and a transient open failure self-heals on the next call.
                    // FileShare allows concurrent readers + deletion; _logLock serializes our own writes.
                    using (var stream = new FileStream(_config.LogPath, FileMode.Append, FileAccess.Write,
                               FileShare.ReadWrite | FileShare.Delete))
                    using (var writer = new StreamWriter(stream))
                    {
                        writer.WriteLine(msg);
                    }
                    _logWriteFailed = false;
                }
                catch (Exception e)
                {
                    // A missing parent directory is the common first-write case for a custom log_path.
                    // Only attempt to create it on the failure path so the happy path stays a plain append
                    // (no per-line directory check). Guard null/empty: GetDirectoryName returns "" for a
                    // bare filename and null for a drive root, and CreateDirectory("") throws.
                    try
                    {
                        string dir = Path.GetDirectoryName(_config.LogPath);
                        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
                        {
                            Directory.CreateDirectory(dir);
                            using (var stream = new FileStream(_config.LogPath, FileMode.Append, FileAccess.Write,
                                       FileShare.ReadWrite | FileShare.Delete))
                            using (var writer = new StreamWriter(stream))
                            {
                                writer.WriteLine(msg);
                            }
                            _logWriteFailed = false;
                            return;
                        }
                    }
                    catch
                    {
                        // Fall through to the error reporting below — the path is genuinely unwritable
                        // (permissions, bad drive, etc.), not merely missing its parent directory.
                    }

                    // Report only the first failure of a streak — otherwise a bad log_path emits one error
                    // event per log line across every worker thread.
                    if (!_logWriteFailed)
                    {
                        _logWriteFailed = true;
                        EventError("Error while writing to logfile (suppressing further log-write errors until it recovers): " + e.Message);
                    }
                }
            }
        }
    }
}
