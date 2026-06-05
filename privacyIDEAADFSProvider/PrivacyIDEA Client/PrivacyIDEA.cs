#nullable enable annotations
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;

namespace PrivacyIDEAADFSProvider.PrivacyIDEA_Client
{
    public class PrivacyIDEA : IDisposable
    {
        public string Url { get; set; } = "";
        public string Realm { get; set; } = "";
        public Dictionary<string, string> RealmMap { get; set; } = new Dictionary<string, string>();

        private readonly bool _sslVerify;
        private readonly string _userAgent;
        private string? _authToken;
        private string? _serviceUser;
        private string? _servicePass;
        private string? _serviceRealm;
        private readonly object _jwtLock = new object();
        private DateTime _jwtExpiry = DateTime.MinValue;
        // When false, suppresses the pretty-printed response log line (which costs a full JToken.Parse + ToString).
        // Adapter ties this to its debug_log registry flag.
        public bool LogServerResponse { get; set; } = true;
        public IPILog? Logger { get; set; }

        // The webauthn parameters should not be url encoded because they already have the correct format.
        // Matched case-insensitively, so the casing of these entries doesn't matter.
        private static readonly HashSet<string> _excludeFromURIEscape = new HashSet<string>(
           new[] { "credentialid", "credential_id", "clientdata", "clientdatajson", "signaturedata", "signature", "authenticatordata",
               "userhandle", "raw_id", "rawid", "assertionclientextensions", "authenticatorattachment", "attestationobject" },
           StringComparer.OrdinalIgnoreCase);

        private static readonly List<string> _logExcludedEndpoints = new List<string>(new string[]
           { "/auth", "/validate/polltransaction" });

        public PrivacyIDEA(string url, string useragent, bool sslVerify = true)
        {
            this.Url = url;
            _userAgent = useragent;
            _sslVerify = sslVerify;

            // HttpWebRequest defaults to 2 connections per host, which would serialize concurrent
            // ADFS worker threads during login storms. Bump it; honor any higher value set elsewhere.
            if (ServicePointManager.DefaultConnectionLimit < 50)
            {
                ServicePointManager.DefaultConnectionLimit = 50;
            }
            // Skip the Expect: 100-continue handshake — adds a round-trip per POST and PI doesn't require it.
            ServicePointManager.Expect100Continue = false;
        }

        /// <summary>
        /// Trigger challenges for the given user using a service account.
        /// </summary>
        public PIResponse TriggerChallenges(string username, PIRequestContext context = null)
        {
            if (!GetJWT())
            {
                Error("Unable to trigger challenges without an auth token!");
                return null;
            }

            var parameters = BuildParameters(new Dictionary<string, string> { { "user", username } }, context);
            string response = SendRequest("/validate/triggerchallenge", parameters, context?.Headers);
            return PIResponse.FromJSON(response, this);
        }

        /// <summary>
        /// Requests a challenge for the given token type. Currently only supports type="passkey".
        /// </summary>
        public PIResponse ValidateInitialize(string type, PIRequestContext context = null)
        {
            // Realm-agnostic by design: a usernameless passkey discovery must not be scoped to a realm
            // (matches the pre-refactor request shape). Custom parameters are still forwarded.
            var parameters = BuildParameters(new Dictionary<string, string> { { "type", type } },
                new PIRequestContext { CustomParameters = context?.CustomParameters });
            string response = SendRequest("/validate/initialize", parameters, context?.Headers, "GET");
            return PIResponse.FromJSON(response, this);
        }

        /// <summary>
        /// Check if the challenge for the given transaction id has been answered yet via /validate/polltransaction.
        /// </summary>
        public bool PollTransaction(string transactionid, PIRequestContext context = null)
        {
            if (string.IsNullOrEmpty(transactionid))
            {
                Error("PollTransaction called with empty transaction id!");
                return false;
            }

            // Poll is keyed by transaction_id alone; do not scope it to a realm (matches the pre-refactor shape).
            var parameters = BuildParameters(new Dictionary<string, string> { { "transaction_id", transactionid } },
                new PIRequestContext { CustomParameters = context?.CustomParameters });
            string response = SendRequest("/validate/polltransaction", parameters, null, "GET");

            if (string.IsNullOrEmpty(response))
            {
                Error("/validate/polltransaction did not respond!");
                return false;
            }
            try
            {
                return (bool)JObject.Parse(response)["result"]["value"];
            }
            catch (Exception)
            {
                Error("/validate/polltransaction response has wrong format or does not contain 'value'.\n" + response);
                return false;
            }
        }

        /// <summary>
        /// Checks if user has existing token. /token/ is an admin endpoint; headers from the context
        /// are not forwarded here (preserves prior behavior where the call was made without ADFS headers).
        /// </summary>
        public bool UserHasToken(string user, PIRequestContext context = null)
        {
            if (!GetJWT())
            {
                Error("Unable to lookup tokens without an auth token!");
                return false;
            }

            var parameters = BuildParameters(new Dictionary<string, string> { { "user", user } }, context);
            string response = SendRequest("/token/", parameters, null, "GET");

            if (string.IsNullOrEmpty(response))
            {
                Error("/token/ did not respond!");
                return false;
            }
            try
            {
                return (int)JObject.Parse(response)["result"]["value"]["count"] != 0;
            }
            catch (Exception)
            {
                Error("/token/ response has wrong format or does not contain 'result.value.count'.\n" + response);
                return false;
            }
        }

        /// <summary>
        /// Enroll TOTP Token for the given user. Like UserHasToken, this is an admin-style call;
        /// headers from the context are not forwarded.
        /// </summary>
        public PIEnrollResponse TokenInit(string user, PIRequestContext context = null)
        {
            var map = new Dictionary<string, string>
            {
                { "user", user },
                { "type", PITokenType.Totp },
                { "genkey", "1" }
            };
            var parameters = BuildParameters(map, context);
            string response = SendRequest("/token/init", parameters, null);
            return PIEnrollResponse.FromJSON(response, this);
        }


        /// <summary>
        /// Authenticate using the /validate/check endpoint with the username and OTP value.
        /// Optionally, a transaction id can be provided if authentication is done using challenge-response.
        /// </summary>
        public PIResponse ValidateCheck(string user, string otp, string transactionid = null, PIRequestContext context = null)
        {
            var map = new Dictionary<string, string>
            {
                { "user", user },
                { "pass", otp }
            };

            if (transactionid != null)
            {
                map.Add("transaction_id", transactionid);
            }

            var parameters = BuildParameters(map, context);
            string response = SendRequest("/validate/check", parameters, context?.Headers);
            return PIResponse.FromJSON(response, this);
        }

        /// <summary>
        /// Cancel an optional enroll-via-multichallenge enrollment for the given transaction id.
        /// The server only honors this when the challenge was emitted with enroll_via_multichallenge_optional=true.
        /// Domain on the context is ignored — cancel must hit whichever realm issued the transaction.
        /// </summary>
        public PIResponse CancelEnrollment(string transactionid, PIRequestContext context = null)
        {
            if (string.IsNullOrEmpty(transactionid))
            {
                Error("CancelEnrollment called with empty transaction id!");
                return null;
            }

            var map = new Dictionary<string, string>
            {
                { "transaction_id", transactionid },
                { "cancel_enrollment", "True" }
            };
            // Pass a context with Domain cleared so BuildParameters does not add a realm.
            var parameters = BuildParameters(map, new PIRequestContext { CustomParameters = context?.CustomParameters });
            string response = SendRequest("/validate/check", parameters, context?.Headers);
            return PIResponse.FromJSON(response, this);
        }

        /// <summary>
        /// Authenticate at /validate/check using a WebAuthn assertion.
        /// </summary>
        public PIResponse ValidateCheckWebAuthn(string user, string transactionid, string webAuthnSignResponse, string origin,
            PIRequestContext context = null)
        {
            if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(transactionid) || string.IsNullOrEmpty(webAuthnSignResponse)
                || string.IsNullOrEmpty(origin))
            {
                Log("ValidateCheckWebAuthn called with missing parameter: user=" + user + ", transactionid=" + transactionid
                    + ", WebAuthnSignResponse=" + webAuthnSignResponse + ", origin=" + origin);
                return null;
            }

            var parameters = new Dictionary<string, string>
            {
                { "user", user },
                { "pass", "" }
            };
            return FIDO2AuthenticationRequest(parameters, transactionid, webAuthnSignResponse, origin, context);
        }

        /// <summary>
        /// Authenticate at /validate/check using a Passkey. Requires prior triggering of a challenge via ValidateInitialize.
        /// </summary>
        public PIResponse ValidateCheckPasskey(string transactionid, string assertionResponse, string origin, PIRequestContext context = null)
        {
            if (string.IsNullOrEmpty(transactionid) || string.IsNullOrEmpty(assertionResponse) || string.IsNullOrEmpty(origin))
            {
                Log("ValidateCheckPasskey called with missing parameter: transactionid=" + transactionid
                    + ", assertionResponse=" + assertionResponse + ", origin=" + origin);
                return null;
            }
            return FIDO2AuthenticationRequest(new Dictionary<string, string>(), transactionid, assertionResponse, origin, context);
        }

        /// <summary>
        /// Completes the passkey registration at the /validate/check endpoint.
        /// </summary>
        public PIResponse ValidateCheckCompletePasskeyRegistration(string transactionid, string serial, string username,
            string attestationResponse, string origin, PIRequestContext context = null)
        {
            if (string.IsNullOrEmpty(transactionid) || string.IsNullOrEmpty(serial) || string.IsNullOrEmpty(username)
                || string.IsNullOrEmpty(attestationResponse) || string.IsNullOrEmpty(origin))
            {
                Log("ValidateCheckCompletePasskeyRegistration called with missing parameter: transactionid=" + transactionid
                    + ", serial=" + serial + ", username=" + username + ", attestationResponse=" + attestationResponse
                    + ", origin=" + origin);
                return null;
            }

            var map = new Dictionary<string, string>
            {
                { "type", PITokenType.Passkey },
                { "serial", serial },
                { "user", username },
                { "transaction_id", transactionid }
            };

            var parsedResponse = ParseFIDO2AttestationResponse(attestationResponse);
            if (parsedResponse != null)
            {
                foreach (var entry in parsedResponse)
                {
                    map.Add(entry.Key, entry.Value);
                }
            }

            var parameters = BuildParameters(map, context);
            string response = SendRequest("/validate/check", parameters, HeadersWithOrigin(origin, context));
            return PIResponse.FromJSON(response, this);
        }

        /// <summary>
        /// Builds the /validate/check call shared by ValidateCheckWebAuthn and ValidateCheckPasskey:
        /// merges the parsed assertion fields into the request body, sets the transaction id, applies the
        /// context's realm and custom parameters, and attaches the Origin header (required by FIDO2).
        /// </summary>
        private PIResponse FIDO2AuthenticationRequest(Dictionary<string, string> parameters, string transactionid,
            string assertionResponse, string origin, PIRequestContext context)
        {
            var parsed = ParseFIDO2AssertionResponse(assertionResponse);
            if (parsed == null)
            {
                return null;
            }
            foreach (var entry in parsed)
            {
                parameters.Add(entry.Key, entry.Value);
            }
            parameters.Add("transaction_id", transactionid);

            AddRealmForDomain(context?.Domain, parameters);
            AddCustomParameters(context?.CustomParameters, parameters);

            string response = SendRequest("/validate/check", parameters, HeadersWithOrigin(origin, context));
            return PIResponse.FromJSON(response, this);
        }

        private static List<KeyValuePair<string, string>> HeadersWithOrigin(string origin, PIRequestContext context)
        {
            var h = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("Origin", origin)
            };
            if (context?.Headers != null)
            {
                h.AddRange(context.Headers);
            }
            return h;
        }

        // FIDO2 assertion (WebAuthn / passkey login): each output key accepts a camelCase or lowercase
        // input alias, so the browser-side naming differences resolve to one canonical request field.
        private static readonly (string outKey, string[] inKeys)[] _fido2AssertionFields =
        {
            ("credential_id", new[] { "credential_id", "credentialid" }),
            ("clientDataJSON", new[] { "clientDataJSON", "clientdata" }),
            ("signature", new[] { "signature", "signaturedata" }),
            ("authenticatorData", new[] { "authenticatorData", "authenticatordata" }),
            ("userHandle", new[] { "userHandle", "userhandle" }),
            // TODO clientassertionextensions are currently not supported
        };

        // FIDO2 attestation (passkey registration): only the canonical key is accepted for each field.
        private static readonly (string outKey, string[] inKeys)[] _fido2AttestationFields =
        {
            ("credential_id", new[] { "credential_id" }),
            ("clientDataJSON", new[] { "clientDataJSON" }),
            ("attestationObject", new[] { "attestationObject" }),
            ("rawId", new[] { "rawId" }),
            ("authenticatorAttachment", new[] { "authenticatorAttachment" }),
        };

        private Dictionary<string, string> ParseFIDO2AssertionResponse(string assertionResponse) =>
            ParseFIDO2Response(assertionResponse, "AssertionResponse", _fido2AssertionFields);

        private Dictionary<string, string> ParseFIDO2AttestationResponse(string attestationResponse) =>
            ParseFIDO2Response(attestationResponse, "AttestationResponse", _fido2AttestationFields);

        /// <summary>
        /// Parses a FIDO2 response (assertion or attestation) from the browser and extracts the required
        /// parameters according to the given field map. Returns null if the input is not valid JSON.
        /// </summary>
        private Dictionary<string, string> ParseFIDO2Response(string json, string label,
            (string outKey, string[] inKeys)[] fields)
        {
            JToken root;
            try
            {
                root = JToken.Parse(json);
            }
            catch (JsonReaderException jex)
            {
                Error(label + " does not have the required format (json)! " + jex.Message);
                return null;
            }

            var parameters = new Dictionary<string, string>();
            foreach (var (outKey, inKeys) in fields)
            {
                if (GetJTokenFirstOf(root, inKeys) is JToken token)
                {
                    parameters.Add(outKey, (string)token);
                }
            }
            return parameters;
        }

        /// <summary>
        /// Gets the first JToken found for the given list of keys.
        /// </summary>
        private JToken GetJTokenFirstOf(JToken root, string[] keys)
        {
            foreach (var key in keys)
            {
                if (root[key] is JToken token)
                {
                    return token;
                }
            }
            return null;
        }

        /// <summary>
        /// Fetches an auth token from the privacyIDEA server using the service account and caches
        /// it as the Authorization header value for subsequent calls until the JWT's exp claim
        /// (minus a 30-second safety margin) is reached.
        /// </summary>
        private bool GetJWT()
        {
            // Fast path: cached token still valid.
            if (DateTime.UtcNow < _jwtExpiry && !string.IsNullOrEmpty(_authToken))
            {
                return true;
            }

            if (!ServiceAccountAvailable())
            {
                Error("Unable to fetch auth token without service account!");
                return false;
            }

            lock (_jwtLock)
            {
                // Another thread may have refreshed while we were waiting on the lock
                if (DateTime.UtcNow < _jwtExpiry && !string.IsNullOrEmpty(_authToken))
                {
                    return true;
                }

                var map = new Dictionary<string, string>
                {
                    { "username", _serviceUser },
                    { "password", _servicePass }
                };

                if (!string.IsNullOrEmpty(_serviceRealm))
                {
                    map.Add("realm", _serviceRealm);
                }
                var parameters = BuildParameters(map, null);

                string response = SendRequest("/auth", parameters);

                if (string.IsNullOrEmpty(response))
                {
                    Error("/auth did not respond!");
                    return false;
                }

                string token = "";
                try
                {
                    token = (string)JObject.Parse(response)["result"]["value"]["token"];
                }
                catch (Exception)
                {
                    Error("/auth response did not have the correct format or did not contain a token.\n" + response);
                }

                if (!string.IsNullOrEmpty(token))
                {
                    // PI expects the JWT as the bare Authorization header value (no "Bearer" prefix),
                    // matching how the previous HttpClient code stored it via AuthenticationHeaderValue(token).
                    _authToken = token;
                    _jwtExpiry = ExtractJWTExpiry(token).AddSeconds(-30);
                    return true;
                }
                return false;
            }
        }

        /// <summary>
        /// Decode the JWT payload and return its `exp` claim as UTC. Falls back to a 5-minute window if parsing fails.
        /// </summary>
        private DateTime ExtractJWTExpiry(string token)
        {
            try
            {
                var parts = token.Split('.');
                if (parts.Length >= 2)
                {
                    string payload = parts[1].Replace('-', '+').Replace('_', '/');
                    payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
                    string json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
                    if (JObject.Parse(json)["exp"] is JToken exp && exp.Type == JTokenType.Integer)
                    {
                        return DateTimeOffset.FromUnixTimeSeconds((long)exp).UtcDateTime;
                    }
                }
            }
            catch (Exception e)
            {
                Error("Failed to parse JWT exp claim: " + e.Message);
            }
            return DateTime.UtcNow.AddMinutes(5);
        }

        /// <summary>
        /// Sets the service account credentials to be used for authentication.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="pass"></param>
        /// <param name="realm"></param>
        public void SetServiceAccount(string user, string pass, string realm = "")
        {
            _serviceUser = user;
            _servicePass = pass;
            if (!string.IsNullOrEmpty(realm))
            {
                _serviceRealm = realm;
            }
        }

        /// <summary>
        /// Sends a request to the privacyIDEA server. Synchronous on purpose: ADFS's IAuthenticationAdapter
        /// contract is sync, and HttpWebRequest doesn't pin a continuation thread per call the way
        /// HttpClient.SendAsync().GetAwaiter().GetResult() does.
        /// </summary>
        private string SendRequest(string endpoint, Dictionary<string, string> parameters, List<KeyValuePair<string, string>> headers = null, string method = "POST")
        {
            // Guard the string-building: ParametersForLog allocates and iterates every parameter, and this
            // runs on every request. LogServerResponse mirrors debug_log, so when debugging is off we skip
            // the work entirely instead of composing a string the logger would discard.
            if (LogServerResponse)
            {
                Log("Sending [" + ParametersForLog(parameters) + "] to [" + endpoint + "] with method [" + method + "]");
            }

            string body = BuildFormBody(parameters);
            string url = this.Url + endpoint + (method == "POST" ? "" : "?" + body);

            HttpWebRequest request;
            try
            {
                request = (HttpWebRequest)WebRequest.Create(url);
            }
            catch (Exception e)
            {
                Error("Failed to build request for " + endpoint + ": " + e.Message);
                return "";
            }

            request.Method = method;
            request.UserAgent = _userAgent;
            if (!_sslVerify)
            {
                request.ServerCertificateValidationCallback = (s, c, ch, errs) => true;
            }
            if (!string.IsNullOrEmpty(_authToken))
            {
                request.Headers["Authorization"] = _authToken;
            }
            if (headers != null)
            {
                foreach (var h in headers)
                {
                    try
                    {
                        SetForwardedHeader(request, h.Key, h.Value);
                    }
                    catch (Exception e)
                    {
                        // Restricted headers (Host, Connection, Date, Referer, Range, ...) throw when set on
                        // HttpWebRequest. Skip the offending one rather than failing the whole authentication.
                        Error("Could not forward header '" + h.Key + "': " + e.Message);
                    }
                }
            }

            if (LogServerResponse)
            {
                Log("Headers: " + FormatHeadersForLog(request.Headers));
            }

            if (method == "POST")
            {
                byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
                request.ContentType = "application/x-www-form-urlencoded; charset=utf-8";
                request.ContentLength = bodyBytes.Length;
                try
                {
                    using (var stream = request.GetRequestStream())
                    {
                        stream.Write(bodyBytes, 0, bodyBytes.Length);
                    }
                }
                catch (Exception e)
                {
                    Error("Failed to write request body for " + endpoint + ": " + e.Message);
                    return "";
                }
            }

            HttpWebResponse response;
            try
            {
                response = (HttpWebResponse)request.GetResponse();
            }
            catch (WebException ex) when (ex.Response is HttpWebResponse errResp)
            {
                // Non-2xx — preserve the old behavior of logging the status and parsing whatever body came back.
                Error("The request to " + endpoint + " returned HttpStatusCode " + errResp.StatusCode);
                response = errResp;
            }
            catch (Exception e)
            {
                Error("Request to " + endpoint + " failed: " + e.Message);
                return "";
            }

            string ret = "";
            try
            {
                using (response)
                using (var stream = response.GetResponseStream())
                using (var reader = new StreamReader(stream))
                {
                    ret = reader.ReadToEnd();
                }
            }
            catch (Exception e)
            {
                Error(e.Message);
            }

            if (LogServerResponse && !string.IsNullOrEmpty(ret) && !_logExcludedEndpoints.Contains(endpoint))
            {
                try
                {
                    Log(endpoint + " response:\n" + JToken.Parse(ret).ToString(Formatting.Indented));
                }
                catch (JsonReaderException)
                {
                    // Non-JSON body (e.g. an HTML error page from a reverse proxy/WAF) — log it raw, don't crash.
                    Log(endpoint + " response (non-JSON):\n" + ret);
                }
            }

            return ret;
        }

        /// <summary>
        /// Restricted headers on HttpWebRequest must go through specific properties rather than the Headers collection.
        /// Only User-Agent and Accept are realistic candidates among the forward_headers config.
        /// </summary>
        private static void SetForwardedHeader(HttpWebRequest request, string name, string value)
        {
            if (name.Equals("User-Agent", StringComparison.OrdinalIgnoreCase))
            {
                request.UserAgent = value;
            }
            else if (name.Equals("Accept", StringComparison.OrdinalIgnoreCase))
            {
                request.Accept = value;
            }
            else
            {
                request.Headers[name] = value;
            }
        }

        /// <summary>
        /// Same shape as the old HttpRequestMessage.Headers.ToString(), but redacts Authorization so the JWT
        /// doesn't end up in the debug log (HttpClient kept Authorization on DefaultRequestHeaders, which the
        /// per-request log line did not cover — preserve that masking behavior).
        /// </summary>
        private static string FormatHeadersForLog(WebHeaderCollection headers)
        {
            var sb = new StringBuilder();
            foreach (string key in headers)
            {
                sb.Append(key).Append(": ");
                sb.Append(key.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ? "***" : headers[key]);
                sb.Append("\r\n");
            }
            return sb.ToString();
        }

        /// <summary>
        /// Evaluates which realm to use for a given domain and adds it to the parameter dictionary.
        /// The realm mapping takes precedence over the general realm that can be set. If no realm is found, the parameter is omitted.
        /// </summary>
        /// <param name="domain"></param>
        /// <param name="parameters"></param>
        private void AddRealmForDomain(string domain, Dictionary<string, string> parameters)
        {
            if (!string.IsNullOrEmpty(domain))
            {
                string r = "";
                // RealmMap is built with an OrdinalIgnoreCase comparer (see RegistryReader.GetRealmMapping),
                // so the lookup is case-insensitive without uppercasing the domain here.
                if (RealmMap.TryGetValue(domain, out string mapped))
                {
                    r = mapped;
                    Log("Found realm in mapping: " + r);
                }

                if (string.IsNullOrEmpty(r) && !string.IsNullOrEmpty(Realm))
                {
                    r = Realm;
                }

                if (!string.IsNullOrEmpty(r))
                {
                    parameters.Add("realm", r);
                }
                else
                {
                    Log("No realm configured for domain " + domain);
                }
            }
            else
            {
                if (!string.IsNullOrEmpty(Realm))
                {
                    parameters.Add("realm", Realm);
                }
            }
        }

        /// <summary>
        /// Adds custom parameters to request.
        /// </summary>
        /// <param name="customParameters">Dictionary of custom parameters to add.</param>
        /// <param name="parameters">The dictionary to add the parameters to.</param>
        private static void AddCustomParameters(Dictionary<string, string>? customParameters, Dictionary<string, string> parameters)
        {
            if (customParameters == null) return;
            foreach (var attribute in customParameters)
            {
                parameters[attribute.Key] = attribute.Value;
            }
        }

        /// <summary>
        /// Helper to build the request body dictionary: starts from baseParams, merges in the realm
        /// (derived from context.Domain) and any custom parameters the caller threaded through.
        /// AddRealmForDomain is skipped when Domain is empty so callers that already populated "realm"
        /// in baseParams (e.g. GetJWT with _serviceRealm) don't hit a duplicate-key add.
        /// </summary>
        private Dictionary<string, string> BuildParameters(Dictionary<string, string> baseParams, PIRequestContext context)
        {
            var parameters = new Dictionary<string, string>(baseParams);
            if (!string.IsNullOrEmpty(context?.Domain))
            {
                AddRealmForDomain(context.Domain, parameters);
            }
            AddCustomParameters(context?.CustomParameters, parameters);
            return parameters;
        }

        /// <summary>
        /// Builds the parameter list for the request log, masking secrets. "password" is the service
        /// account password; "pass" is the user's credential on /validate/check and in privacyIDEA carries
        /// the static PIN prefix in front of the OTP — neither must reach the (possibly long-lived) debug log.
        /// </summary>
        private static readonly HashSet<string> _maskedLogParameters =
            new HashSet<string>(StringComparer.Ordinal) { "password", "pass" };

        private static string ParametersForLog(Dictionary<string, string> parameters)
        {
            var sb = new StringBuilder();
            bool first = true;
            foreach (var kv in parameters)
            {
                if (!first) sb.Append(" , ");
                first = false;
                sb.Append('[').Append(kv.Key).Append(", ");
                sb.Append(_maskedLogParameters.Contains(kv.Key) ? "***" : kv.Value);
                sb.Append(']');
            }
            return sb.ToString();
        }

        /// <summary>
        /// URL-encodes a dictionary as an application/x-www-form-urlencoded body string.
        /// Keys in _excludeFromURIEscape are passed through unescaped (WebAuthn/FIDO2 fields
        /// already have the correct on-wire format).
        /// </summary>
        internal string BuildFormBody(Dictionary<string, string> dict)
        {
            StringBuilder sb = new StringBuilder();
            foreach (var element in dict)
            {
                sb.Append(element.Key).Append("=");
                sb.Append(_excludeFromURIEscape.Contains(element.Key) ? element.Value : Uri.EscapeDataString(element.Value));
                sb.Append("&");
            }
            if (sb.Length > 0)
            {
                sb.Remove(sb.Length - 1, 1);
            }
            return sb.ToString();
        }

        /// <summary>
        /// Checks if the service account credentials are available.
        /// </summary>
        /// <returns></returns>
        internal bool ServiceAccountAvailable()
        {
            return !string.IsNullOrEmpty(_serviceUser) && !string.IsNullOrEmpty(_servicePass);
        }

        internal void Log(string message)
        {
            this.Logger?.Log(message);
        }

        internal void Error(string message)
        {
            this.Logger?.Error(message);
        }

        internal void Error(Exception exception)
        {
            this.Logger?.Error(exception);
        }

        public void Dispose()
        {
            // Nothing to release: HttpWebRequest is created per-call and TCP sockets are managed
            // by ServicePointManager. IDisposable kept on the class for API compatibility.
            GC.SuppressFinalize(this);
        }
    }
}
