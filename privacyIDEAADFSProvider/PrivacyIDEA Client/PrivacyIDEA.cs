using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using static PrivacyIDEAADFSProvider.PrivacyIDEA_Client.PIConstants;

namespace PrivacyIDEAADFSProvider.PrivacyIDEA_Client
{
    public class PrivacyIDEA : IDisposable
    {
        public string Url { get; set; } = "";
        public string Realm { get; set; } = "";
        public Dictionary<string, string> RealmMap { get; set; } = new Dictionary<string, string>();

        private bool _sslVerify = true;
        public bool SSLVerify
        {
            get
            {
                return _sslVerify;
            }
            set
            {
                if (SSLVerify != _sslVerify)
                {
                    _httpClientHandler = new HttpClientHandler();
                    if (!SSLVerify)
                    {
                        _httpClientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                        _httpClientHandler.ServerCertificateCustomValidationCallback =
                            HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                    }
                    _httpClient = new HttpClient(_httpClientHandler);
                    _httpClient.DefaultRequestHeaders.Add(USER_AGENT, _userAgent);
                    _sslVerify = SSLVerify;
                }
            }
        }

        private HttpClientHandler _httpClientHandler;
        private HttpClient _httpClient;
        private bool _disposedValue;
        private string _serviceUser;
        private string _servicePass;
        private string _serviceRealm;
        private readonly string _userAgent;
        private readonly bool _logServerResponse = true;
        public IPILog Logger { get; set; } = null;

        // The webauthn parameters should not be url encoded because they already have the correct format.
        // Comparison is done in lower case, so add them there in lower case
        private static readonly List<string> _excludeFromURIEscape = new List<string>(new string[]
           { CREDENTIALID, CREDENTIAL_ID, CLIENTDATA, CLIENTDATAJSON, SIGNATUREDATA, SIGNATURE, AUTHENTICATORDATA,
               USERHANDLE, RAW_ID, RAWID, ASSERTIONCLIENTEXTENSIONS, AUTHENTICATORATTACHMENT, ATTESTATIONOBJECT });

        private static readonly List<string> _logExcludedEndpoints = new List<string>(new string[]
           { AUTH_ENDPOINT, POLLTRANSACTION_ENDPOINT });

        public PrivacyIDEA(string url, string useragent, bool sslVerify = true)
        {
            this.Url = url;
            this._userAgent = useragent;

            _httpClientHandler = new HttpClientHandler();
            if (!sslVerify)
            {
                _httpClientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                _httpClientHandler.ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            }
            _httpClient = new HttpClient(_httpClientHandler);
            _httpClient.DefaultRequestHeaders.Add(USER_AGENT, useragent);
        }

        /// <summary>
        /// Trigger challenges for the given user using a service account.
        /// </summary>
        /// <param name="username">username to trigger challenges for</param>
        /// <param name="domain">optional domain which can be mapped to a privacyIDEA realm</param>
        /// <param name="headers">optional headers which can be forwarded to the privacyIDEA server</param>
        /// <param name="customParameters">Dictionary of custom parameters to add</param>
        /// <returns>PIResponse object or null on error</returns>
        public PIResponse TriggerChallenges(string username, string domain = null,
            List<KeyValuePair<string, string>> headers = null, Dictionary<string, string> customParameters = null)
        {
            if (!GetJWT())
            {
                Error("Unable to trigger challenges without an auth token!");
                return null;
            }

            var parameters = BuildParameters(new Dictionary<string, string> { { USER, username } }, domain, customParameters);
            string response = SendRequest(TRIGGERCHALLENGE_ENDPOINT, parameters, headers);
            PIResponse ret = PIResponse.FromJSON(response, this);

            return ret;
        }

        /// <summary>
        /// Requests a challenge for the given token type. Currently only supports type="passkey".
        /// </summary>
        /// <param name="type"></param>
        /// <param name="headers"></param>
        /// <param name="customParameters">Dictionary of custom parameters to add</param>
        /// <returns>PIResponse object or null on error</returns>
        public PIResponse ValidateInitialize(string type, List<KeyValuePair<string, string>> headers = null, Dictionary<string, string> customParameters = null)
        {
            var parameters = BuildParameters(new Dictionary<string, string> { { TYPE, type } }, "", customParameters);
            string response = SendRequest(VALIDATE_INITIALIZE_ENDPOINT, parameters, headers, GET);
            return PIResponse.FromJSON(response, this);
        }

        /// <summary>
        /// Check if the challenge for the given transaction id has been answered yet. 
        /// This is done using the /validate/polltransaction endpoint.
        /// </summary>
        /// <param name="transactionid"></param>
        /// <param name="customParameters">Dictionary of custom parameters to add</param>
        /// <returns>true if challenge was answered. false if not or error</returns>
        public bool PollTransaction(string transactionid, Dictionary<string, string> customParameters = null)
        {
            if (!string.IsNullOrEmpty(transactionid))
            {
                var parameters = BuildParameters(new Dictionary<string, string> { { TRANSACTION_ID, transactionid } }, "", customParameters);
                string response = SendRequest(POLLTRANSACTION_ENDPOINT, parameters, new List<KeyValuePair<string, string>>(), GET);

                if (string.IsNullOrEmpty(response))
                {
                    Error("/validate/polltransaction did not respond!");
                    return false;
                }
                bool ret = false;
                try
                {
                    dynamic root = JsonConvert.DeserializeObject(response);
                    ret = (bool)root.result.value;
                }
                catch (Exception)
                {
                    Error("/validate/polltransaction response has wrong format or does not contain 'value'.\n" + response);
                }

                return ret;
            }
            Error("PollTransaction called with empty transaction id!");
            return false;
        }

        /// <summary>
        /// Checks if user has existing token
        /// </summary>
        /// <param name="user">username</param>
        /// <param name="domain">optional domain which can be mapped to a privacyIDEA realm</param>
        /// <param name="customParameters">Dictionary of custom parameters to add</param>
        /// <returns>true if token exists. false if not or error</returns>
        public bool UserHasToken(string user, string domain = null, Dictionary<string, string> customParameters = null)
        {
            if (!GetJWT())
            {
                Error("Unable to lookup tokens without an auth token!");
                return false;
            }

            var parameters = BuildParameters(new Dictionary<string, string> { { USER, user } }, domain, customParameters);
            string response = SendRequest(TOKEN_ENDPOINT, parameters, new List<KeyValuePair<string, string>>(), GET);

            if (string.IsNullOrEmpty(response))
            {
                Error("/token/ did not respond!");
                return false;
            }
            bool ret = false;
            try
            {
                dynamic root = JsonConvert.DeserializeObject(response);
                ret = root.result.value.count != 0;
            }
            catch (Exception)
            {
                Error("/token/ response has wrong format or does not contain 'result.value.count'.\n" + response);
            }
            return ret;
        }

        /// <summary>
        /// Enroll TOTP Token for specified user if user does not already have token
        /// </summary>
        /// <param name="user">username</param>
        /// <param name="domain">optional domain which can be mapped to a privacyIDEA realm</param>
        /// <param name="customParameters">Dictionary of custom parameters to add</param>
        /// <returns>PIEnrollResponse object or null on error</returns>
        public PIEnrollResponse TokenInit(string user, string domain = null, Dictionary<string, string> customParameters = null)
        {
            var map = new Dictionary<string, string>
            {
                { USER, user },
                { TYPE, TOTP },
                { GENKEY, "1" }
            };
            var parameters = BuildParameters(map, domain, customParameters);
            string response = SendRequest(TOKEN_INIT_ENDPOINT, parameters, new List<KeyValuePair<string, string>>());
            return PIEnrollResponse.FromJSON(response, this);
        }


        /// <summary>
        /// Authenticate using the /validate/check endpoint with the username and OTP value. 
        /// Optionally, a transaction id can be provided if authentication is done using challenge-response.
        /// </summary>
        /// <param name="user">username</param>
        /// <param name="otp">OTP</param>
        /// <param name="transactionid">optional transaction id to refer to a challenge</param>
        /// <param name="domain">optional domain which can be mapped to a privacyIDEA realm</param>
        /// <param name="headers">optional headers which can be forwarded to the privacyIDEA server</param>
        /// <param name="customParameters">Dictionary of custom parameters to add</param>
        /// <returns>PIResponse object or null on error</returns>
        public PIResponse ValidateCheck(string user, string otp, string transactionid = null, string domain = null,
            List<KeyValuePair<string, string>> headers = null, Dictionary<string, string> customParameters = null)
        {
            var map = new Dictionary<string, string>
            {
                { USER, user },
                { PASS, otp }
            };

            if (transactionid != null)
            {
                map.Add(TRANSACTION_ID, transactionid);
            }
            
            var parameters = BuildParameters(map, domain, customParameters);
            string response = SendRequest(VALIDATE_CHECK_ENDPOINT, parameters, headers);
            return PIResponse.FromJSON(response, this);
        }

        /// <summary>
        /// Authenticate at the /validate/check endpoint using a WebAuthn token instead of the usual OTP value.
        /// This requires the WebAuthnSignResponse and the Origin from the browser.
        /// </summary>
        /// <param name="user">username</param>
        /// <param name="transactionid">transaction id of the webauthn challenge</param>
        /// <param name="webAuthnSignResponse">the WebAuthnSignResponse string in json format as returned from the browser</param>
        /// <param name="origin">origin also returned by the browser</param>
        /// <param name="domain">optional domain which can be mapped to a privacyIDEA realm</param>
        /// <param name="headers">optional headers which can be forwarded to the privacyIDEA server</param>
        /// <param name="customParameters">Dictionary of custom parameters to add</param>
        /// <returns>PIResponse object or null on error</returns>
        public PIResponse ValidateCheckWebAuthn(string user, string transactionid, string webAuthnSignResponse, string origin,
            string domain = null, List<KeyValuePair<string, string>> headers = null, Dictionary<string, string> customParameters = null)
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
                { USER, user },
                { PASS, "" }
            };
            AddCustomParameters(customParameters, parameters);

            return FIDO2AuthenticationRequest(parameters, transactionid, webAuthnSignResponse, origin, domain, headers);
        }

        /// <summary>
        /// Authenticate at the /validate/check endpoint using a Passkey. Requires prior triggering of a challenge using ValidateInitialize.
        /// </summary>
        /// <param name="transactionid">Transaction id of the challenge</param>
        /// <param name="assertionResponse">As returned from the authenticator, in json format.</param>
        /// <param name="origin">Origin as returned by the browser. Will be added as Origin Header.</param>
        /// <param name="domain">Optional domain of the user</param>
        /// <param name="headers">Optional headers to add to the request</param>
        /// <param name="customParameters">Dictionary of custom parameters to add</param>
        /// <returns></returns>
        public PIResponse ValidateCheckPasskey(string transactionid, string assertionResponse, string origin, string domain = null,
            List<KeyValuePair<string, string>> headers = null, Dictionary<string, string> customParameters = null)
        {
            if (string.IsNullOrEmpty(transactionid) || string.IsNullOrEmpty(assertionResponse) || string.IsNullOrEmpty(origin))
            {
                Log("ValidateCheckPasskey called with missing parameter: transactionid=" + transactionid
                    + ", assertionResponse=" + assertionResponse + ", origin=" + origin);
                return null;
            }
            var parameters = new Dictionary<string, string>();
            AddCustomParameters(customParameters, parameters);

            return FIDO2AuthenticationRequest(parameters, transactionid, assertionResponse, origin, domain, headers);
        }

        /// <summary>
        /// Completes the passkey registration at the /validate/check endpoint.
        /// </summary>
        /// <param name="transactionid"></param>
        /// <param name="serial"></param>
        /// <param name="username"></param>
        /// <param name="attestationResponse"></param>
        /// <param name="origin"></param>
        /// <param name="domain"></param>
        /// <param name="headers"></param>
        /// <param name="customParameters">Dictionary of custom parameters to add</param>
        /// <returns></returns>
        public PIResponse ValidateCheckCompletePasskeyRegistration(string transactionid, string serial, string username,
            string attestationResponse, string origin, string domain = null, List<KeyValuePair<string, string>> headers = null,
            Dictionary<string, string> customParameters = null)
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
                { TYPE, TOKEN_TYPE_PASSKEY },
                { SERIAL, serial },
                { USER, username },
                { TRANSACTION_ID, transactionid }
            };

            var parsedResponse = ParseFIDO2AttestationResponse(attestationResponse);
            if (parsedResponse != null)
            {
                foreach (var entry in parsedResponse)
                {
                    map.Add(entry.Key, entry.Value);
                }
            }

            var parameters = BuildParameters(map, domain, customParameters);

            var h = new List<KeyValuePair<string, string>>()
            {
                new KeyValuePair<string, string>(ORIGIN, origin)
            };

            if (headers is { })
            {
                h.AddRange(headers);
            }
            string response = SendRequest(VALIDATE_CHECK_ENDPOINT, parameters, h);
            return PIResponse.FromJSON(response, this);
        }

        /// <summary>
        /// Cancels an ongoing enrollment process at the /validate/check endpoint.
        /// </summary>
        /// <param name="transactionid"></param>
        /// <param name="domain"></param>
        /// <param name="headers"></param>
        /// <param name="customParameters"></param>
        /// <returns></returns>
        public PIResponse ValidateCheckCancelEnrollment(string transactionid, string domain = null,
            List<KeyValuePair<string, string>> headers = null, Dictionary<string, string> customParameters = null)
        {
            var map = new Dictionary<string, string>
            {
                { TRANSACTION_ID, transactionid },
                { CANCEL_ENROLLMENT, "true" }
            };
            var parameters = BuildParameters(map, domain, customParameters);
            string response = SendRequest(VALIDATE_CHECK_ENDPOINT, parameters, headers);
            return PIResponse.FromJSON(response, this);
        }

        /// <summary>
        /// Initiates the FIDO2 authentication request.
        /// </summary>
        /// <param name="parameters"></param>
        /// <param name="transactionid"></param>
        /// <param name="assertionResponse"></param>
        /// <param name="origin"></param>
        /// <param name="domain"></param>
        /// <param name="headers"></param>
        /// <param name="customParameters"></param>
        /// <returns></returns>
        private PIResponse FIDO2AuthenticationRequest(Dictionary<string, string> parameters, string transactionid, string assertionResponse,
            string origin, string domain = null, List<KeyValuePair<string, string>> headers = null, Dictionary<string, string> customParameters = null)
        {
            foreach (var entry in ParseFIDO2AssertionResponse(assertionResponse))
            {
                parameters.Add(entry.Key, entry.Value);
            }
            parameters.Add(TRANSACTION_ID, transactionid);

            var h = new List<KeyValuePair<string, string>>()
            {
                new KeyValuePair<string, string>(ORIGIN, origin)
            };

            if (headers is { })
            {
                h.AddRange(headers);
            }

            AddRealmForDomain(domain, parameters);
            AddCustomParameters(customParameters, parameters);

            // The origin has to be set in the header for FIDO2 authentication
            headers.Add(new KeyValuePair<string, string>(ORIGIN, origin));

            string response = SendRequest(VALIDATE_CHECK_ENDPOINT, parameters, headers);
            return PIResponse.FromJSON(response, this);
        }

        /// <summary>
        /// Parses the FIDO2 assertion response from the browser and extracts the required parameters.
        /// </summary>
        /// <param name="assertionResponse"></param>
        /// <returns></returns>
        private Dictionary<string, string> ParseFIDO2AssertionResponse(string assertionResponse)
        {
            var parameters = new Dictionary<string, string>();
            // Parse the WebAuthnSignResponse and add mandatory parameters
            JToken root;
            try
            {
                root = JToken.Parse(assertionResponse);
            }
            catch (JsonReaderException jex)
            {
                Error("AssertionResponse does not have the required format (json)! " + jex.Message);
                return null;
            }

            if (GetJTokenFirstOf(root, new List<string>() { CREDENTIAL_ID, CREDENTIALID }) is JToken credential_id)
            {
                parameters.Add(CREDENTIAL_ID, (string)credential_id);
            }
            if (GetJTokenFirstOf(root, new List<string>() { CLIENTDATAJSON_CAM, CLIENTDATA }) is JToken clientDataJSON)
            {
                parameters.Add(CLIENTDATAJSON_CAM, (string)clientDataJSON);
            }
            if (GetJTokenFirstOf(root, new List<string>() { SIGNATURE, SIGNATUREDATA }) is JToken signature)
            {
                parameters.Add(SIGNATURE, (string)signature);
            }
            if (GetJTokenFirstOf(root, new List<string>() { AUTHENTICATORDATA_CAM, AUTHENTICATORDATA }) is JToken authenticatorData)
            {
                parameters.Add(AUTHENTICATORDATA_CAM, (string)authenticatorData);
            }
            if (GetJTokenFirstOf(root, new List<string>() { USERHANDLE_CAM, USERHANDLE }) is JToken userHandle)
            {
                parameters.Add(USERHANDLE_CAM, (string)userHandle);
            }
            // TODO clientassertionextensions are currently not supported

            return parameters;
        }

        /// <summary>
        /// Gets the first JToken found for the given list of keys.
        /// </summary>
        /// <param name="root"></param>
        /// <param name="keys"></param>
        /// <returns></returns>
        private JToken GetJTokenFirstOf(JToken root, List<string> keys)
        {
            JToken ret = null;
            foreach (var key in keys)
            {
                if (root[key] is JToken token)
                {
                    ret = token;
                    break;
                }
            }
            return ret;
        }

        /// <summary>
        /// Parses the FIDO2 attestation response from the browser and extracts the required parameters.
        /// </summary>
        /// <param name="attestationResponse"></param>
        /// <returns></returns>
        private Dictionary<string, string> ParseFIDO2AttestationResponse(string attestationResponse)
        {
            var parameters = new Dictionary<string, string>();
            JToken root;
            try
            {
                root = JToken.Parse(attestationResponse);
            }
            catch (JsonReaderException jex)
            {
                Error("AttestationResponse does not have the required format (json)! " + jex.Message);
                return null;
            }
            if (root[CREDENTIAL_ID] is JToken credential_id)
            {
                parameters.Add(CREDENTIAL_ID, (string)credential_id);
            }
            if (root[CLIENTDATAJSON_CAM] is JToken clientDataJSON)
            {
                parameters.Add(CLIENTDATAJSON_CAM, (string)clientDataJSON);
            }
            if (root[ATTESTATIONOBJECT_CAM] is JToken attestationObject)
            {
                parameters.Add(ATTESTATIONOBJECT_CAM, (string)attestationObject);
            }
            if (root[RAWID_CAM] is JToken rawId)
            {
                parameters.Add(RAWID_CAM, (string)rawId);
            }
            if (root[AUTHENTICATORATTACHMENT_CAM] is JToken authenticatorAttachment)
            {
                parameters.Add(AUTHENTICATORATTACHMENT_CAM, (string)authenticatorAttachment);
            }

            return parameters;
        }

        /// <summary>
        /// Gets an auth token from the privacyIDEA server using the service account.
        /// Afterward, the token is set as the default authentication header for the HttpClient.
        /// </summary>
        /// <param name="customParameters">Dictionary of custom parameters to add</param>
        /// <returns>true if success, false otherwise</returns>
        private bool GetJWT(Dictionary<string, string> customParameters = null)
        {
            if (!ServiceAccountAvailable())
            {
                Error("Unable to fetch auth token without service account!");
                return false;
            }

            var map = new Dictionary<string, string>
            {
                { USERNAME, _serviceUser },
                { PASSWORD, _servicePass }
            };

            if (!string.IsNullOrEmpty(_serviceRealm))
            {
                map.Add(REALM, _serviceRealm);
            }
            var parameters = BuildParameters(map, "", customParameters);

            string response = SendRequest(AUTH_ENDPOINT, parameters);

            if (string.IsNullOrEmpty(response))
            {
                Error("/auth did not respond!");
                return false;
            }

            string token = "";
            try
            {
                dynamic root = JsonConvert.DeserializeObject(response);
                token = root.result.value.token;
            }
            catch (Exception)
            {
                Error("/auth response did not have the correct format or did not contain a token.\n" + response);
            }

            if (!string.IsNullOrEmpty(token))
            {
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(token);
                return true;
            }
            return false;
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
        /// Sends a request to the privacyIDEA server.
        /// </summary>
        /// <param name="endpoint"></param>
        /// <param name="parameters"></param>
        /// <param name="headers"></param>
        /// <param name="method"></param>
        /// <returns></returns>
        private string SendRequest(string endpoint, Dictionary<string, string> parameters, List<KeyValuePair<string, string>> headers = null, string method = "POST")
        {
            Log("Sending [" + string.Join(" , ", parameters) + "] to [" + endpoint + "] with method [" + method + "]");

            var stringContent = DictToEncodedStringContent(parameters);

            HttpRequestMessage request = new HttpRequestMessage();
            if (method == POST)
            {
                request.Method = HttpMethod.Post;
                request.RequestUri = new Uri(this.Url + endpoint);
                request.Content = stringContent;
            }
            else
            {
                string s = stringContent.ReadAsStringAsync().GetAwaiter().GetResult();
                request.Method = HttpMethod.Get;
                request.RequestUri = new Uri(this.Url + endpoint + "?" + s);
            }

            if (headers != null && headers.Count > 0)
            {
                foreach (var element in headers)
                {
                    request.Headers.Add(element.Key, element.Value);
                }
            }
            Log("Headers: " + request.Headers.ToString());
            Task<HttpResponseMessage> responseTask = _httpClient.SendAsync(request);

            var responseMessage = responseTask.GetAwaiter().GetResult();
            if (responseMessage.StatusCode != HttpStatusCode.OK)
            {
                Error("The request to " + endpoint + " returned HttpStatusCode " + responseMessage.StatusCode);
            }

            string ret = "";
            try
            {
                ret = responseMessage.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            }
            catch (Exception e)
            {
                Error(e.Message);
            }

            if (_logServerResponse && !string.IsNullOrEmpty(ret) && !_logExcludedEndpoints.Contains(endpoint))
            {
                Log(endpoint + " response:\n" + JToken.Parse(ret).ToString(Formatting.Indented));
            }

            return ret;
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
                string d = domain.ToUpper();
                if (RealmMap.ContainsKey(d))
                {
                    r = RealmMap[d];
                    Log("Found realm in mapping: " + r);
                }

                if (string.IsNullOrEmpty(r) && !string.IsNullOrEmpty(Realm))
                {
                    r = Realm;
                }

                if (!string.IsNullOrEmpty(r))
                {
                    parameters.Add(REALM, r);
                }
                else
                {
                    Log("No realm configured for domain " + d);
                }
            }
            else
            {
                if (!string.IsNullOrEmpty(Realm))
                {
                    parameters.Add(REALM, Realm);
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
        /// Helper to build request parameters.
        /// </summary>
        /// <param name="baseParams"></param>
        /// <param name="domain"></param>
        /// <param name="customParameters"></param>
        /// <returns></returns>
        private Dictionary<string, string> BuildParameters(Dictionary<string, string> baseParams, string domain, Dictionary<string, string> customParameters)
        {
            var parameters = new Dictionary<string, string>(baseParams);
            if (!string.IsNullOrEmpty(domain))
            {
                AddRealmForDomain(domain, parameters);
            }
            AddCustomParameters(customParameters, parameters);
            return parameters;
        }

        /// <summary>
        /// Converts a dictionary to a StringContent with url encoded values.
        /// </summary>
        /// <param name="dict"></param>
        /// <returns></returns>
        internal StringContent DictToEncodedStringContent(Dictionary<string, string> dict)
        {
            StringBuilder sb = new StringBuilder();
            foreach (var element in dict)
            {
                sb.Append(element.Key).Append("=");
                sb.Append((_excludeFromURIEscape.Contains(element.Key.ToLower())) ? element.Value : Uri.EscapeDataString(element.Value));
                sb.Append("&");
            }

            // Remove tailing &
            if (sb.Length > 0)
            {
                sb.Remove(sb.Length - 1, 1);
            }

            string ret = sb.ToString();
            return new StringContent(ret, Encoding.UTF8, MEDIA_TYPE_URLENCODED);
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

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    // Managed
                    _httpClient.Dispose();
                    _httpClientHandler.Dispose();
                }
                // Unmanaged
                _disposedValue = true;
            }
        }

        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }
    }
}
