using System;
using System.Diagnostics;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace PrivacyIDEASDK
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
                    _HttpClientHandler = new HttpClientHandler();
                    if (!SSLVerify)
                    {
                        _HttpClientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                        _HttpClientHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                    }
                    _HttpClient = new HttpClient(_HttpClientHandler);
                    _HttpClient.DefaultRequestHeaders.Add("User-Agent", _UserAgent);
                    _sslVerify = SSLVerify;
                }
            }
        }

        private HttpClientHandler _HttpClientHandler;
        private HttpClient _HttpClient;
        private bool _DisposedValue;
        private string _ServiceUser;
        private string _ServicePass;
        private string _ServiceRealm;
        private readonly string _UserAgent;
        private readonly bool _LogServerResponse = true;
        public IPILog Logger { get; set; } = null;

        // The webauthn parameters should not be url encoded because they already have the correct format.
        private static readonly List<String> _ExludeFromURIEscape = new List<string>(new string[]
           { "credentialid", "clientdata", "signaturedata", "authenticatordata", "userhandle", "assertionclientextensions" });

        private static readonly List<String> _LogExcludedEndpoints = new List<string>(new string[]
           { "/auth", "/validate/polltransaction" });

        public PrivacyIDEA(string url, string useragent, bool sslVerify = true)
        {
            this.Url = url;
            this._UserAgent = useragent;

            _HttpClientHandler = new HttpClientHandler();
            if (!sslVerify)
            {
                _HttpClientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                _HttpClientHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            }
            _HttpClient = new HttpClient(_HttpClientHandler);
            _HttpClient.DefaultRequestHeaders.Add("User-Agent", useragent);
        }

        /// <summary>
        /// Trigger challenges for the given user using a service account.
        /// </summary>
        /// <param name="username">username to trigger challenges for</param>
        /// <param name="domain">optional domain which can be mapped to a privacyIDEA realm</param>
        /// <param name="headers">optional headers which can be forwarded to the privacyIDEA server</param>
        /// <returns>PIResponse object or null on error</returns>
        public PIResponse TriggerChallenges(string username, string domain = null, List<KeyValuePair<string, string>> headers = null)
        {
            if (!GetAuthToken())
            {
                Error("Unable to trigger challenges without an auth token!");
                return null;
            }
            var parameters = new Dictionary<string, string>
            {
                { "user", username }
            };

            AddRealmForDomain(domain, parameters);

            string response = SendRequest("/validate/triggerchallenge", parameters, headers);
            PIResponse ret = PIResponse.FromJSON(response, this);

            return ret;
        }

        /// <summary>
        /// Check if the challenge for the given transaction id has been answered yet. This is done using the /validate/polltransaction endpoint.
        /// </summary>
        /// <param name="transactionid"></param>
        /// <returns>true if challenge was answered. false if not or error</returns>
        public bool PollTransaction(string transactionid)
        {
            if (!string.IsNullOrEmpty(transactionid))
            {
                var map = new Dictionary<string, string>
                {
                    { "transaction_id", transactionid }
                };

                string response = SendRequest("/validate/polltransaction", map, new List<KeyValuePair<string, string>>(), "GET");

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
        /// <returns>true if token exists. false if not or error</returns>
        public bool UserHasToken(string user, string domain = null)
        {
            if (!GetAuthToken())
            {
                Error("Unable to lookup tokens without an auth token!");
                return false;
            }
            var parameters = new Dictionary<string, string>
            {
                { "user", user }
            };
            AddRealmForDomain(domain, parameters);

            string response = SendRequest("/token/", parameters, new List<KeyValuePair<string, string>>(), "GET");
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
        /// <returns>PIEnrollResponse object or null on error</returns>
        public PIEnrollResponse TokenInit(string user, string domain = null)
        {
            var parameters = new Dictionary<string, string>
            {
                { "user", user },
                { "type", "totp" },
                { "genkey", "1" }
            };
            AddRealmForDomain(domain, parameters);

            string response = SendRequest("/token/init", parameters, new List<KeyValuePair<string, string>>());
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
        /// <returns>PIResponse object or null on error</returns>
        public PIResponse ValidateCheck(string user, string otp, string transactionid = null, string domain = null, List<KeyValuePair<string, string>> headers = null)
        {
            var parameters = new Dictionary<string, string>
            {
                { "user", user },
                { "pass", otp }
            };

            if (transactionid != null)
            {
                parameters.Add("transaction_id", transactionid);
            }

            AddRealmForDomain(domain, parameters);

            string response = SendRequest("/validate/check", parameters, headers);
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
        /// <returns>PIResponse object or null on error</returns>
        public PIResponse ValidateCheckWebAuthn(string user, string transactionid, string webAuthnSignResponse, string origin, string domain = null, List<KeyValuePair<string, string>> headers = null)
        {
            if (string.IsNullOrEmpty(user) || string.IsNullOrEmpty(transactionid) || string.IsNullOrEmpty(webAuthnSignResponse) || string.IsNullOrEmpty(origin))
            {
                Log("ValidateCheckWebAuthn called with missing parameter: user=" + user + ", transactionid=" + transactionid
                    + ", WebAuthnSignResponse=" + webAuthnSignResponse + ", origin=" + origin);
                return null;
            }

            // Parse the WebAuthnSignResponse and add mandatory parameters
            JToken root;
            try
            {
                root = JToken.Parse(webAuthnSignResponse);
            }
            catch (JsonReaderException jex)
            {
                Error("WebAuthnSignRequest does not have the required format! " + jex.Message);
                return null;
            }

            string credentialid = (string)root["credentialid"];
            string clientdata = (string)root["clientdata"];
            string signaturedata = (string)root["signaturedata"];
            string authenticatordata = (string)root["authenticatordata"];

            var parameters = new Dictionary<string, string>
            {
                { "user", user },
                { "pass", "" },
                { "transaction_id", transactionid },
                { "credentialid", credentialid },
                { "clientdata", clientdata },
                { "signaturedata", signaturedata },
                { "authenticatordata", authenticatordata }
            };

            // Optionally add UserHandle and AssertionClientExtensions
            string userhandle = (string)root["userhandle"];
            if (!string.IsNullOrEmpty(userhandle))
            {
                parameters.Add("userhandle", userhandle);
            }

            string ace = (string)root["assertionclientextensions"];
            if (!string.IsNullOrEmpty(ace))
            {
                parameters.Add("assertionclientextensions", ace);
            }

            AddRealmForDomain(domain, parameters);

            // The origin has to be set in the header for WebAuthn authentication
            headers.Add(new KeyValuePair<string, string>("Origin", origin));

            string response = SendRequest("/validate/check", parameters, headers);
            return PIResponse.FromJSON(response, this);
        }

        /// <summary>
        /// Gets an auth token from the privacyIDEA server using the service account.
        /// Afterward, the token is set as the default authentication header for the HttpClient.
        /// </summary>
        /// <returns>true if success, false otherwise</returns>
        private bool GetAuthToken()
        {
            if (!ServiceAccountAvailable())
            {
                Error("Unable to fetch auth token without service account!");
                return false;
            }

            var map = new Dictionary<string, string>
            {
                { "username", _ServiceUser },
                { "password", _ServicePass }
            };

            if (!string.IsNullOrEmpty(_ServiceRealm))
            {
                map.Add("realm", _ServiceRealm);
            }

            string response = SendRequest("/auth", map);

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
                _HttpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(token);
                return true;
            }
            return false;
        }

        public void SetServiceAccount(string user, string pass, string realm = "")
        {
            _ServiceUser = user;
            _ServicePass = pass;
            if (!string.IsNullOrEmpty(realm))
            {
                _ServiceRealm = realm;
            }
        }

        private string SendRequest(string endpoint, Dictionary<string, string> parameters, List<KeyValuePair<string, string>> headers = null, string method = "POST")
        {
            Log("Sending [" + string.Join(" , ", parameters) + "] to [" + endpoint + "] with method [" + method + "]");

            var stringContent = DictToEncodedStringContent(parameters);

            HttpRequestMessage request = new HttpRequestMessage();
            if (method == "POST")
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
                    Log("Forwarding headers: " + element.Key + " = " + element.Value);
                }
            }

            Task<HttpResponseMessage> responseTask = _HttpClient.SendAsync(request);

            var responseMessage = responseTask.GetAwaiter().GetResult();
            if (responseMessage.StatusCode != HttpStatusCode.OK)
            {
                Error("The request to " + endpoint + " returned HttpStatusCode " + responseMessage.StatusCode);
                //return "";
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

            if (_LogServerResponse && !string.IsNullOrEmpty(ret) && !_LogExcludedEndpoints.Contains(endpoint))
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
                Log("Searching realm for domain " + d);
                if (RealmMap.ContainsKey(d))
                {
                    r = RealmMap[d];
                    Log("Found realm in mapping: " + r);
                }

                if (string.IsNullOrEmpty(r) && !string.IsNullOrEmpty(Realm))
                {
                    r = Realm;
                    Log("Using default realm " + r);
                }

                if (!string.IsNullOrEmpty(r))
                {
                    parameters.Add("realm", r);
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
                    parameters.Add("realm", Realm);
                }
            }            
        }

        internal StringContent DictToEncodedStringContent(Dictionary<string, string> dict)
        {
            StringBuilder sb = new StringBuilder();

            foreach (var element in dict)
            {
                sb.Append(element.Key).Append("=");
                sb.Append((_ExludeFromURIEscape.Contains(element.Key)) ? element.Value : Uri.EscapeDataString(element.Value));
                sb.Append("&");
            }
            // Remove tailing &
            if (sb.Length > 0)
            {
                sb.Remove(sb.Length - 1, 1);
            }

            string ret = sb.ToString();
            //Log("Built string: " + ret);
            return new StringContent(ret, Encoding.UTF8, "application/x-www-form-urlencoded"); ;
        }

        internal bool ServiceAccountAvailable()
        {
            return !string.IsNullOrEmpty(_ServiceUser) && !string.IsNullOrEmpty(_ServicePass);
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
            if (!_DisposedValue)
            {
                if (disposing)
                {
                    // Managed
                    _HttpClient.Dispose();
                    _HttpClientHandler.Dispose();
                }
                // Unmanaged
                _DisposedValue = true;
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
