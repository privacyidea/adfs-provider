using System;
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
                    httpClientHandler = new HttpClientHandler();
                    if (!SSLVerify)
                    {
                        httpClientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                        httpClientHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
                    }
                    httpClient = new HttpClient(httpClientHandler);
                    httpClient.DefaultRequestHeaders.Add("User-Agent", useragent);
                    _sslVerify = SSLVerify;
                }
            }
        }

        private HttpClientHandler httpClientHandler;
        private HttpClient httpClient;
        private bool disposedValue;
        private string serviceuser, servicepass, servicerealm, useragent;

        public PILog Logger { get; set; } = null;
        public PrivacyIDEA(string url, string useragent, bool sslVerify = true)
        {
            this.Url = url;
            this.useragent = useragent;

            httpClientHandler = new HttpClientHandler();
            if (!sslVerify)
            {
                httpClientHandler.ClientCertificateOptions = ClientCertificateOption.Manual;
                httpClientHandler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            }
            httpClient = new HttpClient(httpClientHandler);
            httpClient.DefaultRequestHeaders.Add("User-Agent", useragent);
        }

        public void SetServiceAccount(string user, string pass, string realm = "")
        {
            serviceuser = user;
            servicepass = pass;
            if (!string.IsNullOrEmpty(realm))
            {
                servicerealm = realm;
            }
        }
        public PIResponse ValidateCheck(string user, string otp, string transactionid = null)
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

            string response = SendRequest("/validate/check", parameters, new List<KeyValuePair<string, string>>());
            Log("/validate/check:\n" + JToken.Parse(response).ToString(Formatting.Indented));
            return PIResponse.FromJSON(response, this);
        }

        public PIResponse ValidateCheckWebAuthn(string user, string transactionid, string webAuthnSignResponse, string origin)
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

            var paramDict = new Dictionary<string, string>
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
                paramDict.Add("userhandle", userhandle);
            }

            string ace = (string)root["assertionclientextensions"];
            if (!string.IsNullOrEmpty(ace))
            {
                paramDict.Add("assertionclientextensions", ace);
            }

            // The origin has to be set in the header for WebAuthn authentication
            var headers = new List<KeyValuePair<string, string>>
            {
                new KeyValuePair<string, string>("Origin", origin)
            };

            string response = SendRequest("/validate/check", paramDict, headers);
            Log("/validate/check webauthn response:\n" + JToken.Parse(response).ToString(Formatting.Indented));
            return PIResponse.FromJSON(response, this);
        }

        private static List<String> exludeFromURIEscape = new List<string>(new string[]
            { "credentialid", "clientdata", "signaturedata", "authenticatordata", "userhandle", "assertionclientextensions" });
        internal StringContent DictToEncodedStringContent(Dictionary<string, string> dict)
        {
            StringBuilder sb = new StringBuilder();

            foreach (var element in dict)
            {
                sb.Append(element.Key).Append("=");
                sb.Append((exludeFromURIEscape.Contains(element.Key)) ? element.Value : Uri.EscapeDataString(element.Value));
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
            return !string.IsNullOrEmpty(serviceuser) && !string.IsNullOrEmpty(servicepass);
        }

        public PIResponse TriggerChallenges(string username)
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

            string response = SendRequest("/validate/triggerchallenge", parameters);
            Log("/validate/triggerchallenge response:\n" + JToken.Parse(response).ToString(Formatting.Indented));
            PIResponse ret = PIResponse.FromJSON(response, this);

            return ret;
        }

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

        private bool GetAuthToken()
        {
            if (!ServiceAccountAvailable())
            {
                Error("Unable to fetch auth token without service account!");
                return false;
            }

            var map = new Dictionary<string, string>
            {
                { "username", serviceuser },
                { "password", servicepass }
            };

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
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(token);
                return true;
            }
            return false;
        }

        private String SendRequest(string endpoint, Dictionary<string, string> parameters, List<KeyValuePair<string, string>> headers = null, string method = "POST")
        {
            Log("Sending " + string.Join(" , ", parameters) + " to [" + endpoint + "] with method [" + method + "]");

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
                }
            }

            Task<HttpResponseMessage> responseTask = httpClient.SendAsync(request);

            var responseMessage = responseTask.GetAwaiter().GetResult();
            if (responseMessage.StatusCode != HttpStatusCode.OK)
            {
                Error("The request to " + endpoint + " returned HttpStatusCode " + responseMessage.StatusCode);
                return "";
            }

            string body = responseMessage.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            return body;
        }

        internal void Log(string message)
        {
            if (this.Logger != null)
            {
                this.Logger.Log(message);
            }
        }

        internal void Error(string message)
        {
            if (this.Logger != null)
            {
                this.Logger.Error(message);
            }
        }

        internal void Error(Exception exception)
        {
            if (this.Logger != null)
            {
                this.Logger.Error(exception);
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // Managed
                    httpClient.Dispose();
                    httpClientHandler.Dispose();
                }
                // Unmanaged
                disposedValue = true;
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
