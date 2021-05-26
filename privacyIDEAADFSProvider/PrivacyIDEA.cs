using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using SDK;

namespace SDKNS
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
            var parameters = new List<KeyValuePair<string, string>>();
            parameters.Add(new KeyValuePair<string, string>("user", user));
            parameters.Add(new KeyValuePair<string, string>("pass", otp));

            AddOptionalParameter(transactionid, "transaction_id", parameters);
            AddOptionalParameter(Realm, "realm", parameters);

            string response = SendRequest("/validate/check", parameters, new List<KeyValuePair<string, string>>());
            Log("validate/check:\n" + JToken.Parse(response).ToString(Formatting.Indented));
            return PIResponse.FromJSON(response, this);
        }

        internal bool ServiceAccountAvailable()
        {
            return !string.IsNullOrEmpty(serviceuser) && !string.IsNullOrEmpty(servicepass);
        }

        private void AddOptionalParameter(string optValue, string key, List<KeyValuePair<string, string>> list)
        {
            if (!string.IsNullOrEmpty(optValue))
            {
                list.Add(new KeyValuePair<string, string>(key, optValue));
            }
        }

        public PIResponse TriggerChallenges(string username)
        {
            if (!ServiceAccountAvailable())
            {
                Error("Unable to trigger challenges without service account!");
                return null;
            }
            var parameters = new List<KeyValuePair<string, string>>();
            parameters.Add(new KeyValuePair<string, string>("user", username));

            AddOptionalParameter(Realm, "realm", parameters);

            if (!GetAuthToken())
            {
                Error("Could not fetch auth token!");
                return null;
            }

            var headers = new List<KeyValuePair<string, string>>();

            string response = SendRequest("/validate/triggerchallenge", parameters, headers);
            Log("TriggerChallenge:\n" + JToken.Parse(response).ToString(Formatting.Indented));
            PIResponse ret = PIResponse.FromJSON(response, this);

            return ret;
        }

        public bool PollTransaction(string transactionid)
        {
            if (!string.IsNullOrEmpty(transactionid))
            {
                var map = new List<KeyValuePair<string, string>>();
                map.Add(new KeyValuePair<string, string>("transaction_id", transactionid));
                string response = SendRequest("/validate/polltransaction", map, new List<KeyValuePair<string, string>>(), "GET");

                if (string.IsNullOrEmpty(response))
                {
                    Error("/validate/polltransaction did not respond!");
                    return false;
                }

                dynamic root = JsonConvert.DeserializeObject(response);
                return (bool)root.result.value;
            }
            Error("PollTransaction called with empty transaction id!");
            return false;
        }

        private bool GetAuthToken()
        {
            var map = new List<KeyValuePair<string, string>>();
            map.Add(new KeyValuePair<string, string>("username", serviceuser));
            map.Add(new KeyValuePair<string, string>("password", servicepass));

            string response = SendRequest("/auth", map, new List<KeyValuePair<string, string>>());
            if (string.IsNullOrEmpty(response))
            {
                Error("/auth did not respond!");
                return false;
            }

            dynamic root = JsonConvert.DeserializeObject(response);
            string token = root.result.value.token;
            if (!string.IsNullOrEmpty(token))
            {
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(token);
                return true;
            }
            return false;
        }

        private String SendRequest(string endpoint, List<KeyValuePair<string, string>> parameters, List<KeyValuePair<string, string>> headers, string method = "POST")
        {
            var content = new FormUrlEncodedContent(parameters);

            content.Headers.Clear();
            content.Headers.Add("Content-Type", "application/x-www-form-urlencoded");
            headers.ForEach(entry => content.Headers.Add(entry.Key, entry.Value));
            Log("Sending " + string.Join(" , ", parameters) + " to [" + endpoint + "] with method [" + method + "]");

            AuthenticationHeaderValue authheader = httpClient.DefaultRequestHeaders.Authorization;
            if (authheader != null)
            {
            }

            Task<HttpResponseMessage> responseTask;
            if (method == "POST")
            {
                responseTask = httpClient.PostAsync((this.Url + endpoint), content);
            }
            else
            {
                string requestURI = this.Url + endpoint + "?";
                parameters.ForEach(pair =>
                {
                    requestURI += Uri.EscapeDataString(pair.Key) + "=" + Uri.EscapeDataString(pair.Value);
                });
                responseTask = httpClient.GetAsync(requestURI);
            }

            var responseMessage = responseTask.GetAwaiter().GetResult();
            if (responseMessage.StatusCode != System.Net.HttpStatusCode.OK)
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
