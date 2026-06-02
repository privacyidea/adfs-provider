using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace PrivacyIDEAADFSProvider
{
    internal class Configuration
    {
        public string Url { get; set; }
        public string Realm { get; set; } = "";
        public List<string> ForwardHeaders { get; set; } = new List<string>();
        public bool ForwardClientIP { get; set; } = false;
        public bool ForwardClientUserAgent { get; set; } = false;
        public bool DebugLog { get; set; } = false;
        public string OtpHint { get; set; } = "One-Time-Password";
        public bool UseUPN { get; set; } = false;
        public bool TriggerChallenge { get; set; } = false;
        public bool SendEmptyPassword { get; set; } = false;
        public bool EnrollmentEnabled { get; set; } = false;
        public bool DisableSSL { get; set; } = false;
        public string ServiceUser { get; set; } = "";
        public string ServicePass { get; set; } = "";
        public string ServiceRealm { get; set; } = "";
        public Dictionary<string, string> RealmMap { get; set; } = new Dictionary<string, string>();
        public int AutoSubmitLength { get; set; } = 0; // 0 indicates that auto-submit is disabled
        public bool DisablePasskey { get; set; } = false;
        // Where Adapter.LogImpl appends when DebugLog is on. Default keeps backward compat with the previous hardcoded path.
        public string LogPath { get; set; } = @"C:\PrivacyIDEA-ADFS log.txt";

        private static readonly Dictionary<string, (SecurityProtocolType Protocol, string Label)> _tlsVersions =
            new Dictionary<string, (SecurityProtocolType, string)>
            {
                ["tls11"] = (SecurityProtocolType.Tls11, "1.1"),
                ["tls12"] = (SecurityProtocolType.Tls12, "1.2"),
                ["tls13"] = (SecurityProtocolType.Tls13, "1.3"),
            };

        public Configuration(LogFunction logFunction)
        {
            ReadConfigFromRegistry(logFunction);
        }

        private void ReadConfigFromRegistry(LogFunction logFunction)
        {
            var registryReader = new RegistryReader(logFunction);

            string Get(string key, string defaultValue = "")
            {
                string value = registryReader.Read(key);
                return string.IsNullOrEmpty(value) ? defaultValue : value;
            }
            bool GetBool(string key) => registryReader.Read(key) == "1";

            DebugLog = GetBool("debug_log");
            Url = Get("url");
            DisableSSL = GetBool("disable_ssl");
            Realm = Get("realm");

            ServiceUser = Get("service_user");
            ServicePass = Get("service_pass");
            ServiceRealm = Get("service_realm");

            OtpHint = Get("otp_hint", "One-Time-Password");
            UseUPN = GetBool("use_upn");
            EnrollmentEnabled = GetBool("enable_enrollment");
            TriggerChallenge = GetBool("trigger_challenges");
            if (!TriggerChallenge)
            {
                // Only if triggerChallenge is disabled, sendEmptyPassword COULD be set
                SendEmptyPassword = GetBool("send_empty_pass");
            }
            RealmMap = registryReader.GetRealmMapping();

            // Check if the TLS version should be overwritten
            string tlsVersion = Get("tls_version");
            if (!string.IsNullOrEmpty(tlsVersion))
            {
                var match = _tlsVersions.FirstOrDefault(kv => tlsVersion.Contains(kv.Key));
                if (match.Key != null)
                {
                    ServicePointManager.SecurityProtocol = match.Value.Protocol;
                    logFunction("Setting TLS version to " + match.Value.Label);
                }
                else
                {
                    logFunction($"Given TLS version ({tlsVersion}) has wrong format! Using default version from system.");
                }
            }

            // Check if headers to forward are set
            string headers = Get("forward_headers");
            if (!string.IsNullOrEmpty(headers))
            {
                ForwardHeaders = headers.Replace(" ", "").Split(',').ToList();
            }
            ForwardHeaders.Add("Accept-Language");

            if (int.TryParse(Get("auto_submit_otp_length"), out int autoSubmitLength))
            {
                AutoSubmitLength = autoSubmitLength;
            }

            DisablePasskey = GetBool("disable_passkey");
            ForwardClientIP = GetBool("forward_client_ip");
            ForwardClientUserAgent = GetBool("forward_client_user_agent");

            string configuredLogPath = Get("log_path");
            if (!string.IsNullOrEmpty(configuredLogPath))
            {
                LogPath = configuredLogPath;
            }
        }

        public bool ServiceAccountAvailable() => !string.IsNullOrEmpty(ServiceUser) && !string.IsNullOrEmpty(ServicePass);
    }
}
