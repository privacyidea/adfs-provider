using PrivacyIDEASDK;
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
        public bool DebugLog { get; set; } = false;
        public string OtpHint { get; set; } = "One-Time-Password";
        public bool UseUPN { get; set; } = false;
        public bool TriggerChallenge { get; set; } = false;
        public bool SendEmptyPassword { get; set; } = false;
        public bool EnrollmentEnabled { get; set; } = false;
        public Dictionary<string, string> Config { get; set; } = new Dictionary<string, string>();
        public bool DisableSSL { get; set; } = false;
        public string ServiceUser { get; set; } = "";
        public string ServicePass { get; set; } = "";
        public string ServiceRealm { get; set; } = "";
        public Dictionary<string, string> RealmMap { get; set; } = new Dictionary<string, string>();
        public int AutoSubmitLength { get; set; } = 0; // 0 indicates that auto-submit is disabled
        public bool DisablePasskey { get; set; } = false;

        private List<string> _ConfigKeys = new List<string>(new string[]
            { "use_upn", "url", "disable_ssl", "tls_version", "enable_enrollment", "service_user", "service_pass", "service_realm", "disable_passkey",
                "realm", "trigger_challenges", "send_empty_pass", "otp_hint", "forward_headers", "auto_submit_otp_length" });

        public Configuration(LogFunction logFunction)
        {
            ReadConfigFromRegistry(logFunction);
        }

        private void ReadConfigFromRegistry(LogFunction logFunction)
        {
            var registryReader = new RegistryReader(logFunction);
            DebugLog = registryReader.Read("debug_log") == "1";
            _ConfigKeys.ForEach(key =>
            {
                // Do not add the value to the dictionary if it is empty!
                string value = registryReader.Read(key);
                if (!string.IsNullOrEmpty(value))
                {
                    Config[key] = value;
                }
            });

            Url = Config.ContainsKey("url") ? Config["url"] : "";
            DisableSSL = Config.ContainsKey("disable_ssl") && Config["disable_ssl"] == "1";
            Realm = Config.ContainsKey("realm") ? Config["realm"] : "";

            ServiceUser = Config.ContainsKey("service_user") ? Config["service_user"] : "";
            ServicePass = Config.ContainsKey("service_pass") ? Config["service_pass"] : "";
            ServiceRealm = Config.ContainsKey("service_realm") ? Config["service_realm"] : "";

            OtpHint = Config.ContainsKey("otp_hint") ? Config["otp_hint"] : "One-Time-Password";
            UseUPN = Config.ContainsKey("use_upn") ? Config["use_upn"] == "1" : false;
            EnrollmentEnabled = Config.ContainsKey("enable_enrollment") && Config["enable_enrollment"] == "1";
            TriggerChallenge = Config.ContainsKey("trigger_challenges") && Config["trigger_challenges"] == "1";
            if (!TriggerChallenge)
            {
                // Only if triggerChallenge is disabled, sendEmptyPassword COULD be set
                SendEmptyPassword = Config.ContainsKey("send_empty_pass") && Config["send_empty_pass"] == "1";
            }
            RealmMap = registryReader.GetRealmMapping();

            // Check if the TLS version should be overwritten
            if (Config.TryGetValue("tls_version", out string tlsVersion) && !string.IsNullOrEmpty(tlsVersion))
            {
                if (tlsVersion.Contains("tls11"))
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls11;
                    logFunction("Setting TLS version to 1.1");
                }
                else if (tlsVersion.Contains("tls12"))
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                    logFunction("Setting TLS version to 1.2");
                }
                else if (tlsVersion.Contains("tls13"))
                {
                    ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls13;
                    logFunction("Setting TLS version to 1.3");
                }
                else
                {
                    logFunction($"Given TLS version ({tlsVersion}) has wrong format! Using default version from system.");
                }
            }

            // Check if headers to forward are set
            if (Config.TryGetValue("forward_headers", out string headers))
            {
                headers = headers.Replace(" ", "");
                ForwardHeaders = headers.Split(',').ToList();
            }
            ForwardHeaders.Add("Accept-Language");
            if (Config.TryGetValue("auto_submit_otp_length", out string autoSubmitLengthStr)
                && int.TryParse(autoSubmitLengthStr, out int autoSubmitLength))
            {
                AutoSubmitLength = autoSubmitLength;
            }
            else
            {
                AutoSubmitLength = 0; // Default to 0 if not set or invalid
            }

            DisablePasskey = Config.ContainsKey("disable_passkey") && Config["disable_passkey"] == "1";
        }

        public bool ServiceAccountAvailable() => !string.IsNullOrEmpty(ServiceUser) && !string.IsNullOrEmpty(ServicePass);
    }
}
