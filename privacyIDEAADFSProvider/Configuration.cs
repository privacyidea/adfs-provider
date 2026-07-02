using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using System;
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
        // IPs/CIDRs of reverse proxies allowed to set X-Forwarded-For. When non-empty, XFF is only honored
        // if the direct TCP peer is in this list (so a client talking to AD FS directly can't spoof its
        // source IP and bypass IP-based privacyIDEA policies). Empty preserves the legacy trust-XFF behavior.
        public List<string> TrustedProxies { get; set; } = new List<string>();
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
                ["tls12"] = (SecurityProtocolType.Tls12, "1.2"),
                ["tls13"] = (SecurityProtocolType.Tls13, "1.3"),
            };

        // Protocols we refuse to pin: TLS 1.1 and older are deprecated and insecure. A request for one is
        // ignored with a warning, leaving the system-default negotiation (TLS 1.2/1.3) in place rather than
        // forcing a downgrade. Order/length irrelevant; matched as substrings like the supported versions.
        private static readonly string[] _deprecatedTlsVersions = { "ssl3", "tls10", "tls11" };

        public Configuration(LogFunction logFunction, LogFunction eventLogFunction = null)
        {
            ReadConfigFromRegistry(logFunction, eventLogFunction);
        }

        private void ReadConfigFromRegistry(LogFunction logFunction, LogFunction eventLogFunction)
        {
            var registryReader = new RegistryReader(logFunction, eventLogFunction);

            string Get(string key, string defaultValue = "")
            {
                string value = registryReader.Read(key);
                return string.IsNullOrEmpty(value) ? defaultValue : value;
            }
            bool GetBool(string key) => registryReader.Read(key) == "1";

            DebugLog = GetBool("debug_log");
            Url = Get("url");
            DisableSSL = GetBool("disable_ssl");
            if (DisableSSL)
            {
                // Security-relevant weakening that is otherwise invisible at runtime: surface it in the
                // EVENT LOG (always available, unlike the debug file) on every provider load so it can be
                // alerted on and audited. Without this, an estate could run with TLS verification off and
                // leave no trace — which defeats any "transport security is enforced" control.
                eventLogFunction?.Invoke("SSL/TLS certificate validation is DISABLED (disable_ssl=1). The connection " +
                    "to the privacyIDEA server is NOT authenticated and is vulnerable to interception. This must not " +
                    "be used in production — remove the disable_ssl setting to restore certificate verification.");
            }
            Realm = Get("realm");

            ServiceUser = Get("service_user");
            // service_pass is a secret: ReadSecret decrypts it (and migrates any legacy plaintext to
            // encrypted-at-rest). Returns "" when unset, same as Get.
            ServicePass = registryReader.ReadSecret("service_pass");
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
                if (_deprecatedTlsVersions.Any(v => tlsVersion.Contains(v)))
                {
                    // Don't honor a request to pin a deprecated protocol. Warn in the event log (an admin may
                    // have set it for "compliance" and needs to know it was rejected) and leave the system
                    // default in place, which negotiates TLS 1.2/1.3 on a modern server.
                    eventLogFunction?.Invoke($"Configured tls_version '{tlsVersion}' selects a deprecated, insecure " +
                        "protocol (TLS 1.1 or older). Ignoring it and using the system-default TLS negotiation " +
                        "(TLS 1.2/1.3). Set tls_version to 'tls12' or 'tls13'.");
                }
                else
                {
                    var match = _tlsVersions.FirstOrDefault(kv => tlsVersion.Contains(kv.Key));
                    if (match.Key != null)
                    {
                        try
                        {
                            ServicePointManager.SecurityProtocol = match.Value.Protocol;
                            logFunction("Setting TLS version to " + match.Value.Label);
                        }
                        catch (Exception ex)
                        {
                            // The framework/OS may not support the requested protocol (e.g. tls13 on a Windows
                            // build without TLS 1.3 in SChannel). A TLS preference must not take down provider
                            // load, so fall back to the system default — which negotiates the best protocol the
                            // OS supports (TLS 1.2/1.3 on a modern server), a superset of the intent rather than
                            // a downgrade. Surface it in the EVENT LOG (not just the debug file) so an admin who
                            // pinned a version for compliance reasons can see it was not applied.
                            eventLogFunction?.Invoke($"Requested TLS version '{match.Value.Label}' could not be applied " +
                                $"({ex.Message}). Falling back to the system default TLS negotiation. If TLS {match.Value.Label} " +
                                "is required, ensure the operating system supports it.");
                        }
                    }
                    else
                    {
                        logFunction($"Given TLS version ({tlsVersion}) has wrong format! Using default version from system.");
                    }
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

            string trustedProxies = Get("trusted_proxies");
            if (!string.IsNullOrEmpty(trustedProxies))
            {
                TrustedProxies = trustedProxies.Replace(" ", "").Split(',')
                    .Where(s => !string.IsNullOrEmpty(s)).ToList();
            }

            string configuredLogPath = Get("log_path");
            if (!string.IsNullOrEmpty(configuredLogPath))
            {
                LogPath = configuredLogPath;
            }
        }

        public bool ServiceAccountAvailable() => !string.IsNullOrEmpty(ServiceUser) && !string.IsNullOrEmpty(ServicePass);
    }
}
