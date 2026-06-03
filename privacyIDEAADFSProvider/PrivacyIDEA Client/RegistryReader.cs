using System;
using System.Collections.Generic;
using System.Security.AccessControl;
using Microsoft.Win32;

namespace PrivacyIDEAADFSProvider.PrivacyIDEA_Client
{

    public delegate void LogFunction(string message);

    public class RegistryReader
    {
        private static readonly string _RegistryPath = "SOFTWARE\\Netknights GmbH\\PrivacyIDEA-ADFS";
        private static readonly string _RealmMapPath = _RegistryPath + "\\realm-mapping";

        private readonly LogFunction _LogFunc;
        // Separate sink for notable, infrequent secret-handling events (encryption-at-rest migration and
        // its failures). These must NOT use _LogFunc: that one writes to the debug file, which is only
        // open when debug_log=1 and — critically — is not yet open while Configuration is being built in
        // OnAuthenticationPipelineLoad. The event-log sink is always available, so admins actually see it.
        private readonly LogFunction _EventLogFunc;

        public RegistryReader(LogFunction logFunction, LogFunction eventLogFunction = null)
        {
            _LogFunc = logFunction;
            _EventLogFunc = eventLogFunction;
        }

        public string Read(string name)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(_RegistryPath))
                {
                    if (key != null)
                    {
                        Object o = key.GetValue(name);
                        if (o != null)
                        {
                            return (o as string);
                        }
                        else
                        {
                            _LogFunc?.Invoke($"'{name}' is not set in registry.");
                        }

                    }
                }
            }
            catch (Exception ex)
            {
                _LogFunc?.Invoke("RegistryReader exception occured: " + ex.Message);
            }

            return "";
        }

        /// <summary>
        /// Reads a value that holds a secret (e.g. service_pass). Secrets are stored DPAPI-encrypted with
        /// the <see cref="SecretProtector"/> marker. For backward compatibility a plaintext value is still
        /// accepted, but it is transparently re-written encrypted (write-back) and a one-time warning is
        /// logged. This covers every way a plaintext value can appear: an upgraded install, the MSI writing
        /// the value, or an admin typing it straight into regedit. The write-back needs SetValue on the key,
        /// which Install.ps1 grants the AD FS service account.
        /// </summary>
        public string ReadSecret(string name)
        {
            string stored = Read(name);
            if (string.IsNullOrEmpty(stored))
            {
                return "";
            }

            if (SecretProtector.IsProtected(stored))
            {
                try
                {
                    return SecretProtector.Unprotect(stored);
                }
                catch (Exception ex)
                {
                    _EventLogFunc?.Invoke($"Failed to decrypt the stored secret '{name}': {ex.Message}");
                    return "";
                }
            }

            // Legacy plaintext: use it, but encrypt it at rest so it is not exposed in registry exports/backups.
            TryWriteBackEncrypted(name, stored);
            return stored;
        }

        private void TryWriteBackEncrypted(string name, string plaintext)
        {
            try
            {
                string encrypted = SecretProtector.Protect(plaintext);
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(_RegistryPath,
                    RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ReadKey | RegistryRights.SetValue))
                {
                    if (key == null)
                    {
                        _EventLogFunc?.Invoke($"Could not encrypt '{name}' at rest: configuration key '{_RegistryPath}' not found.");
                        return;
                    }
                    key.SetValue(name, encrypted, RegistryValueKind.String);
                }
                _EventLogFunc?.Invoke($"'{name}' was found in plaintext and has now been encrypted at rest (DPAPI). " +
                                      "Plaintext storage is deprecated.");
            }
            catch (Exception ex)
            {
                // Non-fatal: authentication still works with the plaintext we already read. The value just
                // stays plaintext on disk — most likely the service account lacks SetValue on the key
                // (run Install.ps1 to apply the ACL).
                _EventLogFunc?.Invoke($"Could not encrypt '{name}' at rest; it remains in plaintext: {ex.Message}");
            }
        }

        public Dictionary<string, string> GetRealmMapping()
        {
            // OrdinalIgnoreCase so PrivacyIDEA.AddRealmForDomain can look up the domain without uppercasing it.
            var ret = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(_RealmMapPath))
                {
                    if (key != null)
                    {
                        foreach (string name in key.GetValueNames())
                        {
                            ret.Add(name, (string)key.GetValue(name));
                        }
                    }
                }
            }
            catch (Exception e)
            {
                // The subkey might not exist if no realm mapping is configured
                _LogFunc?.Invoke("Exception while loading realm map: " + e.Message);
            }

            return ret;
        }
    }
}
