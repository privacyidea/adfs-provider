using System;
using System.Security.Cryptography;
using System.Text;

namespace PrivacyIDEAADFSProvider.PrivacyIDEA_Client
{
    /// <summary>
    /// Encrypts secrets at rest (service_pass today, an API key later) using Windows DPAPI.
    ///
    /// Scope is LocalMachine: any process on this box can decrypt. That is acceptable because the
    /// registry ACL applied by Install.ps1 already restricts who can read the configuration key.
    /// DPAPI's job here is the off-box-leakage / compliance angle — a registry export, backup or disk
    /// image carries only ciphertext — NOT a boundary against a local admin. On an AD FS server that
    /// attacker already owns the token-signing key, so no same-box scheme can stop them.
    ///
    /// Stored format: the marker prefix "enc:" followed by the base64 of the DPAPI blob. A value
    /// without the marker is treated as legacy plaintext.
    /// </summary>
    public static class SecretProtector
    {
        public const string Marker = "enc:";

        public static bool IsProtected(string storedValue) =>
            !string.IsNullOrEmpty(storedValue) && storedValue.StartsWith(Marker, StringComparison.Ordinal);

        public static string Protect(string plaintext)
        {
            byte[] cipher = ProtectedData.Protect(
                Encoding.UTF8.GetBytes(plaintext), optionalEntropy: null, scope: DataProtectionScope.LocalMachine);
            return Marker + Convert.ToBase64String(cipher);
        }

        public static string Unprotect(string storedValue)
        {
            byte[] cipher = Convert.FromBase64String(storedValue.Substring(Marker.Length));
            byte[] plain = ProtectedData.Unprotect(
                cipher, optionalEntropy: null, scope: DataProtectionScope.LocalMachine);
            return Encoding.UTF8.GetString(plain);
        }
    }
}
