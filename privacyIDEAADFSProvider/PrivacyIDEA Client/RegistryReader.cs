using System;
using System.Collections.Generic;
using Microsoft.Win32;

namespace PrivacyIDEAADFSProvider.PrivacyIDEA_Client
{

    public delegate void LogFunction(string message);

    public class RegistryReader
    {
        private static readonly string _RegistryPath = "SOFTWARE\\Netknights GmbH\\PrivacyIDEA-ADFS";
        private static readonly string _RealmMapPath = _RegistryPath + "\\realm-mapping";

        private readonly LogFunction _LogFunc;

        public RegistryReader(LogFunction logFunction)
        {
            _LogFunc = logFunction;
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
