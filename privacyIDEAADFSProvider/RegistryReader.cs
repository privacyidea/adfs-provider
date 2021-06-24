using System;
using System.Collections.Generic;
using Microsoft.Win32;

namespace PrivacyIDEASDK
{

    public delegate void LogFunction(string message);

    public class RegistryReader
    {
        private static string registryPath = "SOFTWARE\\Netknights GmbH\\PrivacyIDEA-ADFS";
        private static string realmMapPath = registryPath + "\\realm-mapping";

        private LogFunction LogFunc;

        public RegistryReader(LogFunction logFunction)
        {
            this.LogFunc = logFunction;
        }

        public string Read(string name)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(registryPath))
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
                            LogFunc("object for key " + key + " is null.");
                        }

                    }
                }
            }
            catch (Exception ex)
            {
                LogFunc("registryreader: " + ex.Message);
            }

            return "";
        }

        public Dictionary<string, string> GetRealmMapping()
        {
            var ret = new Dictionary<string, string>();
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(realmMapPath))
                {
                    if (key != null)
                    {
                        foreach (var name in key.GetValueNames())
                        {
                            ret.Add(name, (string)key.GetValue(name));
                        }
                    }
                }
            }
            catch (Exception e)
            {
                // The subkey might not exist if no realm mapping is configured
                LogFunc("Exception while loading realm map: " + e.Message);
            }

            return ret;
        }
    }
}
