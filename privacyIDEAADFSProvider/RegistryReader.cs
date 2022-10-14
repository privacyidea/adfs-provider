using System;
using System.Collections.Generic;
using Microsoft.Win32;

namespace PrivacyIDEASDK
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
                            _LogFunc?.Invoke("Object for key " + key + " is null.");
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

        public List<string> ReadMultiValue(string name)
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
                            return new List<string>(o as string[]);
                        }
                        else
                        {
                            _LogFunc?.Invoke("Object for key " + key + " is null.");
                        }

                    }
                }
            }
            catch (Exception ex)
            {
                _LogFunc?.Invoke("RegistryReader exception occured: " + ex.Message);
            }

            return new List<string>();
        }

        public Dictionary<string, string> GetRealmMapping()
        {
            var ret = new Dictionary<string, string>();
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(_RealmMapPath))
                {
                    if (key != null)
                    {
                        foreach (string name in key.GetValueNames())
                        {
                            ret.Add(name.ToUpper(), (string)key.GetValue(name));
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
