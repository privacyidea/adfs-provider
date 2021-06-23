using System;
using Microsoft.Win32;

namespace PrivacyIDEASDK
{

    public delegate void LogFunction(string message);

    class RegistryReader
    {
        private string subKey = "SOFTWARE\\Netknights GmbH\\PrivacyIDEA-ADFS";

        private LogFunction LogFunc;

        public RegistryReader(LogFunction logFunction)
        {
            this.LogFunc = logFunction;
        }

        public string Read(string name)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(subKey))
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

    }
}
