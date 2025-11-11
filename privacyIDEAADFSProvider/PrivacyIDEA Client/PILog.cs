using System;

namespace PrivacyIDEAADFSProvider.PrivacyIDEA_Client
{
    public interface IPILog
    {
        void Log(string message);

        void Error(string message);

        void Error(Exception exception);
    }
}
