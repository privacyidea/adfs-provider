using System;

namespace PrivacyIDEASDK
{
    public interface IPILog
    {
        void Log(string message);

        void Error(string message);

        void Error(Exception exception);
    }
}
