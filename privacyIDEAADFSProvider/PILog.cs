using System;

namespace PrivacyIDEASDK
{
    public interface PILog
    {
        void Log(string message);

        void Error(string message);

        void Error(Exception exception);
    }
}
