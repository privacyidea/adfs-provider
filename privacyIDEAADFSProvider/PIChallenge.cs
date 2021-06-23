using System.Collections.Generic;

namespace PrivacyIDEASDK
{
    public class PIChallenge
    {
        public string Serial { get; set; } = "";
        public string Message { get; set; } = "";
        public string TransactionID { get; set; } = "";
        public string Type { get; set; } = "";
        public Dictionary<string, object> Attributes { get; set; } = new Dictionary<string, object>();
    }
}
