using System.Collections.Generic;

namespace PrivacyIDEAADFSProvider.PrivacyIDEA_Client
{
    /// <summary>
    /// Per-call context that travels through every Validate* / Trigger* method:
    /// the privacyIDEA realm hint (Domain), headers to forward to the server,
    /// and custom parameters to merge into the request body. Build once per
    /// ADFS request, pass to whatever dispatch chooses.
    /// </summary>
    public sealed class PIRequestContext
    {
        public string Domain { get; set; }
        public List<KeyValuePair<string, string>> Headers { get; set; }
        public Dictionary<string, string> CustomParameters { get; set; }
    }
}
