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
        // Defaulted (not left null) to match the codebase's collection/string defaults. Consumers still
        // use null-conditional access, so this is purely belt-and-suspenders; an empty Domain behaves
        // exactly like null (BuildParameters skips the realm via IsNullOrEmpty).
        public string Domain { get; set; } = "";
        public List<KeyValuePair<string, string>> Headers { get; set; } = new List<KeyValuePair<string, string>>();
        public Dictionary<string, string> CustomParameters { get; set; } = new Dictionary<string, string>();
    }
}
