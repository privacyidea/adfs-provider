namespace PrivacyIDEAADFSProvider.PrivacyIDEA_Client
{
    /// <summary>
    /// A "remember device" cookie value returned by the server, together with its lifetime.
    /// The value is the opaque <c>series_id:counter</c> token; it never carries the API key.
    /// </summary>
    public class PICookie
    {
        public string Value { get; }
        public int MaxAgeSeconds { get; }

        public PICookie(string value, int maxAgeSeconds)
        {
            Value = value;
            MaxAgeSeconds = maxAgeSeconds;
        }

        /// <summary>
        /// True when the cookie must be removed rather than stored. The server clears a dead cookie with an
        /// empty value (pi_remember_device=;) and a non-positive Max-Age (a miss or a detected theft). An
        /// issued or rotated cookie always carries a non-empty value and a positive Max-Age. A non-positive
        /// Max-Age is also a clear, because Max-Age&lt;=0 is the HTTP delete signal and because a stored
        /// security token with no server-set lifetime must not be kept (the client must not invent one).
        /// </summary>
        public bool IsClear => string.IsNullOrEmpty(Value) || MaxAgeSeconds <= 0;
    }

    /// <summary>
    /// Outcome of presenting a "remember device" cookie to <c>/validate/remember_device</c>.
    /// <see cref="Recognized"/> is the server's answer (skip the second factor when true).
    /// <see cref="Cookie"/> is the cookie directive from the response, or null when the response
    /// carried no cookie change (a tolerated duplicate, or a cookie bound to a different user).
    /// </summary>
    public class RememberDeviceResult
    {
        public bool Recognized { get; set; }
        public PICookie Cookie { get; set; }
    }
}
