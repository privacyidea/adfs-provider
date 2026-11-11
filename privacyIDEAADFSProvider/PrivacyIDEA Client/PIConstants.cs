namespace PrivacyIDEAADFSProvider.PrivacyIDEA_Client
{
    public static class PITokenType
    {
        public const string Push = "push";
        public const string WebAuthn = "webauthn";
        public const string Otp = "otp";
        public const string Passkey = "passkey";
        public const string Smartphone = "smartphone";
        public const string Hotp = "hotp";
        public const string Totp = "totp";
        public const string Email = "email";
    }

    public static class PIClientMode {
        public const string Poll = "poll";
        public const string Interactive = "interactive";
        public const string WebAuthn = "webauthn";
    }

    public static class PIConstants
    {
        // Name of the "remember device" cookie. Must match PERSISTENT_COOKIE_NAME in the server's
        // privacyidea.lib.remembered_device.
        public const string RememberDeviceCookieName = "pi_remember_device";
    }
}
