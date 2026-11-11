namespace PrivacyIDEAADFSProvider
{
    internal class FormResult
    {
        public bool PasskeyLoginRequested { get; set; } = false;
        public bool EnrollmentCancelled { get; set; } = false;
        public bool ModeChanged { get; set; } = false;
        public string NewMode { get; set; } = "";
        public string WebAuthnSignResponse { get; set; } = "";
        public string PasskeySignResponse { get; set; } = "";
        public string PasskeyRegistrationResponse { get; set; } = "";
        public string Origin { get; set; } = "";
        // The user ticked "remember this device". The page JS copies the checkbox state here on submit;
        // a no-JavaScript client posts a plain rememberDevice field instead (both are honoured).
        public bool RememberDevice { get; set; } = false;
    }
}
