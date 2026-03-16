namespace PrivacyIDEAADFSProvider
{
    internal class FormResult
    {
        public bool AuthenticationResetRequested { get; set; } = false;
        public bool PasskeyLoginRequested { get; set; } = false;
        public bool PasskeyLoginCancelled { get; set; } = false;
        public bool ModeChanged { get; set; } = false;
        public string NewMode { get; set; } = "";
        public string WebAuthnSignResponse { get; set; } = "";
        public string PasskeySignResponse { get; set; } = "";
        public string PasskeyRegistrationResponse { get; set; } = "";
        public string Origin { get; set; } = "";
        public bool EnrollmentCancelled { get; set; } = false;
    }
}
