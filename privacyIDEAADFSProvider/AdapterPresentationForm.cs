using Microsoft.IdentityServer.Web.Authentication.External;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using System.Collections.Generic;
using System.Net;
using System.Text.RegularExpressions;

namespace PrivacyIDEAADFSProvider
{
    class AdapterPresentationForm : IAdapterPresentationForm
    {
        public string ErrorMessage { get; set; } = "";
        public string OtpHint { get; set; } = "";
        public string Message { get; set; } = "";
        public string PushMessage { get; set; } = "";
        public string PushAvailable { get; set; } = "0";
        public string Mode { get; set; } = PITokenType.Otp;
        public int AutoSubmitLength { get; set; } = 0;

        public string AutoSubmit { get; set; } = "0";
        public string WebAuthnSignRequest { get; set; } = "";
        public string AuthCounter { get; set; } = "0";
        public string PasskeyChallenge { get; set; } = "";
        public string PasskeyRegistration { get; set; } = "";
        public string DisablePasskey { get; set; } = "";
        public string EnrollmentLink { get; set; } = "";
        public string EnrollmentOptional { get; set; } = "0";
        // Drives the JS branch that hides the OTP input when the only available option is poll (push, smartphone container enrollment).
        public string DisableOTP { get; set; } = "0";
        public string EnrollmentUrl { get; set; } = "";
        public string EnrollmentImg { get; set; } = "";

        // Cached once: Resources.AuthPage is a ResourceManager lookup and the template is ~16 KB,
        // and the single regex pass replaces 25 sequential string.Replace calls (each of which
        // allocated a fresh ~16 KB copy).
        private static readonly string s_template = Resources.AuthPage;
        private static readonly Regex s_tokenRx = new Regex(@"#([A-Za-z]+)#", RegexOptions.Compiled);

        /// Returns the HTML Form fragment that contains the adapter user interface. This data will be included in the web page that is presented
        /// to the client.
        public string GetFormHtml(int lcid)
        {
            // The enrollment block lives in AuthPage.html; we just decide which of its sub-blocks is active.
            // "legacy" is the deprecated provider-driven TOTP rollout (enable_enrollment registry flag).
            // "image" is the server-driven enroll_via_multichallenge flow with a QR + optional link.
            string enrollmentMode = "none";
            if (!string.IsNullOrEmpty(EnrollmentImg) && !string.IsNullOrEmpty(EnrollmentUrl))
            {
                enrollmentMode = "legacy";
            }
            else if (!string.IsNullOrEmpty(EnrollmentImg))
            {
                enrollmentMode = "image";
            }

            var tokens = new Dictionary<string, string>
            {
                ["enrollmentMode"] = enrollmentMode,
                ["enrollmentUrl"] = EnrollmentUrl,
                ["enrollmentImg"] = EnrollmentImg,
                ["enrollmentLink"] = EnrollmentLink,
                ["ERROR"] = ErrorMessage,
                ["OTPTEXT"] = string.IsNullOrEmpty(OtpHint) ? "One-Time-Password" : OtpHint,
                ["SUBMIT"] = "Submit",
                ["MESSAGE"] = Message,
                ["authCounter"] = AuthCounter,
                ["mode"] = Mode,
                ["pushAvailable"] = PushAvailable,
                ["webAuthnSignRequest"] = WebAuthnSignRequest,
                ["pushMessage"] = PushMessage,
                ["modeChanged"] = "0",
                ["pollInterval"] = "1",
                // Empty string when 0 so the JS `if (asl !== "") setAutoSubmit(asl)` guard skips it,
                // matching the previous "leave placeholder unreplaced" → parseInt → NaN behavior.
                ["autoSubmitLength"] = AutoSubmitLength > 0 ? AutoSubmitLength.ToString() : "",
                ["autoSubmit"] = AutoSubmit,
                ["disableOTP"] = DisableOTP,
                ["enrollmentOptional"] = EnrollmentOptional,
                ["disablePasskey"] = DisablePasskey,
                ["passkeyChallenge"] = PasskeyChallenge,
                ["passkeyRegistration"] = PasskeyRegistration,
            };

            // Every value is HTML-encoded on substitution: these tokens land in text nodes, double-quoted
            // attributes (aria-label, placeholder, href, hidden input values), so server/config-provided
            // strings (messages, URLs) or JSON payloads must not break out of the markup. Encoding round-trips
            // cleanly for the JS — it reads element.value / dataset, which the browser HTML-decodes first.
            // Unknown tokens (none expected) pass through as the literal #name# so they're easy to spot.
            return s_tokenRx.Replace(s_template, m =>
                tokens.TryGetValue(m.Groups[1].Value, out string v) ? WebUtility.HtmlEncode(v) : m.Value);
        }

        /// Return any external resources, ie references to libraries etc., that should be included in
        /// the HEAD section of the presentation form html. 
        public string GetFormPreRenderHtml(int lcid)
        {
            return null;
        }

        /// Returns the title string for the web page which presents the HTML form content to the end user
        public string GetPageTitle(int lcid)
        {
            return "privacyIDEA AD FS";
        }

    }
}
