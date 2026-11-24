using Microsoft.IdentityServer.Web.Authentication.External;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace PrivacyIDEAADFSProvider
{
    class AdapterPresentationForm : IAdapterPresentationForm
    {
        // Seconds between two push checks of the page when push_poll_interval is not set.
        public const int DefaultPushPollInterval = 3;

        private string _errorMessage = "";
        // Set by SetError: a key of Texts. GetFormHtml then shows the message in the page language.
        private string _errorKey;

        /// The message above the form. A message from the server is shown as it is. Setting this property
        /// clears a message that SetError set.
        public string ErrorMessage
        {
            get => _errorMessage;
            set
            {
                _errorMessage = value ?? "";
                _errorKey = null;
            }
        }

        /// Sets one of the provider's own messages, a key of Texts. GetFormHtml shows it in the language of the
        /// page, and ErrorMessage holds the English text (for the log and for the checks in the adapter).
        public void SetError(string textKey)
        {
            _errorMessage = Texts.Get(Texts.EnglishLcid, textKey);
            _errorKey = textKey;
        }

        public static AdapterPresentationForm WithError(string textKey)
        {
            var form = new AdapterPresentationForm();
            form.SetError(textKey);
            return form;
        }

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
        // "1" when the server offers "remember device" to this client: shows the checkbox.
        public string RememberDeviceEnabled { get; set; } = "0";
        // Renders the checkbox ticked, so a form that is rendered again (push poll, wrong OTP, mode switch)
        // keeps the user's choice.
        public bool RememberDeviceChecked { get; set; } = false;
        // When set, the page JS writes this value into the pi_remember_device cookie (series:counter) with
        // DeviceCookieMaxAge seconds of lifetime, then the form auto-submits. Used to issue or rotate it.
        public string DeviceCookieValue { get; set; } = "";
        public string DeviceCookieMaxAge { get; set; } = "";
        // "1" when the page JS should delete the pi_remember_device cookie (an unrecognised/stale cookie).
        public string DeviceCookieClear { get; set; } = "0";

        // Push checks of the page (AuthPage.html, startPushPolling). PushPollInterval comes from
        // push_poll_interval; 0 or less means DefaultPushPollInterval.
        public int PushPollInterval { get; set; } = 0;
        // "" while the page checks automatically, "stopped" after the user or the time limit stopped it (the page
        // posts this back), "refused" after the user declined or cancelled the push on the device (set by the
        // adapter on each poll, never taken from the client).
        public string PushPollState { get; set; } = "";
        // The browser time (milliseconds since 1970) of the first automatic check, for the time limit. The page
        // sets it and posts it back.
        public string PushPollStarted { get; set; } = "";
        // The id of the control that had the focus when the page posted itself for a push check. The page puts
        // the focus back on it after the reload.
        public string FocusId { get; set; } = "";

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

            // The placeholder of the OTP field: the otp_hint setting, else the translated default.
            string otpHint = string.IsNullOrEmpty(OtpHint) ? Texts.Get(lcid, Texts.OtpLabel) : OtpHint;

            var tokens = new Dictionary<string, string>
            {
                ["enrollmentMode"] = enrollmentMode,
                ["enrollmentUrl"] = EnrollmentUrl,
                ["enrollmentImg"] = EnrollmentImg,
                ["enrollmentLink"] = EnrollmentLink,
                ["ERROR"] = _errorKey != null ? Texts.Get(lcid, _errorKey) : ErrorMessage,
                ["OTPTEXT"] = otpHint,
                // The visible label of the OTP field: the server's challenge message. Without a triggered
                // challenge (the default configuration) there is no message, so show the placeholder text as a
                // label too. A placeholder alone disappears while the user types.
                ["otpLabel"] = string.IsNullOrEmpty(Message) ? otpHint : Message,
                // The server message, posted back in a hidden field, so a wrong OTP shows the same label again.
                ["MESSAGE"] = Message,
                ["authCounter"] = AuthCounter,
                ["mode"] = Mode,
                ["pushAvailable"] = PushAvailable,
                // Label for the manual push button. In poll-mode enrollment (smartphone/container
                // registration) the challenge carries an image and the action is "finish registration", not
                // "confirm a login", so word the button for that case.
                ["pushButtonLabel"] = Texts.Get(lcid, string.IsNullOrEmpty(EnrollmentImg)
                    ? Texts.PushConfirm
                    : Texts.PushConfirmRegistration),
                ["pushPollInterval"] = (PushPollInterval >= 1 ? PushPollInterval : DefaultPushPollInterval)
                    .ToString(CultureInfo.InvariantCulture),
                ["pushPollState"] = PushPollState,
                ["pushPollStarted"] = PushPollStarted,
                ["focusId"] = FocusId,
                ["webAuthnSignRequest"] = WebAuthnSignRequest,
                ["pushMessage"] = PushMessage,
                ["modeChanged"] = "0",
                // Empty string when 0 so the JS `if (asl !== "") setAutoSubmit(asl)` guard skips it,
                // matching the previous "leave placeholder unreplaced" → parseInt → NaN behavior.
                ["autoSubmitLength"] = AutoSubmitLength > 0 ? AutoSubmitLength.ToString() : "",
                ["autoSubmit"] = AutoSubmit,
                ["disableOTP"] = DisableOTP,
                ["enrollmentOptional"] = EnrollmentOptional,
                ["disablePasskey"] = DisablePasskey,
                ["passkeyChallenge"] = PasskeyChallenge,
                ["passkeyRegistration"] = PasskeyRegistration,
                ["rememberDeviceEnabled"] = RememberDeviceEnabled,
                // A bare attribute in the checkbox tag: "checked" or nothing.
                ["rememberDeviceChecked"] = RememberDeviceChecked ? "checked" : "",
                ["deviceCookieValue"] = DeviceCookieValue,
                ["deviceCookieMaxAge"] = DeviceCookieMaxAge,
                ["deviceCookieClear"] = DeviceCookieClear,
            };
            // The fixed texts of the page, in the language that AD FS chose: #txt<Key># (see Texts).
            foreach (string key in Texts.Keys)
            {
                tokens["txt" + key] = Texts.Get(lcid, key);
            }

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

        /// Returns the title string for the web page which presents the HTML form content to the end user.
        /// It names the task, not the product, in the language of the page.
        public string GetPageTitle(int lcid)
        {
            return Texts.Get(lcid, Texts.PageTitle);
        }

    }
}
