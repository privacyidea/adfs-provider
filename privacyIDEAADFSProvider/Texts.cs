using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace PrivacyIDEAADFSProvider
{
    /// <summary>
    /// The texts of the login page and the provider's own messages, in English, German and French.
    /// AD FS passes the language of the sign-in page as an LCID to GetFormHtml, GetPageTitle and the metadata.
    /// A language without a table here gets the English texts. Messages from the privacyIDEA server are not in
    /// these tables: the provider forwards Accept-Language, and the server translates them.
    /// The tables live in code, not in a .resx file per language: a .resx per language builds a satellite
    /// assembly, which the installer would also have to put into the GAC.
    /// Every key needs a text in every language. A unit test checks this.
    /// </summary>
    internal static class Texts
    {
        public const int EnglishLcid = 1033;
        private const string DefaultLanguage = "en";

        // Keys. AdapterPresentationForm passes each text to AuthPage.html as the token #txt<Key>#.
        public const string PageTitle = "PageTitle";
        public const string ProviderDescription = "ProviderDescription";
        public const string OtpLabel = "OtpLabel";
        public const string Submit = "Submit";
        public const string PushConfirm = "PushConfirm";
        public const string PushConfirmRegistration = "PushConfirmRegistration";
        public const string PushStop = "PushStop";
        public const string PushStopped = "PushStopped";
        public const string PushNotConfirmed = "PushNotConfirmed";
        public const string RegistrationNotCompleted = "RegistrationNotCompleted";
        public const string PushDeclined = "PushDeclined";
        public const string PushCancelled = "PushCancelled";
        public const string RegistrationCancelled = "RegistrationCancelled";
        public const string PushRefusedOnOneDevice = "PushRefusedOnOneDevice";
        public const string UseOtp = "UseOtp";
        public const string UsePush = "UsePush";
        public const string RememberDevice = "RememberDevice";
        public const string RetryPasskeyRegistration = "RetryPasskeyRegistration";
        public const string NotNow = "NotNow";
        public const string OtherLoginOptions = "OtherLoginOptions";
        public const string Passkey = "Passkey";
        public const string RetryPasskeyLogin = "RetryPasskeyLogin";
        public const string WebAuthn = "WebAuthn";
        public const string Push = "Push";
        public const string Otp = "Otp";
        public const string NoScript = "NoScript";
        public const string EnrollmentQrAlt = "EnrollmentQrAlt";
        public const string EnrollmentLinkText = "EnrollmentLinkText";
        public const string LegacyIntro = "LegacyIntro";
        public const string LegacyWarning = "LegacyWarning";
        public const string LegacyStep1 = "LegacyStep1";
        public const string LegacyStep2 = "LegacyStep2";
        public const string LegacyLinkLabel = "LegacyLinkLabel";
        public const string LegacyCopy = "LegacyCopy";
        public const string LegacyStep3 = "LegacyStep3";
        public const string InternalError = "InternalError";
        public const string CancelEnrollmentFailed = "CancelEnrollmentFailed";
        public const string PasskeyStartFailed = "PasskeyStartFailed";
        public const string PasskeyFailed = "PasskeyFailed";
        public const string PasskeyRegistrationFailed = "PasskeyRegistrationFailed";
        public const string WebAuthnFailed = "WebAuthnFailed";
        public const string PasskeyWrongUser = "PasskeyWrongUser";
        public const string ServerUnreachable = "ServerUnreachable";
        public const string GenericError = "GenericError";

        // French puts a no-break space before ! ? : and inside guillemets.
        private const string Nbsp = " ";

        private static readonly Dictionary<string, Dictionary<string, string>> s_tables =
            new Dictionary<string, Dictionary<string, string>>
            {
                ["en"] = new Dictionary<string, string>
                {
                    [PageTitle] = "Verify your identity",
                    [ProviderDescription] = "AD FS Provider to authenticate with privacyIDEA.",
                    [OtpLabel] = "One-Time-Password",
                    [Submit] = "Submit",
                    [PushConfirm] = "I confirmed on my device",
                    [PushConfirmRegistration] = "I completed the registration",
                    [PushStop] = "Stop automatic check",
                    // {0} is the label of the PushConfirm or PushConfirmRegistration button.
                    [PushStopped] = "Automatic check stopped. After you confirm on your device, select \"{0}\".",
                    [PushNotConfirmed] = "Authentication not confirmed yet!",
                    [RegistrationNotCompleted] = "Registration not completed yet!",
                    [PushDeclined] = "The login request was declined on your device. Use another login option, or sign in again.",
                    [PushCancelled] = "The login request was cancelled on your device. Use another login option, or sign in again.",
                    [RegistrationCancelled] = "The registration was cancelled on your device.",
                    [PushRefusedOnOneDevice] = "The login request was declined on one of your devices. You can still " +
                        "confirm it on another device.",
                    [UseOtp] = "Use one-time password",
                    [UsePush] = "Use push",
                    [RememberDevice] = "Remember this device",
                    [RetryPasskeyRegistration] = "Retry Passkey Registration",
                    [NotNow] = "Not Now",
                    [OtherLoginOptions] = "Other Login Options",
                    [Passkey] = "Passkey",
                    [RetryPasskeyLogin] = "Retry Passkey Login",
                    [WebAuthn] = "WebAuthn",
                    [Push] = "Push",
                    [Otp] = "OTP",
                    [NoScript] = "JavaScript is disabled. Enter your one-time password and select Submit, or for push confirm " +
                        "on your device and select the button. Use the token-type buttons to switch between one-time " +
                        "password and push. Security key and passkey options need JavaScript and are hidden.",
                    [EnrollmentQrAlt] = "Enrollment QR code",
                    [EnrollmentLinkText] = "Alternatively, click on this link to enroll the new token.",
                    [LegacyIntro] = "It appears your account has not previously setup Multi-Factor Authentication (MFA).",
                    [LegacyWarning] = "Please carefully follow the instructions - they will only be shown once!",
                    [LegacyStep1] = "Download and/or install a TOTP compliant MFA app or Password Manager if you haven't " +
                        "already. Here are some recommendations:",
                    [LegacyStep2] = "Scan the following QR code or copy the enrollment link into your MFA app of choice.",
                    [LegacyLinkLabel] = "Enrollment link",
                    [LegacyCopy] = "Copy text",
                    [LegacyStep3] = "Paste the code that your app generates into the One-Time-Password field.",
                    [InternalError] = "Internal error. Please try again.",
                    [CancelEnrollmentFailed] = "Failed to cancel enrollment.",
                    [PasskeyStartFailed] = "Could not start Passkey authentication. Try again or use another token type.",
                    [PasskeyFailed] = "Could not complete Passkey authentication. Try again or use another token type.",
                    [PasskeyRegistrationFailed] = "Could not complete Passkey registration. Try again or use another token type.",
                    [WebAuthnFailed] = "Could not complete WebAuthn authentication. Try again or use another token type.",
                    [PasskeyWrongUser] = "The passkey is not for the user trying to log in!",
                    [ServerUnreachable] = "The authentication server could not be reached.",
                    [GenericError] = "An error occurred.",
                },
                ["de"] = new Dictionary<string, string>
                {
                    [PageTitle] = "Identität bestätigen",
                    [ProviderDescription] = "AD FS-Provider für die Anmeldung mit privacyIDEA.",
                    [OtpLabel] = "Einmalpasswort",
                    [Submit] = "Anmelden",
                    [PushConfirm] = "Ich habe auf meinem Gerät bestätigt",
                    [PushConfirmRegistration] = "Ich habe die Registrierung abgeschlossen",
                    [PushStop] = "Automatische Prüfung beenden",
                    [PushStopped] = "Die automatische Prüfung ist beendet. Wenn Sie auf Ihrem Gerät bestätigt haben, wählen Sie „{0}“.",
                    [PushNotConfirmed] = "Anmeldung noch nicht bestätigt!",
                    [RegistrationNotCompleted] = "Registrierung noch nicht abgeschlossen!",
                    [PushDeclined] = "Die Anmeldeanfrage wurde auf Ihrem Gerät abgelehnt. Verwenden Sie eine andere " +
                        "Anmeldeoption oder melden Sie sich erneut an.",
                    [PushCancelled] = "Die Anmeldeanfrage wurde auf Ihrem Gerät abgebrochen. Verwenden Sie eine andere " +
                        "Anmeldeoption oder melden Sie sich erneut an.",
                    [RegistrationCancelled] = "Die Registrierung wurde auf Ihrem Gerät abgebrochen.",
                    [PushRefusedOnOneDevice] = "Die Anmeldeanfrage wurde auf einem Ihrer Geräte abgelehnt. Sie können " +
                        "sie noch auf einem anderen Gerät bestätigen.",
                    [UseOtp] = "Einmalpasswort verwenden",
                    [UsePush] = "Push verwenden",
                    [RememberDevice] = "Dieses Gerät merken",
                    [RetryPasskeyRegistration] = "Passkey-Registrierung wiederholen",
                    [NotNow] = "Jetzt nicht",
                    [OtherLoginOptions] = "Andere Anmeldeoptionen",
                    [Passkey] = "Passkey",
                    [RetryPasskeyLogin] = "Passkey-Anmeldung wiederholen",
                    [WebAuthn] = "WebAuthn",
                    [Push] = "Push",
                    [Otp] = "Einmalpasswort",
                    [NoScript] = "JavaScript ist deaktiviert. Geben Sie Ihr Einmalpasswort ein und wählen Sie „Anmelden“. " +
                        "Für Push bestätigen Sie auf Ihrem Gerät und wählen dann die Schaltfläche. Mit den Schaltflächen " +
                        "für die Token-Art wechseln Sie zwischen Einmalpasswort und Push. Sicherheitsschlüssel und " +
                        "Passkeys benötigen JavaScript und sind ausgeblendet.",
                    [EnrollmentQrAlt] = "QR-Code für die Registrierung",
                    [EnrollmentLinkText] = "Alternativ klicken Sie auf diesen Link, um den neuen Token einzurichten.",
                    [LegacyIntro] = "Für Ihr Konto ist noch keine Multi-Faktor-Authentifizierung (MFA) eingerichtet.",
                    [LegacyWarning] = "Bitte folgen Sie sorgfältig den Anweisungen. Sie werden nur einmal angezeigt!",
                    [LegacyStep1] = "Installieren Sie eine TOTP-fähige MFA-App oder einen Passwort-Manager, falls noch " +
                        "nicht geschehen. Einige Empfehlungen:",
                    [LegacyStep2] = "Scannen Sie den folgenden QR-Code oder kopieren Sie den Registrierungslink in Ihre MFA-App.",
                    [LegacyLinkLabel] = "Registrierungslink",
                    [LegacyCopy] = "Text kopieren",
                    [LegacyStep3] = "Fügen Sie den Code, den Ihre App erzeugt, in das Feld „Einmalpasswort“ ein.",
                    [InternalError] = "Interner Fehler. Bitte versuchen Sie es erneut.",
                    [CancelEnrollmentFailed] = "Die Registrierung konnte nicht übersprungen werden.",
                    [PasskeyStartFailed] = "Die Passkey-Anmeldung konnte nicht gestartet werden. Versuchen Sie es erneut " +
                        "oder verwenden Sie eine andere Token-Art.",
                    [PasskeyFailed] = "Die Passkey-Anmeldung konnte nicht abgeschlossen werden. Versuchen Sie es erneut " +
                        "oder verwenden Sie eine andere Token-Art.",
                    [PasskeyRegistrationFailed] = "Die Passkey-Registrierung konnte nicht abgeschlossen werden. Versuchen " +
                        "Sie es erneut oder verwenden Sie eine andere Token-Art.",
                    [WebAuthnFailed] = "Die WebAuthn-Anmeldung konnte nicht abgeschlossen werden. Versuchen Sie es erneut " +
                        "oder verwenden Sie eine andere Token-Art.",
                    [PasskeyWrongUser] = "Der Passkey gehört nicht zu dem Benutzer, der sich anmeldet!",
                    [ServerUnreachable] = "Der Authentifizierungsserver ist nicht erreichbar.",
                    [GenericError] = "Ein Fehler ist aufgetreten.",
                },
                ["fr"] = new Dictionary<string, string>
                {
                    [PageTitle] = "Vérifiez votre identité",
                    [ProviderDescription] = "Fournisseur AD FS pour l'authentification avec privacyIDEA.",
                    [OtpLabel] = "Mot de passe à usage unique",
                    [Submit] = "Se connecter",
                    [PushConfirm] = "J'ai confirmé sur mon appareil",
                    [PushConfirmRegistration] = "J'ai terminé l'enregistrement",
                    [PushStop] = "Arrêter la vérification automatique",
                    [PushStopped] = "La vérification automatique est arrêtée. Après avoir confirmé sur votre appareil, " +
                        "sélectionnez «" + Nbsp + "{0}" + Nbsp + "».",
                    [PushNotConfirmed] = "L'authentification n'a pas encore été confirmée" + Nbsp + "!",
                    [RegistrationNotCompleted] = "L'enregistrement n'est pas encore terminé" + Nbsp + "!",
                    [PushDeclined] = "La demande de connexion a été refusée sur votre appareil. Utilisez une autre option " +
                        "de connexion ou reconnectez-vous.",
                    [PushCancelled] = "La demande de connexion a été annulée sur votre appareil. Utilisez une autre option " +
                        "de connexion ou reconnectez-vous.",
                    [RegistrationCancelled] = "L'enregistrement a été annulé sur votre appareil.",
                    [PushRefusedOnOneDevice] = "La demande de connexion a été refusée sur l'un de vos appareils. Vous " +
                        "pouvez encore la confirmer sur un autre appareil.",
                    [UseOtp] = "Utiliser un mot de passe à usage unique",
                    [UsePush] = "Utiliser Push",
                    [RememberDevice] = "Mémoriser cet appareil",
                    [RetryPasskeyRegistration] = "Réessayer l'enregistrement de la clé d'accès",
                    [NotNow] = "Pas maintenant",
                    [OtherLoginOptions] = "Autres options de connexion",
                    [Passkey] = "Clé d'accès",
                    [RetryPasskeyLogin] = "Réessayer la connexion par clé d'accès",
                    [WebAuthn] = "WebAuthn",
                    [Push] = "Push",
                    [Otp] = "Mot de passe à usage unique",
                    [NoScript] = "JavaScript est désactivé. Saisissez votre mot de passe à usage unique et sélectionnez «" +
                        Nbsp + "Se connecter" + Nbsp + "». Pour Push, confirmez sur votre appareil, puis sélectionnez le " +
                        "bouton. Utilisez les boutons de type de jeton pour passer du mot de passe à usage unique à Push. " +
                        "Les options clé de sécurité et clé d'accès nécessitent JavaScript et sont masquées.",
                    [EnrollmentQrAlt] = "Code QR d'enregistrement",
                    [EnrollmentLinkText] = "Vous pouvez également cliquer sur ce lien pour enregistrer le nouveau jeton.",
                    [LegacyIntro] = "Votre compte ne dispose pas encore d'une authentification multifacteur (MFA).",
                    [LegacyWarning] = "Suivez attentivement les instructions. Elles ne seront affichées qu'une seule fois" + Nbsp + "!",
                    [LegacyStep1] = "Si ce n'est pas déjà fait, installez une application MFA compatible TOTP ou un " +
                        "gestionnaire de mots de passe. Quelques recommandations" + Nbsp + ":",
                    [LegacyStep2] = "Scannez le code QR suivant ou copiez le lien d'enregistrement dans votre application MFA.",
                    [LegacyLinkLabel] = "Lien d'enregistrement",
                    [LegacyCopy] = "Copier le texte",
                    [LegacyStep3] = "Collez le code généré par votre application dans le champ «" + Nbsp +
                        "Mot de passe à usage unique" + Nbsp + "».",
                    [InternalError] = "Erreur interne. Veuillez réessayer.",
                    [CancelEnrollmentFailed] = "Impossible d'ignorer l'enregistrement.",
                    [PasskeyStartFailed] = "Impossible de démarrer l'authentification par clé d'accès. Réessayez ou " +
                        "utilisez un autre type de jeton.",
                    [PasskeyFailed] = "Impossible de terminer l'authentification par clé d'accès. Réessayez ou utilisez " +
                        "un autre type de jeton.",
                    [PasskeyRegistrationFailed] = "Impossible de terminer l'enregistrement de la clé d'accès. Réessayez ou " +
                        "utilisez un autre type de jeton.",
                    [WebAuthnFailed] = "Impossible de terminer l'authentification WebAuthn. Réessayez ou utilisez un " +
                        "autre type de jeton.",
                    [PasskeyWrongUser] = "La clé d'accès n'appartient pas à l'utilisateur qui se connecte" + Nbsp + "!",
                    [ServerUnreachable] = "Le serveur d'authentification est injoignable.",
                    [GenericError] = "Une erreur s'est produite.",
                },
            };

        /// <summary>All keys, in the order of the English table.</summary>
        public static IEnumerable<string> Keys => s_tables[DefaultLanguage].Keys;

        /// <summary>The two-letter language whose table serves the LCID: "en", "de" or "fr".</summary>
        public static string Language(int lcid)
        {
            try
            {
                string language = CultureInfo.GetCultureInfo(lcid).TwoLetterISOLanguageName;
                return s_tables.ContainsKey(language) ? language : DefaultLanguage;
            }
            catch (ArgumentException)
            {
                // CultureNotFoundException and ArgumentOutOfRangeException: an LCID that Windows does not know.
                return DefaultLanguage;
            }
        }

        /// <summary>The text for the key in the language of the LCID. Falls back to English.</summary>
        public static string Get(int lcid, string key)
        {
            if (s_tables[Language(lcid)].TryGetValue(key, out string text))
            {
                return text;
            }
            return s_tables[DefaultLanguage][key];
        }

        /// <summary>Keys that the language does not translate. Empty for every shipped language.</summary>
        internal static IEnumerable<string> MissingKeys(string language) =>
            Keys.Where(key => !s_tables[language].ContainsKey(key));

        internal static IEnumerable<string> Languages => s_tables.Keys;
    }
}
