using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.IdentityServer.Web.Authentication.External;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using privacyIDEAADFSProvider;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using Tests.Fixtures;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Tests.AdapterTests
{
    /// <summary>
    /// The login page: the English, German and French texts (chosen by the LCID that AD FS passes), the
    /// visible label of the OTP field, and the push check (interval, stop, declined push, focus).
    /// </summary>
    [TestClass]
    public class LoginPageTests
    {
        private const int English = 1033;
        private const int German = 1031;
        private const int French = 1036;
        private const int Italian = 1040;

        private static readonly Assembly s_provider = typeof(Adapter).Assembly;

        private WireMockServer _server;

        [TestInitialize]
        public void Setup() => _server = WireMockServer.Start();

        [TestCleanup]
        public void Cleanup() => _server.Stop();

        private sealed class FakeProofData : IProofData
        {
            public Dictionary<string, object> Properties { get; }
            public FakeProofData(Dictionary<string, object> properties) => Properties = properties;
        }

        private sealed class FakeAuthContext : IAuthenticationContext
        {
            public int Lcid => 1033;
            public string ActivityId => "activity";
            public string ContextId => "context";
            public Dictionary<string, object> Data { get; }
            public FakeAuthContext(Dictionary<string, object> data) => Data = data;
        }

        /// The Adapter with an uninitialized Configuration (its constructor reads the registry), pointed at the
        /// mock server. configure can set Configuration properties.
        private Adapter NewAdapter(Action<object> configure = null)
        {
            var adapter = new Adapter();
            Type configType = s_provider.GetType("PrivacyIDEAADFSProvider.Configuration");
            object config = RuntimeHelpers.GetUninitializedObject(configType);
            configure?.Invoke(config);
            SetField(adapter, "_config", config);
            SetField(adapter, "_privacyIDEA", TestHelpers.PIPointedAt(_server));
            return adapter;
        }

        private static void SetField(object target, string field, object value)
        {
            FieldInfo fi = target.GetType().GetField(field, BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.IsNotNull(fi, $"Field {field} not found on {target.GetType().Name}.");
            fi.SetValue(target, value);
        }

        private static void SetProperty(object target, string property, object value) =>
            target.GetType().GetProperty(property).SetValue(target, value);

        private static object GetProperty(object target, string property) =>
            target.GetType().GetProperty(property).GetValue(target);

        /// A new, empty AdapterPresentationForm (internal type).
        private static IAdapterPresentationForm NewForm() =>
            (IAdapterPresentationForm)Activator.CreateInstance(
                s_provider.GetType("PrivacyIDEAADFSProvider.AdapterPresentationForm"));

        private static Dictionary<string, object> PushContext(string previousResponse = PushFixtures.PushChallenge) =>
            new Dictionary<string, object>
            {
                ["userid"] = "alice",
                ["domain"] = "example.com",
                ["previousResponse"] = previousResponse,
            };

        private void StubPoll(string body) =>
            _server.Given(Request.Create().WithPath("/validate/polltransaction").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(body));

        /// Posts a push check of the page (mode=push) with the given extra fields.
        private IAdapterPresentationForm PostPushCheck(Adapter adapter, Dictionary<string, object> extra = null)
        {
            var fields = new Dictionary<string, object> { ["formResult"] = "", ["mode"] = "push" };
            if (extra != null)
            {
                foreach (var kv in extra) fields[kv.Key] = kv.Value;
            }
            IAdapterPresentation result = adapter.TryEndAuthentication(new FakeAuthContext(PushContext()),
                new FakeProofData(fields), null, out Claim[] claims);
            Assert.AreEqual(0, claims.Length, "The push check must not authenticate.");
            Assert.IsNotNull(result);
            return (IAdapterPresentationForm)result;
        }

        // ---- Texts ----

        [TestMethod]
        public void Texts_EveryLanguageHasEveryKey()
        {
            Type texts = s_provider.GetType("PrivacyIDEAADFSProvider.Texts");
            var languages = ((IEnumerable<string>)texts.GetProperty("Languages", BindingFlags.Static | BindingFlags.NonPublic)
                .GetValue(null)).ToList();
            CollectionAssert.AreEquivalent(new[] { "en", "de", "fr" }, languages);
            MethodInfo missingKeys = texts.GetMethod("MissingKeys", BindingFlags.Static | BindingFlags.NonPublic);
            foreach (string language in languages)
            {
                var missing = ((IEnumerable<string>)missingKeys.Invoke(null, new object[] { language })).ToList();
                Assert.AreEqual(0, missing.Count, $"Language {language} has no text for: {string.Join(", ", missing)}");
            }
        }

        [TestMethod]
        [DataRow(English, "Other Login Options", "value=\"Submit\"", "One-Time-Password")]
        [DataRow(German, "Andere Anmeldeoptionen", "value=\"Anmelden\"", "Einmalpasswort")]
        [DataRow(3079, "Andere Anmeldeoptionen", "value=\"Anmelden\"", "Einmalpasswort")] // de-AT
        [DataRow(French, "Autres options de connexion", "value=\"Se connecter\"", "Mot de passe ")]
        [DataRow(Italian, "Other Login Options", "value=\"Submit\"", "One-Time-Password")] // no Italian table
        [DataRow(0, "Other Login Options", "value=\"Submit\"", "One-Time-Password")]
        [DataRow(-5, "Other Login Options", "value=\"Submit\"", "One-Time-Password")]
        public void GetFormHtml_UsesTheLanguageOfTheLcid(int lcid, string otherOptions, string submit, string otpLabel)
        {
            string html = NewForm().GetFormHtml(lcid);

            StringAssert.Contains(html, otherOptions);
            StringAssert.Contains(html, submit);
            StringAssert.Contains(html, "<label for=\"otp\" class=\"block\">" + otpLabel);
        }

        [TestMethod]
        [DataRow(English)]
        [DataRow(German)]
        [DataRow(French)]
        public void GetFormHtml_LeavesNoTokenUnreplaced(int lcid)
        {
            string html = NewForm().GetFormHtml(lcid);

            var leftOver = Regex.Matches(html, "#[A-Za-z]+#").Cast<Match>().Select(m => m.Value).ToList();
            Assert.AreEqual(0, leftOver.Count, "Unreplaced tokens: " + string.Join(", ", leftOver));
        }

        [TestMethod]
        public void GetPageTitle_NamesTheTaskInTheLanguageOfThePage()
        {
            IAdapterPresentationForm form = NewForm();
            Assert.AreEqual("Verify your identity", form.GetPageTitle(English));
            Assert.AreEqual("Identität bestätigen", form.GetPageTitle(German));
            Assert.AreEqual("Vérifiez votre identité", form.GetPageTitle(French));
            Assert.AreEqual("Verify your identity", form.GetPageTitle(Italian));
        }

        [TestMethod]
        public void Metadata_EnglishFirst_DescriptionTranslated()
        {
            IAuthenticationAdapterMetadata metadata = new Adapter().Metadata;
            Assert.AreEqual(English, metadata.AvailableLcids[0], "English must be the first language.");
            Assert.AreEqual("AD FS Provider to authenticate with privacyIDEA.", metadata.Descriptions[English]);
            Assert.AreEqual("AD FS-Provider für die Anmeldung mit privacyIDEA.", metadata.Descriptions[German]);
            Assert.AreEqual("Fournisseur AD FS pour l'authentification avec privacyIDEA.", metadata.Descriptions[French]);
            foreach (int lcid in metadata.AvailableLcids)
            {
                Assert.IsTrue(metadata.FriendlyNames.ContainsKey(lcid) && metadata.Descriptions.ContainsKey(lcid));
            }
        }

        [TestMethod]
        public void AdapterMessage_IsShownInTheLanguageOfThePage_ErrorMessageStaysEnglish()
        {
            // A formResult that is not JSON gives the provider's own "internal error" message.
            var adapter = NewAdapter();
            IAdapterPresentation result = adapter.TryEndAuthentication(
                new FakeAuthContext(new Dictionary<string, object> { ["userid"] = "alice", ["domain"] = "example.com" }),
                new FakeProofData(new Dictionary<string, object> { ["formResult"] = "{not json" }), null, out _);

            Assert.AreEqual("Internal error. Please try again.", GetProperty(result, "ErrorMessage"));
            var form = (IAdapterPresentationForm)result;
            StringAssert.Contains(form.GetFormHtml(French), "Erreur interne. Veuillez r");
            StringAssert.Contains(form.GetFormHtml(German), "Interner Fehler. Bitte versuchen Sie es erneut.");
        }

        [TestMethod]
        public void ServerMessage_IsShownUnchanged()
        {
            // A message that the server sends is already in the user's language (Accept-Language): no lookup.
            IAdapterPresentationForm form = NewForm();
            SetProperty(form, "ErrorMessage", "Falsches Einmalpasswort");
            StringAssert.Contains(form.GetFormHtml(French), ">Falsches Einmalpasswort</p>");
        }

        // ---- OTP label ----

        [TestMethod]
        public void OtpLabel_WithoutServerMessage_ShowsTheDefaultText()
        {
            // Default configuration: no challenge is triggered, so there is no server message. The field still
            // gets a visible label, not only a placeholder.
            string html = NewForm().GetFormHtml(English);
            StringAssert.Contains(html, "<label for=\"otp\" class=\"block\">One-Time-Password</label>");
            StringAssert.Contains(html, "placeholder=\"One-Time-Password\"");
        }

        [TestMethod]
        public void OtpLabel_WithOtpHint_ShowsTheHint()
        {
            IAdapterPresentationForm form = NewForm();
            SetProperty(form, "OtpHint", "Token code");
            string html = form.GetFormHtml(German);
            StringAssert.Contains(html, "<label for=\"otp\" class=\"block\">Token code</label>");
            StringAssert.Contains(html, "placeholder=\"Token code\"");
        }

        [TestMethod]
        public void OtpLabel_WithServerMessage_ShowsTheMessage()
        {
            IAdapterPresentationForm form = NewForm();
            SetProperty(form, "Message", "Please enter the OTP from your app");
            string html = form.GetFormHtml(English);
            StringAssert.Contains(html, "<label for=\"otp\" class=\"block\">Please enter the OTP from your app</label>");
            StringAssert.Contains(html, "placeholder=\"One-Time-Password\"");
        }

        // ---- Push check ----

        [TestMethod]
        public void PushPollInterval_DefaultIsThreeSeconds()
        {
            StubPoll(PushFixtures.PollPending);
            string html = PostPushCheck(NewAdapter()).GetFormHtml(English);
            StringAssert.Contains(html, "id=\"pushPollInterval\" type=\"hidden\" value=\"3\"");
        }

        [TestMethod]
        public void PushPollInterval_ComesFromTheConfiguration()
        {
            StubPoll(PushFixtures.PollPending);
            var adapter = NewAdapter(config => SetProperty(config, "PushPollInterval", 7));
            string html = PostPushCheck(adapter).GetFormHtml(English);
            StringAssert.Contains(html, "id=\"pushPollInterval\" type=\"hidden\" value=\"7\"");
        }

        [TestMethod]
        public void PushPending_KeepsStopStateStartTimeAndFocus()
        {
            StubPoll(PushFixtures.PollPending);
            IAdapterPresentationForm form = PostPushCheck(NewAdapter(), new Dictionary<string, object>
            {
                ["pushPollState"] = "stopped",
                ["pushPollStarted"] = "1764000000000",
                ["focusId"] = "useOTPButton",
            });

            Assert.AreEqual("Authentication not confirmed yet!", GetProperty(form, "ErrorMessage"));
            string html = form.GetFormHtml(English);
            StringAssert.Contains(html, "name=\"pushPollState\" value=\"stopped\"");
            StringAssert.Contains(html, "name=\"pushPollStarted\" value=\"1764000000000\"");
            StringAssert.Contains(html, "name=\"focusId\" value=\"useOTPButton\"");
            StringAssert.Contains(form.GetFormHtml(German), "Anmeldung noch nicht best");
        }

        [TestMethod]
        public void PushPending_DropsValuesThatThePageDoesNotSend()
        {
            // "refused" comes only from the server. The start time is digits only, the focus id letters only:
            // both go back into the page.
            StubPoll(PushFixtures.PollPending);
            IAdapterPresentationForm form = PostPushCheck(NewAdapter(), new Dictionary<string, object>
            {
                ["pushPollState"] = "refused",
                ["pushPollStarted"] = "12a",
                ["focusId"] = "x\" onfocus=\"alert(1)",
            });

            string html = form.GetFormHtml(English);
            StringAssert.Contains(html, "name=\"pushPollState\" value=\"\"");
            StringAssert.Contains(html, "name=\"pushPollStarted\" value=\"\"");
            StringAssert.Contains(html, "name=\"focusId\" value=\"\"");
            StringAssert.Contains(html, "data-push-state=\"\"");
        }

        [TestMethod]
        [DataRow(PushFixtures.PollDeclined, "The login request was declined on your device. Use another login option, or sign in again.",
            "Die Anmeldeanfrage wurde auf Ihrem Ger")]
        [DataRow(PushFixtures.PollCancelled, "The login request was cancelled on your device. Use another login option, or sign in again.",
            "Die Anmeldeanfrage wurde auf Ihrem Ger")]
        public void PushRefusedOnTheDevice_StopsTheCheckAndSaysWhy(string pollBody, string english, string germanStart)
        {
            StubPoll(pollBody);
            IAdapterPresentationForm form = PostPushCheck(NewAdapter(), new Dictionary<string, object>
            {
                ["pushPollStarted"] = "1764000000000",
            });

            Assert.AreEqual(english, GetProperty(form, "ErrorMessage"));
            string html = form.GetFormHtml(English);
            StringAssert.Contains(html, "data-push-state=\"refused\"");
            StringAssert.Contains(html, "name=\"pushPollState\" value=\"refused\"");
            StringAssert.Contains(form.GetFormHtml(German), germanStart);
            // No /validate/check: a refused push cannot finish the login.
            Assert.IsFalse(_server.LogEntries.Any(e => e.RequestMessage.Path == "/validate/check"));
        }

        [TestMethod]
        public void RegistrationCancelledOnTheDevice_SaysSo()
        {
            // Poll-mode enrollment (smartphone or push registration): the page carries the QR image.
            StubPoll(PushFixtures.PollCancelled);
            IAdapterPresentationForm form = PostPushCheck(NewAdapter(), new Dictionary<string, object>
            {
                ["enrollmentImg"] = "data:image/png;base64,AAAA",
                ["disableOTP"] = "1",
            });

            Assert.AreEqual("The registration was cancelled on your device.", GetProperty(form, "ErrorMessage"));
            StringAssert.Contains(form.GetFormHtml(English), "data-push-state=\"refused\"");
        }

        [TestMethod]
        public void PushOnAnOldServer_WithoutChallengeStatus_KeepsChecking()
        {
            StubPoll(PushFixtures.PollPendingNoDetail);
            IAdapterPresentationForm form = PostPushCheck(NewAdapter());

            Assert.AreEqual("Authentication not confirmed yet!", GetProperty(form, "ErrorMessage"));
            StringAssert.Contains(form.GetFormHtml(English), "data-push-state=\"\"");
        }

        [TestMethod]
        public void ModeSwitch_ResetsThePushCheck()
        {
            // The user switches to OTP and back to push later: that push starts with automatic checks again.
            var adapter = NewAdapter();
            IAdapterPresentation result = adapter.TryEndAuthentication(new FakeAuthContext(PushContext()),
                new FakeProofData(new Dictionary<string, object>
                {
                    ["formResult"] = "{\"modeChanged\": true, \"newMode\": \"otp\"}",
                    ["mode"] = "push",
                    ["pushPollState"] = "stopped",
                    ["pushPollStarted"] = "1764000000000",
                    ["focusId"] = "useOTPButton",
                }), null, out _);

            string html = ((IAdapterPresentationForm)result).GetFormHtml(English);
            StringAssert.Contains(html, "name=\"pushPollState\" value=\"\"");
            StringAssert.Contains(html, "name=\"pushPollStarted\" value=\"\"");
            StringAssert.Contains(html, "name=\"focusId\" value=\"\"");
        }

        [TestMethod]
        public void PushButtons_AccessibleNameIsTheVisibleText()
        {
            // WCAG 2.5.3: no aria-label that replaces the visible text of a button.
            string html = NewForm().GetFormHtml(English);
            Assert.IsFalse(Regex.IsMatch(html, "<input[^>]*type=\"button\"[^>]*aria-label="),
                "A button has an aria-label: its accessible name differs from the visible text.");
            StringAssert.Contains(html, "role=\"group\" aria-labelledby=\"alternateTokenLabel\"");
        }
    }
}
