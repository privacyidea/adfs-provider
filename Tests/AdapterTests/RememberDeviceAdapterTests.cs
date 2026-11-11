using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Claims;
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
    /// Covers the "remember device" issuance path in Adapter.TryEndAuthentication: when the user opts in and
    /// the capability is on, a successful authentication does not return claims directly. Instead the adapter
    /// renders a short auto-submit page that stores the device cookie via JavaScript (an AD FS adapter cannot
    /// set a response cookie), and the follow-up submit then returns the claims.
    /// Recognition (BeginAuthentication) reads the cookie from the HTTP request, which is a sealed
    /// HttpListenerRequest that cannot be constructed in a unit test, so that path is covered at the client
    /// level in RememberDeviceClientTests.
    /// </summary>
    [TestClass]
    public class RememberDeviceAdapterTests
    {
        private const string OtpAuthMethod = "http://schemas.microsoft.com/ws/2012/12/authmethod/otp";

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

        private Adapter NewAdapter(bool rememberEnabled)
        {
            var adapter = new Adapter();

            System.Type configType = typeof(Adapter).Assembly.GetType("PrivacyIDEAADFSProvider.Configuration");
            object config = RuntimeHelpers.GetUninitializedObject(configType);
            SetPrivateField(adapter, "_config", config);

            PrivacyIDEA pi = TestHelpers.PIPointedAt(_server);
            pi.ApiKey = "secret-key";
            SetPrivateField(adapter, "_privacyIDEA", pi);
            SetPrivateField(adapter, "_rememberDeviceEnabled", rememberEnabled);

            return adapter;
        }

        private static void SetPrivateField(object target, string field, object value)
        {
            FieldInfo fi = target.GetType().GetField(field, BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.IsNotNull(fi, $"Field {field} not found on {target.GetType().Name}.");
            fi.SetValue(target, value);
        }

        private static Dictionary<string, object> MinimalContext() => new Dictionary<string, object>
        {
            ["userid"] = "alice",
            ["domain"] = "example.com",
        };

        private void StubAcceptWithCookie() =>
            _server.Given(
                    Request.Create().WithPath("/validate/check").UsingPost()
                        .WithBody(b => b != null && b.Contains("request_persistent_cookie=1")))
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Set-Cookie", "pi_remember_device=abc-series:1; Max-Age=3600; Path=/; Secure; HttpOnly; SameSite=Strict")
                    .WithBody(OtpFixtures.SimpleAccept));

        [TestMethod]
        public void OptIn_Success_RendersCookieSetPage_ThenClaims()
        {
            StubAcceptWithCookie();
            var adapter = NewAdapter(rememberEnabled: true);
            var proof = new FakeProofData(new Dictionary<string, object>
            {
                ["formResult"] = "{\"rememberDevice\":true}",
                ["otp"] = "123456",
            });
            var ctx = new FakeAuthContext(MinimalContext());

            // First submit: authentication succeeds, but a cookie was issued, so the adapter returns the
            // auto-submit cookie-set page instead of claims.
            IAdapterPresentation first = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] firstClaims);

            Assert.IsNotNull(first, "A cookie was issued, so the adapter must render the cookie-set page.");
            Assert.AreEqual(0, firstClaims.Length);
            Assert.AreEqual("1", ctx.Data["authSuccess"], "authSuccess must be set so the follow-up submit completes.");
            string html = ((IAdapterPresentationForm)first).GetFormHtml(1033);
            StringAssert.Contains(html, "abc-series:1", "The issued cookie value must reach the page for the JS to set it.");
            StringAssert.Contains(html, "name=\"autoSubmit\" value=\"1\"", "The page auto-submits (autoSubmit=1).");

            // Follow-up submit (the page auto-posts): authSuccess short-circuits and the claims are emitted.
            IAdapterPresentation second = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] secondClaims);

            Assert.IsNull(second);
            Assert.AreEqual(1, secondClaims.Length);
            Assert.AreEqual(OtpAuthMethod, secondClaims[0].Value);
        }

        [TestMethod]
        public void NoJavaScriptCheckbox_PlainField_AlsoIssues()
        {
            // Without JavaScript the checkbox posts a plain rememberDevice=1 field (formResult is empty).
            StubAcceptWithCookie();
            var adapter = NewAdapter(rememberEnabled: true);
            var proof = new FakeProofData(new Dictionary<string, object>
            {
                ["formResult"] = "",
                ["rememberDevice"] = "1",
                ["otp"] = "123456",
            });
            var ctx = new FakeAuthContext(MinimalContext());

            IAdapterPresentation result = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] claims);

            Assert.IsNotNull(result, "The plain rememberDevice field must also trigger issuance.");
            Assert.AreEqual(0, claims.Length);
            StringAssert.Contains(((IAdapterPresentationForm)result).GetFormHtml(1033), "abc-series:1");
        }

        [TestMethod]
        public void NotOptedIn_Success_ReturnsClaimsDirectly_NoCookiePage()
        {
            // Capability on, but the user did not tick the box: the normal validate/check runs (no
            // request_persistent_cookie), so authentication returns claims directly with no extra page.
            _server.Given(Request.Create().WithPath("/validate/check").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpFixtures.SimpleAccept));
            var adapter = NewAdapter(rememberEnabled: true);
            var proof = new FakeProofData(new Dictionary<string, object>
            {
                ["formResult"] = "{\"rememberDevice\":false}",
                ["otp"] = "123456",
            });
            var ctx = new FakeAuthContext(MinimalContext());

            IAdapterPresentation result = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] claims);

            Assert.IsNull(result);
            Assert.AreEqual(1, claims.Length);
        }

        [TestMethod]
        public void CapabilityOff_OptInIgnored_ReturnsClaimsDirectly()
        {
            // The server does not offer the feature (capability cached off). Even if the client posts
            // rememberDevice=true, no cookie is requested and authentication returns claims directly.
            _server.Given(Request.Create().WithPath("/validate/check").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpFixtures.SimpleAccept));
            var adapter = NewAdapter(rememberEnabled: false);
            var proof = new FakeProofData(new Dictionary<string, object>
            {
                ["formResult"] = "{\"rememberDevice\":true}",
                ["otp"] = "123456",
            });
            var ctx = new FakeAuthContext(MinimalContext());

            IAdapterPresentation result = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] claims);

            Assert.IsNull(result);
            Assert.AreEqual(1, claims.Length);
        }
    }
}
