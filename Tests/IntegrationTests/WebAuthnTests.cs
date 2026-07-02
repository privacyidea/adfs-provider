using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Tests.Fixtures;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Tests.IntegrationTests
{
    /// <summary>
    /// Wire-level checks for ValidateCheckWebAuthn: Origin header, parameter shape,
    /// short-circuit on missing required args.
    /// </summary>
    [TestClass]
    public class WebAuthnTests
    {
        private WireMockServer _server;

        [TestInitialize]
        public void Setup() => _server = WireMockServer.Start();

        [TestCleanup]
        public void Cleanup() => _server.Stop();

        [TestMethod]
        public void ValidateCheckWebAuthn_AddsOriginHeader_AndSendsUserAndEmptyPass()
        {
            _server.Given(
                    Request.Create()
                        .WithPath("/validate/check")
                        .UsingPost()
                        .WithHeader("Origin", "https://sso.example.com")
                        .WithBody(b => b != null && b.Contains("user=alice") && b.Contains("pass=")))
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpFixtures.SimpleAccept));

            var pi = TestHelpers.PIPointedAt(_server);
            var resp = pi.ValidateCheckWebAuthn(
                user: "alice",
                transactionid: "tx-wa-1",
                webAuthnSignResponse: "{\"credentialid\":\"c\",\"clientdata\":\"cd\",\"signaturedata\":\"s\",\"authenticatordata\":\"ad\"}",
                origin: "https://sso.example.com");

            // Assert success, not just non-null: an unmatched stub returns WireMock's default
            // (parseable) body, so only IsTrue proves the Origin header + body predicate actually matched.
            Assert.IsNotNull(resp);
            Assert.IsTrue(resp.isAuthenticationSuccessful());
        }

        [TestMethod]
        public void ValidateCheckWebAuthn_UriEscapes_Fido2Fields()
        {
            // FIDO2 field values are percent-encoded like every other form field (matching privacyIDEA's
            // canonical request format). A value containing +, /, = must reach the wire escaped as
            // %2B, %2F, %3D — not raw. Real browser values are base64url so escaping is a no-op for them;
            // this synthetic standard-base64 value exercises the encoding path.
            _server.Given(
                    Request.Create()
                        .WithPath("/validate/check")
                        .UsingPost()
                        .WithBody(b => b != null && b.Contains("credential_id=A%2BB%2FC%3D")))
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpFixtures.SimpleAccept));

            var pi = TestHelpers.PIPointedAt(_server);
            var resp = pi.ValidateCheckWebAuthn(
                user: "alice",
                transactionid: "tx-wa-2",
                webAuthnSignResponse: "{\"credentialid\":\"A+B/C=\",\"clientdata\":\"cd\",\"signaturedata\":\"s\",\"authenticatordata\":\"ad\"}",
                origin: "https://sso.example.com");

            // Must assert success, not just non-null: an unmatched WireMock stub returns a default
            // (parseable) body, so IsNotNull alone would pass even if the body predicate never matched.
            Assert.IsNotNull(resp);
            Assert.IsTrue(resp.isAuthenticationSuccessful());
        }

        [TestMethod]
        public void ValidateCheckWebAuthn_EscapesFido2Field_PreventingParameterInjection()
        {
            // A crafted userHandle tries to smuggle an extra parameter (&user=victim) into the request
            // body. Because every value is URL-encoded, the '&' and '=' are escaped (%26, %3D) and cannot
            // start a new key/value pair — so an injected, unescaped "&user=victim" never appears.
            _server.Given(
                    Request.Create()
                        .WithPath("/validate/check")
                        .UsingPost()
                        .WithBody(b => b != null && b.Contains("userHandle=x%26user%3Dvictim") && !b.Contains("&user=victim")))
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpFixtures.SimpleAccept));

            var pi = TestHelpers.PIPointedAt(_server);
            var resp = pi.ValidateCheckWebAuthn(
                user: "alice",
                transactionid: "tx-wa-3",
                webAuthnSignResponse: "{\"credentialid\":\"c\",\"clientdata\":\"cd\",\"signaturedata\":\"s\",\"authenticatordata\":\"ad\",\"userHandle\":\"x&user=victim\"}",
                origin: "https://sso.example.com");

            Assert.IsNotNull(resp);
            Assert.IsTrue(resp.isAuthenticationSuccessful());
        }

        [TestMethod]
        public void ValidateCheckWebAuthn_WithMissingArgs_ShortCircuitsAndReturnsNull()
        {
            var pi = TestHelpers.PIPointedAt(_server);

            Assert.IsNull(pi.ValidateCheckWebAuthn("", "tx", "sign", "https://sso.example.com"));
            Assert.IsNull(pi.ValidateCheckWebAuthn("alice", "", "sign", "https://sso.example.com"));
            Assert.IsNull(pi.ValidateCheckWebAuthn("alice", "tx", "", "https://sso.example.com"));
            Assert.IsNull(pi.ValidateCheckWebAuthn("alice", "tx", "sign", ""));

            Assert.AreEqual(0, _server.LogEntries.Count());
        }
    }
}
