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
        public void ValidateCheckWebAuthn_DoesNotUriEscape_Fido2Fields()
        {
            // The input alias 'credentialid' is normalized to the canonical wire key 'credential_id',
            // which is on the exclude list so the value is sent as-is without URL-escaping. Use a value
            // containing characters that would normally get escaped (+, /, =) to verify.
            _server.Given(
                    Request.Create()
                        .WithPath("/validate/check")
                        .UsingPost()
                        .WithBody(b => b != null && b.Contains("credential_id=A+B/C=")))
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
