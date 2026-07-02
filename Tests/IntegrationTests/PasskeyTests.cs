using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using Tests.Fixtures;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Tests.IntegrationTests
{
    /// <summary>
    /// Wire-level checks for the passkey flow: initialize and validate, plus the
    /// short-circuit when required parameters are missing.
    /// </summary>
    [TestClass]
    public class PasskeyTests
    {
        private WireMockServer _server;

        [TestInitialize]
        public void Setup() => _server = WireMockServer.Start();

        [TestCleanup]
        public void Cleanup() => _server.Stop();

        [TestMethod]
        public void ValidateInitialize_RequestsPasskeyTypeViaGet()
        {
            _server.Given(
                    Request.Create()
                        .WithPath("/validate/initialize")
                        .UsingGet()
                        .WithParam("type", "passkey"))
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(PasskeyFixtures.PasskeyInitChallenge));

            var pi = TestHelpers.PIPointedAt(_server);
            var resp = pi.ValidateInitialize("passkey");

            Assert.IsNotNull(resp);
            Assert.AreEqual("44444444444444444444", resp.PasskeyTransactionID);
        }

        [TestMethod]
        public void ValidateCheckPasskey_AddsOriginHeader()
        {
            _server.Given(
                    Request.Create()
                        .WithPath("/validate/check")
                        .UsingPost()
                        .WithHeader("Origin", "https://sso.example.com"))
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(PasskeyFixtures.PasskeyAuthAccept));

            var pi = TestHelpers.PIPointedAt(_server);
            var resp = pi.ValidateCheckPasskey(
                transactionid: "44444444444444444444",
                assertionResponse: "{\"credential_id\":\"cred\",\"clientDataJSON\":\"cdj\",\"signature\":\"sig\",\"authenticatorData\":\"ad\",\"userHandle\":\"uh\"}",
                origin: "https://sso.example.com");

            Assert.IsNotNull(resp);
            Assert.IsTrue(resp.isAuthenticationSuccessful());
            Assert.AreEqual("alice", resp.Username);
        }

        [TestMethod]
        public void ValidateCheckPasskey_WithMissingArgs_ShortCircuitsAndReturnsNull()
        {
            var pi = TestHelpers.PIPointedAt(_server);

            Assert.IsNull(pi.ValidateCheckPasskey("", "assertion", "https://sso.example.com"));
            Assert.IsNull(pi.ValidateCheckPasskey("tx", "", "https://sso.example.com"));
            Assert.IsNull(pi.ValidateCheckPasskey("tx", "assertion", ""));

            // None of those should have actually hit the server.
            Assert.AreEqual(0, _server.LogEntries.Count());
        }
    }
}
