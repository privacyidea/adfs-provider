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
    /// Wire-level checks for PrivacyIDEA.ValidateCheck: the body shape we send and
    /// the response parsing into a PIResponse.
    /// </summary>
    [TestClass]
    public class OtpValidationTests
    {
        private WireMockServer _server;

        [TestInitialize]
        public void Setup() => _server = WireMockServer.Start();

        [TestCleanup]
        public void Cleanup() => _server.Stop();

        [TestMethod]
        public void ValidateCheck_PostsUserAndPass_AndReturnsAccept()
        {
            _server.Given(
                    Request.Create()
                        .WithPath("/validate/check")
                        .UsingPost()
                        .WithBody(b => b != null && b.Contains("user=alice") && b.Contains("pass=123456")))
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpFixtures.SimpleAccept));

            var pi = TestHelpers.PIPointedAt(_server);
            var resp = pi.ValidateCheck("alice", "123456");

            Assert.IsNotNull(resp);
            Assert.AreEqual(PIAuthenticationStatus.ACCEPT, resp.AuthenticationStatus);
        }

        [TestMethod]
        public void ValidateCheck_WithTransactionId_IncludesItInBody()
        {
            _server.Given(
                    Request.Create()
                        .WithPath("/validate/check")
                        .UsingPost()
                        .WithBody(b => b != null && b.Contains("transaction_id=tx-123")))
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpFixtures.ChallengeCompletionAccept));

            var pi = TestHelpers.PIPointedAt(_server);
            var resp = pi.ValidateCheck("alice", "999999", "tx-123");

            Assert.IsNotNull(resp);
            Assert.IsTrue(resp.isAuthenticationSuccessful());
        }

        [TestMethod]
        public void ValidateCheck_UrlEncodesUsername_WithSpecialCharacters()
        {
            // An @ in the username (UPN-style) should be URL-encoded in the body as %40.
            _server.Given(
                    Request.Create()
                        .WithPath("/validate/check")
                        .UsingPost()
                        .WithBody(b => b != null && b.Contains("user=alice%40example.com")))
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpFixtures.SimpleAccept));

            var pi = TestHelpers.PIPointedAt(_server);
            var resp = pi.ValidateCheck("alice@example.com", "123456");

            // Assert success, not just non-null: an unmatched stub returns WireMock's default
            // (parseable) body, so only IsTrue proves the %40-encoded body predicate actually matched.
            Assert.IsNotNull(resp);
            Assert.IsTrue(resp.isAuthenticationSuccessful());
        }
    }
}
