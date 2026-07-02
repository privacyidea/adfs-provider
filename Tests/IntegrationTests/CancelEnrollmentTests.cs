using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using Tests.Fixtures;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Tests.IntegrationTests
{
    /// <summary>
    /// Verifies the request shape PrivacyIDEA.CancelEnrollment puts on the wire and the
    /// client's interpretation of both the ACCEPT (cancel honored) and REJECT
    /// (cancel refused, enrollment was not optional) responses.
    /// </summary>
    [TestClass]
    public class CancelEnrollmentTests
    {
        private WireMockServer _server;

        [TestInitialize]
        public void Setup() => _server = WireMockServer.Start();

        [TestCleanup]
        public void Cleanup() => _server.Stop();

        [TestMethod]
        public void CancelEnrollment_PostsTransactionIdAndCancelFlag_AndReturnsAcceptedResponse()
        {
            _server.Given(
                    Request.Create()
                        .WithPath("/validate/check")
                        .UsingPost()
                        .WithBody(b => b != null
                            && b.Contains("transaction_id=12345")
                            && b.Contains("cancel_enrollment=True")))
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithBody(MultichallengeEnrollFixtures.CancelEnrollmentAccept));

            var pi = TestHelpers.PIPointedAt(_server);
            var resp = pi.CancelEnrollment("12345");

            Assert.IsNotNull(resp, "CancelEnrollment returned null — request body probably didn't match the WireMock stub.");
            Assert.AreEqual(PIAuthenticationStatus.ACCEPT, resp.AuthenticationStatus);
            Assert.IsTrue(resp.isAuthenticationSuccessful());
        }

        [TestMethod]
        public void CancelEnrollment_OnNonOptionalChallenge_ParsesRejectResponse()
        {
            _server.Given(
                    Request.Create()
                        .WithPath("/validate/check")
                        .UsingPost())
                .RespondWith(Response.Create()
                    .WithStatusCode(200)
                    .WithBody(MultichallengeEnrollFixtures.CancelEnrollmentReject));

            var pi = TestHelpers.PIPointedAt(_server);
            var resp = pi.CancelEnrollment("99999");

            Assert.IsNotNull(resp);
            Assert.AreEqual(PIAuthenticationStatus.REJECT, resp.AuthenticationStatus);
            Assert.IsFalse(resp.isAuthenticationSuccessful());
            Assert.AreEqual("Failed to cancel enrollment via multichallenge", resp.Message);
        }

        [TestMethod]
        public void CancelEnrollment_WithEmptyTransactionId_ShortCircuits_WithoutHittingServer()
        {
            // No WireMock stub installed — if the client did call out, the request would
            // get the default 404 and CancelEnrollment would still return non-null. So
            // we instead assert that the client refuses the call locally and returns null.
            var pi = TestHelpers.PIPointedAt(_server);
            var resp = pi.CancelEnrollment("");

            Assert.IsNull(resp);
        }
    }
}
