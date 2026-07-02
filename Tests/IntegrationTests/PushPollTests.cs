using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Tests.Fixtures;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Tests.IntegrationTests
{
    /// <summary>
    /// Wire-level checks for PrivacyIDEA.PollTransaction. The endpoint is GET-based
    /// with transaction_id in the query string; the boolean return is driven by
    /// result.value in the response.
    /// </summary>
    [TestClass]
    public class PushPollTests
    {
        private WireMockServer _server;

        [TestInitialize]
        public void Setup() => _server = WireMockServer.Start();

        [TestCleanup]
        public void Cleanup() => _server.Stop();

        [TestMethod]
        public void PollTransaction_ReturnsTrue_OnAcceptedResponse()
        {
            _server.Given(
                    Request.Create()
                        .WithPath("/validate/polltransaction")
                        .UsingGet())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(PushFixtures.PollAccepted));

            var pi = TestHelpers.PIPointedAt(_server);
            Assert.IsTrue(pi.PollTransaction("02659936574063359702"));
        }

        [TestMethod]
        public void PollTransaction_ReturnsFalse_OnPendingResponse()
        {
            _server.Given(
                    Request.Create()
                        .WithPath("/validate/polltransaction")
                        .UsingGet())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(PushFixtures.PollPending));

            var pi = TestHelpers.PIPointedAt(_server);
            Assert.IsFalse(pi.PollTransaction("02659936574063359702"));
        }

        [TestMethod]
        public void PollTransaction_PutsTransactionIdInQueryString()
        {
            _server.Given(
                    Request.Create()
                        .WithPath("/validate/polltransaction")
                        .UsingGet()
                        .WithParam("transaction_id", "tx-poll-1"))
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(PushFixtures.PollAccepted));

            var pi = TestHelpers.PIPointedAt(_server);
            Assert.IsTrue(pi.PollTransaction("tx-poll-1"));
        }

        [TestMethod]
        public void PollTransaction_WithEmptyId_ReturnsFalseWithoutCallingServer()
        {
            // No stub installed — if PollTransaction did hit the server, it would 404
            // and the parse would return false anyway. So we instead assert that no
            // request was logged.
            var pi = TestHelpers.PIPointedAt(_server);

            Assert.IsFalse(pi.PollTransaction(""));
            Assert.AreEqual(0, _server.LogEntries.Count());
        }
    }
}
