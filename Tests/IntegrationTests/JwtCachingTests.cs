using System;
using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Tests.Fixtures;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Tests.IntegrationTests
{
    /// <summary>
    /// The /auth call is cached based on the JWT's `exp` claim minus a 30-second safety
    /// margin. These tests pin down: cached token is reused, expired token triggers a
    /// refetch, and a malformed/no-exp token falls back to the 5-minute window.
    /// </summary>
    [TestClass]
    public class JwtCachingTests
    {
        private WireMockServer _server;

        [TestInitialize]
        public void Setup()
        {
            _server = WireMockServer.Start();
            _server.Given(Request.Create().WithPath("/validate/triggerchallenge").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpFixtures.OtpChallenge));
        }

        [TestCleanup]
        public void Cleanup() => _server.Stop();

        private int AuthCallCount() =>
            _server.LogEntries.Count(le => le.RequestMessage.Path == "/auth");

        [TestMethod]
        public void TwoConsecutiveCalls_OnlyHitAuthEndpointOnce()
        {
            _server.Given(Request.Create().WithPath("/auth").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithBody(TestHelpers.AuthResponse(TestHelpers.MakeJwt(DateTime.UtcNow.AddHours(1)))));

            var pi = TestHelpers.PIPointedAt(_server);
            pi.SetServiceAccount("svc", "pw");

            pi.TriggerChallenges("alice");
            pi.TriggerChallenges("bob");

            Assert.AreEqual(1, AuthCallCount(), "Second TriggerChallenges should reuse the cached JWT.");
        }

        [TestMethod]
        public void ExpiredJwt_TriggersRefetch_OnNextCall()
        {
            // JWT exp is in the past, so even the 30s safety margin can't save it.
            _server.Given(Request.Create().WithPath("/auth").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithBody(TestHelpers.AuthResponse(TestHelpers.MakeJwt(DateTime.UtcNow.AddMinutes(-1)))));

            var pi = TestHelpers.PIPointedAt(_server);
            pi.SetServiceAccount("svc", "pw");

            pi.TriggerChallenges("alice");
            pi.TriggerChallenges("bob");

            Assert.AreEqual(2, AuthCallCount(), "Expired JWT should trigger a fresh /auth on the second call.");
        }

        [TestMethod]
        public void MalformedJwt_UsesFiveMinuteFallback_AndCachesAcrossCalls()
        {
            // Token has no `.` separators → ExtractJWTExpiry can't parse → falls back to
            // DateTime.UtcNow + 5 minutes, which (minus 30s safety) still caches the call.
            _server.Given(Request.Create().WithPath("/auth").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithBody(TestHelpers.AuthResponse("not-a-real-jwt")));

            var pi = TestHelpers.PIPointedAt(_server);
            pi.SetServiceAccount("svc", "pw");

            pi.TriggerChallenges("alice");
            pi.TriggerChallenges("bob");

            Assert.AreEqual(1, AuthCallCount(),
                "Malformed JWT should still take the fallback cache path, not refetch on every call.");
        }
    }
}
