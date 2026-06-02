using System.Collections.Generic;
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
    /// Realm resolution precedence: a RealmMap hit for the domain beats the default Realm.
    /// The map is looked up case-insensitively (RegistryReader builds it with an
    /// OrdinalIgnoreCase comparer). Unknown domains fall back to the default Realm if one is
    /// set. When nothing is configured the realm parameter is omitted.
    /// </summary>
    [TestClass]
    public class RealmMappingTests
    {
        private WireMockServer _server;

        [TestInitialize]
        public void Setup()
        {
            _server = WireMockServer.Start();
            // /auth always returns a JWT so the JWT cache populates and subsequent
            // requests can be inspected.
            _server.Given(Request.Create().WithPath("/auth").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithBody(TestHelpers.AuthResponse(TestHelpers.MakeJwt(System.DateTime.UtcNow.AddHours(1)))));
        }

        [TestCleanup]
        public void Cleanup() => _server.Stop();

        [TestMethod]
        public void TriggerChallenges_WithMappedDomain_SendsMappedRealm()
        {
            _server.Given(Request.Create().WithPath("/validate/triggerchallenge").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpFixtures.OtpChallenge));

            var pi = TestHelpers.PIPointedAt(_server);
            pi.SetServiceAccount("svc", "pw");
            pi.Realm = "default-realm";
            pi.RealmMap = new Dictionary<string, string> { { "EXAMPLE", "mapped-realm" } };

            pi.TriggerChallenges("alice", new PIRequestContext { Domain = "EXAMPLE" });

            var trigger = _server.LogEntries.Single(le => le.RequestMessage.Path == "/validate/triggerchallenge");
            string body = trigger.RequestMessage.Body;
            Assert.IsTrue(body.Contains("realm=mapped-realm"), "Expected mapped realm; body was: " + body);
            Assert.IsFalse(body.Contains("realm=default-realm"), "Default realm should not appear when a mapping matches.");
        }

        [TestMethod]
        public void TriggerChallenges_WithUnmappedDomain_FallsBackToDefaultRealm()
        {
            _server.Given(Request.Create().WithPath("/validate/triggerchallenge").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpFixtures.OtpChallenge));

            var pi = TestHelpers.PIPointedAt(_server);
            pi.SetServiceAccount("svc", "pw");
            pi.Realm = "default-realm";
            pi.RealmMap = new Dictionary<string, string> { { "OTHER", "other-realm" } };

            pi.TriggerChallenges("alice", new PIRequestContext { Domain = "EXAMPLE" });

            var trigger = _server.LogEntries.Single(le => le.RequestMessage.Path == "/validate/triggerchallenge");
            string body = trigger.RequestMessage.Body;
            Assert.IsTrue(body.Contains("realm=default-realm"), "Expected default realm fallback; body was: " + body);
        }

        [TestMethod]
        public void TriggerChallenges_RealmMapKeysAreCaseInsensitive_OnLookup()
        {
            _server.Given(Request.Create().WithPath("/validate/triggerchallenge").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpFixtures.OtpChallenge));

            var pi = TestHelpers.PIPointedAt(_server);
            pi.SetServiceAccount("svc", "pw");
            // Case-insensitivity comes from the map's comparer, mirroring how RegistryReader
            // builds the realm mapping (StringComparer.OrdinalIgnoreCase).
            pi.RealmMap = new Dictionary<string, string>(System.StringComparer.OrdinalIgnoreCase)
            {
                { "EXAMPLE", "mapped-realm" }
            };

            pi.TriggerChallenges("alice", new PIRequestContext { Domain = "example" }); // lowercase domain

            var trigger = _server.LogEntries.Single(le => le.RequestMessage.Path == "/validate/triggerchallenge");
            Assert.IsTrue(trigger.RequestMessage.Body.Contains("realm=mapped-realm"));
        }

        [TestMethod]
        public void TriggerChallenges_WithNoRealmConfig_OmitsRealmParameter()
        {
            _server.Given(Request.Create().WithPath("/validate/triggerchallenge").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpFixtures.OtpChallenge));

            var pi = TestHelpers.PIPointedAt(_server);
            pi.SetServiceAccount("svc", "pw");
            // No Realm, no RealmMap, no domain → realm parameter should be omitted entirely.

            pi.TriggerChallenges("alice");

            var trigger = _server.LogEntries.Single(le => le.RequestMessage.Path == "/validate/triggerchallenge");
            Assert.IsFalse(trigger.RequestMessage.Body.Contains("realm="),
                "No realm should be sent when nothing is configured; body was: " + trigger.RequestMessage.Body);
        }
    }
}
