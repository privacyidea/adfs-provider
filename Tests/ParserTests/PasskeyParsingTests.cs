using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using Tests.Fixtures;

namespace Tests.ParserTests
{
    /// <summary>
    /// Parser coverage for passkey login init and passkey registration via multichallenge.
    /// </summary>
    [TestClass]
    public class PasskeyParsingTests
    {
        [TestMethod]
        public void PasskeyInit_ExposesPasskeyChallengeAndTransactionId()
        {
            var resp = PIResponse.FromJSON(PasskeyFixtures.PasskeyInitChallenge, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual("44444444444444444444", resp.PasskeyTransactionID);
            // The full passkey object is preserved as JSON for the browser-side challenge.
            Assert.IsTrue(resp.PasskeyChallenge.Contains("sso.example.com"));
            Assert.IsTrue(resp.PasskeyChallenge.Contains("preferred"));
        }

        [TestMethod]
        public void PasskeyAuthAccept_ExposesAuthenticatedUsername()
        {
            var resp = PIResponse.FromJSON(PasskeyFixtures.PasskeyAuthAccept, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual(PIAuthenticationStatus.ACCEPT, resp.AuthenticationStatus);
            Assert.IsTrue(resp.isAuthenticationSuccessful());
            Assert.AreEqual("alice", resp.Username);
        }

        [TestMethod]
        public void PasskeyAuthAccept_DifferentUser_StillSucceedsButReportsRealUsername()
        {
            // The parser doesn't enforce a user match — Adapter.TryEndAuthentication does.
            // This test just locks down that detail.username is exposed unchanged.
            var resp = PIResponse.FromJSON(PasskeyFixtures.PasskeyAuthAcceptDifferentUser, null);

            Assert.IsNotNull(resp);
            Assert.IsTrue(resp.isAuthenticationSuccessful());
            Assert.AreEqual("bob", resp.Username);
        }

        [TestMethod]
        public void PasskeyRegistrationChallenge_ExposesRegistrationPayloadAndSerial()
        {
            var resp = PIResponse.FromJSON(PasskeyFixtures.PasskeyRegistrationChallenge, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual(PIAuthenticationStatus.CHALLENGE, resp.AuthenticationStatus);
            Assert.AreEqual("PIPK00001234", resp.Serial);
            Assert.IsTrue(resp.PasskeyRegistration.Contains("sso.example.com"));
            Assert.IsTrue(resp.PasskeyRegistration.Contains("pubKeyCredParams"));
        }
    }
}
