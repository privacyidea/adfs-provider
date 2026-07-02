using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using Tests.Fixtures;

namespace Tests.ParserTests
{
    /// <summary>
    /// Coverage for /validate/check response parsing — ACCEPT, REJECT, CHALLENGE,
    /// server-side error, and the preferred_client_mode translation rules.
    /// </summary>
    [TestClass]
    public class OtpValidationParsingTests
    {
        [TestMethod]
        public void SimpleAccept_IsSuccessfulAuthentication()
        {
            var resp = PIResponse.FromJSON(OtpFixtures.SimpleAccept, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual(PIAuthenticationStatus.ACCEPT, resp.AuthenticationStatus);
            Assert.IsTrue(resp.isAuthenticationSuccessful());
            Assert.AreEqual("TOTP00001234", resp.Serial);
            Assert.AreEqual("totp", resp.Type);
            Assert.AreEqual(0, resp.Challenges.Count);
        }

        [TestMethod]
        public void SimpleReject_IsFailedAuthentication()
        {
            var resp = PIResponse.FromJSON(OtpFixtures.SimpleReject, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual(PIAuthenticationStatus.REJECT, resp.AuthenticationStatus);
            Assert.IsFalse(resp.isAuthenticationSuccessful());
            Assert.AreEqual(0, resp.Challenges.Count);
        }

        [TestMethod]
        public void OtpChallenge_ExposesTransactionIdAndOtpType()
        {
            var resp = PIResponse.FromJSON(OtpFixtures.OtpChallenge, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual(PIAuthenticationStatus.CHALLENGE, resp.AuthenticationStatus);
            Assert.AreEqual("11111111111111111111", resp.TransactionID);
            Assert.AreEqual(1, resp.Challenges.Count);
            Assert.AreEqual("hotp", resp.Challenges[0].Type);
            Assert.AreEqual("11111111111111111111", resp.Challenges[0].TransactionID);
        }

        [TestMethod]
        public void ServerError_ExposesCodeAndMessage()
        {
            var resp = PIResponse.FromJSON(OtpFixtures.ServerError, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual(904, resp.ErrorCode);
            Assert.AreEqual("ERR904: User not found", resp.ErrorMessage);
            Assert.IsFalse(resp.Status);
            Assert.IsFalse(resp.isAuthenticationSuccessful());
        }

        [TestMethod]
        public void PreferredClientMode_Interactive_TranslatesToOtp()
        {
            var resp = PIResponse.FromJSON(OtpFixtures.PreferredClientModeInteractive, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual("otp", resp.PreferredClientMode);
        }

        [TestMethod]
        public void PreferredClientMode_Poll_TranslatesToPush()
        {
            var resp = PIResponse.FromJSON(OtpFixtures.PreferredClientModePoll, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual("push", resp.PreferredClientMode);
        }

        [TestMethod]
        public void ChallengeCompletionAccept_IsSuccessful()
        {
            var resp = PIResponse.FromJSON(OtpFixtures.ChallengeCompletionAccept, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual(PIAuthenticationStatus.ACCEPT, resp.AuthenticationStatus);
            Assert.IsTrue(resp.isAuthenticationSuccessful());
        }
    }
}
