using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using Tests.Fixtures;

namespace Tests.ParserTests
{
    /// <summary>
    /// Parser-level coverage for the enroll-via-multichallenge flow. Touches only
    /// PIResponse.FromJSON — no HTTP, no PrivacyIDEA instance — so failures point straight
    /// at parser regressions when the server response shape changes.
    /// </summary>
    [TestClass]
    public class MultichallengeEnrollParsingTests
    {
        [TestMethod]
        public void HotpEnroll_ParsesAsChallengeWithImageAndLink()
        {
            var resp = PIResponse.FromJSON(MultichallengeEnrollFixtures.HotpEnrollChallenge, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual(PIAuthenticationStatus.CHALLENGE, resp.AuthenticationStatus);
            Assert.IsFalse(resp.isAuthenticationSuccessful());
            Assert.AreEqual("18249856845542401525", resp.TransactionID);
            Assert.AreEqual("OATH0000AC38", resp.Serial);
            Assert.AreEqual("hotp", resp.Type);

            Assert.AreEqual(1, resp.Challenges.Count);
            var challenge = resp.Challenges[0];
            Assert.AreEqual("hotp", challenge.Type);
            Assert.AreEqual("OATH0000AC38", challenge.Serial);
            Assert.AreEqual("interactive", challenge.ClientMode);
            Assert.IsTrue(challenge.Image.StartsWith("data:image/png;base64,"));
        }

        [TestMethod]
        public void EnrollmentOptional_DefaultsToFalse()
        {
            var resp = PIResponse.FromJSON(MultichallengeEnrollFixtures.HotpEnrollChallenge, null);
            Assert.IsFalse(resp.EnrollmentOptional);
        }

        [TestMethod]
        public void EnrollmentOptional_IsTrue_WhenFlagSet()
        {
            var resp = PIResponse.FromJSON(MultichallengeEnrollFixtures.HotpEnrollChallengeOptional, null);
            Assert.IsTrue(resp.EnrollmentOptional);
        }

        [TestMethod]
        public void EmailEnroll_FirstStepHasNoImage()
        {
            var resp = PIResponse.FromJSON(MultichallengeEnrollFixtures.EmailEnrollAskForAddress, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual(PIAuthenticationStatus.CHALLENGE, resp.AuthenticationStatus);
            Assert.AreEqual("email", resp.Type);
            Assert.AreEqual(1, resp.Challenges.Count);
            // No QR code on this step — just the prompt for the email address.
            Assert.AreEqual(string.Empty, resp.Challenges[0].Image);
            Assert.AreEqual("Please enter your new email address!", resp.Challenges[0].Message);
        }

        [TestMethod]
        public void SmartphoneEnroll_ExposesPollClientModeAndTransactionId()
        {
            var resp = PIResponse.FromJSON(MultichallengeEnrollFixtures.SmartphoneEnrollChallenge, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual(PIAuthenticationStatus.CHALLENGE, resp.AuthenticationStatus);
            Assert.AreEqual("smartphone", resp.Challenges[0].Type);
            Assert.AreEqual("poll", resp.Challenges[0].ClientMode);
            Assert.AreEqual("SMPH0000D847", resp.Challenges[0].Serial);
            // client_mode=poll is what the adapter keys off to enter the push-polling path; the
            // adapter reads response.TransactionID for the poll call.
            Assert.AreEqual("17359662976761378280", resp.TransactionID);
        }

        [TestMethod]
        public void CancelAccept_ParsesAsSuccessfulAuthentication()
        {
            var resp = PIResponse.FromJSON(MultichallengeEnrollFixtures.CancelEnrollmentAccept, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual(PIAuthenticationStatus.ACCEPT, resp.AuthenticationStatus);
            Assert.IsTrue(resp.isAuthenticationSuccessful());
            Assert.AreEqual(0, resp.Challenges.Count);
            Assert.AreEqual("Cancelled enrollment via multichallenge", resp.Message);
        }

        [TestMethod]
        public void CancelReject_ParsesAsRejectedAuthentication()
        {
            var resp = PIResponse.FromJSON(MultichallengeEnrollFixtures.CancelEnrollmentReject, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual(PIAuthenticationStatus.REJECT, resp.AuthenticationStatus);
            Assert.IsFalse(resp.isAuthenticationSuccessful());
            Assert.AreEqual("Failed to cancel enrollment via multichallenge", resp.Message);
        }
    }
}
