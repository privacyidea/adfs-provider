using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using Tests.Fixtures;

namespace Tests.ParserTests
{
    /// <summary>
    /// Parser coverage for push token challenges and the helpers that read push data
    /// off the response object.
    /// </summary>
    [TestClass]
    public class PushParsingTests
    {
        [TestMethod]
        public void PushChallenge_PopulatesTransactionID()
        {
            var resp = PIResponse.FromJSON(PushFixtures.PushChallenge, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual(PIAuthenticationStatus.CHALLENGE, resp.AuthenticationStatus);
            Assert.AreEqual("02659936574063359702", resp.TransactionID);
        }

        [TestMethod]
        public void PushChallenge_ExposesPushMessage()
        {
            var resp = PIResponse.FromJSON(PushFixtures.PushChallenge, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual(
                "Please confirm the authentication on your mobile device!",
                resp.PushMessage());
        }

        [TestMethod]
        public void PushChallenge_TriggeredTokenTypes_ContainsPush()
        {
            var resp = PIResponse.FromJSON(PushFixtures.PushChallenge, null);

            Assert.IsNotNull(resp);
            CollectionAssert.Contains(resp.TriggeredTokenTypes(), "push");
        }

        [TestMethod]
        public void CodeToPhoneChallenge_MapsPreferredClientModeToOtp()
        {
            var resp = PIResponse.FromJSON(PushFixtures.CodeToPhoneChallenge, null);

            Assert.IsNotNull(resp);
            // interactive -> the client must show an input, not poll. The form keys off PreferredClientMode.
            Assert.AreEqual(PITokenType.Otp, resp.PreferredClientMode);
        }

        [TestMethod]
        public void CodeToPhoneChallenge_DoesNotExposePushMessage()
        {
            var resp = PIResponse.FromJSON(PushFixtures.CodeToPhoneChallenge, null);

            Assert.IsNotNull(resp);
            // type=push but client_mode=interactive: it cannot be polled, so the push-poll option
            // (driven by PushMessage/PushAvailable) must stay hidden.
            Assert.AreEqual("", resp.PushMessage());
        }
    }
}
