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
    }
}
