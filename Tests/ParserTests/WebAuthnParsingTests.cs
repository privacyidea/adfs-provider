using Microsoft.VisualStudio.TestTools.UnitTesting;
using Newtonsoft.Json.Linq;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using Tests.Fixtures;

namespace Tests.ParserTests
{
    /// <summary>
    /// Parser coverage for WebAuthn challenges, including the multi-credential merge.
    /// </summary>
    [TestClass]
    public class WebAuthnParsingTests
    {
        [TestMethod]
        public void SingleWebAuthn_ExposesSignRequestAndTransactionId()
        {
            var resp = PIResponse.FromJSON(WebAuthnFixtures.SingleWebAuthnChallenge, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual("66666666666666666666", resp.TransactionID);

            var merged = resp.MergedSignRequest();
            Assert.IsFalse(string.IsNullOrEmpty(merged));

            var json = JObject.Parse(merged);
            Assert.AreEqual("sso.example.com", (string)json["rpId"]);
            Assert.AreEqual(1, ((JArray)json["allowCredentials"]).Count);
        }

        [TestMethod]
        public void DualWebAuthn_MergesAllowCredentials()
        {
            var resp = PIResponse.FromJSON(WebAuthnFixtures.DualWebAuthnChallenge, null);

            Assert.IsNotNull(resp);
            Assert.AreEqual(2, resp.Challenges.Count);

            var merged = resp.MergedSignRequest();
            Assert.IsFalse(string.IsNullOrEmpty(merged));

            var creds = (JArray)JObject.Parse(merged)["allowCredentials"];
            Assert.AreEqual(2, creds.Count);
            // Both credential ids should appear in the merged set.
            CollectionAssert.AreEquivalent(
                new[] { "cred-A", "cred-B" },
                new[] { (string)creds[0]["id"], (string)creds[1]["id"] });
        }

        [TestMethod]
        public void NoWebAuthn_MergedSignRequest_IsNull()
        {
            // Push challenge has no webauthn; the merger should return null.
            var resp = PIResponse.FromJSON(PushFixtures.PushChallenge, null);

            Assert.IsNotNull(resp);
            Assert.IsNull(resp.MergedSignRequest());
        }
    }
}
