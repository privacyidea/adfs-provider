using System.Linq;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using WireMock.Matchers;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Tests.IntegrationTests
{
    /// <summary>
    /// Wire-level checks for the "remember device" client calls: the X-API-Key header, the capability
    /// discovery, presenting a cookie to /validate/remember_device, issuing one on /validate/check, and
    /// parsing the Set-Cookie the server returns.
    /// </summary>
    [TestClass]
    public class RememberDeviceClientTests
    {
        private const string CapabilityOn = "{\"result\":{\"status\":true,\"value\":{\"capabilities\":{\"remember_device\":true}}}}";
        private const string CapabilityOff = "{\"result\":{\"status\":true,\"value\":{\"capabilities\":{\"remember_device\":false}}}}";
        private const string RecognizedTrue = "{\"result\":{\"status\":true,\"value\":true}}";
        private const string RecognizedFalse = "{\"result\":{\"status\":true,\"value\":false}}";
        private const string OtpAccept = "{\"result\":{\"authentication\":\"ACCEPT\",\"status\":true,\"value\":true}}";

        private WireMockServer _server;

        [TestInitialize]
        public void Setup() => _server = WireMockServer.Start();

        [TestCleanup]
        public void Cleanup() => _server.Stop();

        [TestMethod]
        public void GetCapability_SendsApiKey_AndParsesTrue()
        {
            // The stub only matches when the X-API-Key header is present, so a true result proves it was sent.
            _server.Given(
                    Request.Create().WithPath("/validate/capabilities").UsingGet()
                        .WithHeader("X-API-Key", new ExactMatcher("secret-key")))
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(CapabilityOn));

            var pi = TestHelpers.PIPointedAt(_server);
            pi.ApiKey = "secret-key";

            Assert.IsTrue(pi.GetRememberDeviceCapability());
        }

        [TestMethod]
        public void GetCapability_False_WhenServerReportsOff()
        {
            _server.Given(Request.Create().WithPath("/validate/capabilities").UsingGet())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(CapabilityOff));

            var pi = TestHelpers.PIPointedAt(_server);
            pi.ApiKey = "secret-key";

            Assert.IsFalse(pi.GetRememberDeviceCapability());
        }

        [TestMethod]
        public void GetCapability_False_WithoutApiKey_MakesNoCall()
        {
            // No stub is configured. Without an API key the client must not call the server at all.
            var pi = TestHelpers.PIPointedAt(_server);

            Assert.IsFalse(pi.GetRememberDeviceCapability());
            Assert.AreEqual(0, _server.LogEntries.Count());
        }

        [TestMethod]
        public void CheckRememberDevice_SendsCookieAndApiKey_Recognized_ParsesRotatedCookie()
        {
            // Matches only when the presented cookie and the API key are both sent; the response rotates the
            // cookie (a new value with a positive Max-Age).
            _server.Given(
                    Request.Create().WithPath("/validate/remember_device").UsingPost()
                        .WithHeader("X-API-Key", new ExactMatcher("secret-key"))
                        .WithHeader("Cookie", new WildcardMatcher("*pi_remember_device=old-series:1*")))
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Set-Cookie", "pi_remember_device=new-series:2; Max-Age=3600; Path=/; Secure; HttpOnly; SameSite=Strict")
                    .WithBody(RecognizedTrue));

            var pi = TestHelpers.PIPointedAt(_server);
            pi.ApiKey = "secret-key";

            RememberDeviceResult result = pi.CheckRememberDevice("alice", "old-series:1", null);

            Assert.IsTrue(result.Recognized);
            Assert.IsNotNull(result.Cookie);
            Assert.AreEqual("new-series:2", result.Cookie.Value);
            Assert.AreEqual(3600, result.Cookie.MaxAgeSeconds);
            Assert.IsFalse(result.Cookie.IsClear);
        }

        [TestMethod]
        public void CheckRememberDevice_NotRecognized_ParsesClearDirective()
        {
            // A miss: value false and a cleared cookie (Max-Age=0) so the client removes it.
            _server.Given(Request.Create().WithPath("/validate/remember_device").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Set-Cookie", "pi_remember_device=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict")
                    .WithBody(RecognizedFalse));

            var pi = TestHelpers.PIPointedAt(_server);
            pi.ApiKey = "secret-key";

            RememberDeviceResult result = pi.CheckRememberDevice("alice", "dead-series:5", null);

            Assert.IsFalse(result.Recognized);
            Assert.IsNotNull(result.Cookie);
            Assert.IsTrue(result.Cookie.IsClear);
        }

        [TestMethod]
        public void CheckRememberDevice_NoCookiePresented_MakesNoCall()
        {
            var pi = TestHelpers.PIPointedAt(_server);
            pi.ApiKey = "secret-key";

            RememberDeviceResult result = pi.CheckRememberDevice("alice", "", null);

            Assert.IsFalse(result.Recognized);
            Assert.AreEqual(0, _server.LogEntries.Count());
        }

        [TestMethod]
        public void ValidateCheckRemember_RequestsPersistentCookie_AndParsesIssuedCookie()
        {
            // The issuance call must carry request_persistent_cookie=1; the response's Set-Cookie is parsed
            // into the issued cookie for the adapter to relay to the browser.
            _server.Given(
                    Request.Create().WithPath("/validate/check").UsingPost()
                        .WithBody(b => b != null && b.Contains("request_persistent_cookie=1")
                            && b.Contains("user=alice") && b.Contains("pass=123456")))
                .RespondWith(Response.Create().WithStatusCode(200)
                    .WithHeader("Set-Cookie", "pi_remember_device=fresh-series:1; Max-Age=1209600; Path=/; Secure; HttpOnly; SameSite=Strict")
                    .WithBody(OtpAccept));

            var pi = TestHelpers.PIPointedAt(_server);
            pi.ApiKey = "secret-key";

            PIResponse resp = pi.ValidateCheckRemember("alice", "123456", null, null, out PICookie issued);

            Assert.IsNotNull(resp);
            Assert.IsTrue(resp.isAuthenticationSuccessful());
            Assert.IsNotNull(issued);
            Assert.AreEqual("fresh-series:1", issued.Value);
            Assert.AreEqual(1209600, issued.MaxAgeSeconds);
        }

        [TestMethod]
        public void ValidateCheckRemember_NoSetCookie_LeavesIssuedCookieNull()
        {
            // The server did not issue a cookie (e.g. no policy for this user): issued cookie stays null and
            // the authentication result is still returned.
            _server.Given(Request.Create().WithPath("/validate/check").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpAccept));

            var pi = TestHelpers.PIPointedAt(_server);
            pi.ApiKey = "secret-key";

            PIResponse resp = pi.ValidateCheckRemember("alice", "123456", null, null, out PICookie issued);

            Assert.IsNotNull(resp);
            Assert.IsTrue(resp.isAuthenticationSuccessful());
            Assert.IsNull(issued);
        }
    }
}
