using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using Microsoft.IdentityServer.Web.Authentication.External;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using privacyIDEAADFSProvider;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using Tests.Fixtures;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Tests.AdapterTests
{
    /// <summary>
    /// Covers the no-JavaScript submit path in Adapter.TryEndAuthentication. The hidden formResult field is
    /// only populated by the page JavaScript on submit. A client without JavaScript (a legacy embedded
    /// WebView, issue #90, or the device-registration/OAuth passive flow urn:ms-drs, issue #77) posts it
    /// empty. For a plain one-time-password submit that field carries nothing the server needs, so the
    /// adapter must treat an empty, missing, or non-string formResult as an all-default FormResult and
    /// validate the posted otp. These tests drive that end to end against a mock privacyIDEA server.
    /// </summary>
    [TestClass]
    public class NoJavaScriptSubmitTests
    {
        private const string OtpAuthMethod = "http://schemas.microsoft.com/ws/2012/12/authmethod/otp";

        private WireMockServer _server;

        [TestInitialize]
        public void Setup() => _server = WireMockServer.Start();

        [TestCleanup]
        public void Cleanup() => _server.Stop();

        private sealed class FakeProofData : IProofData
        {
            public Dictionary<string, object> Properties { get; }
            public FakeProofData(Dictionary<string, object> properties) => Properties = properties;
        }

        private sealed class FakeAuthContext : IAuthenticationContext
        {
            public int Lcid => 1033;
            public string ActivityId => "activity";
            public string ContextId => "context";
            public Dictionary<string, object> Data { get; }
            public FakeAuthContext(Dictionary<string, object> data) => Data = data;
        }

        /// <summary>
        /// Builds an Adapter whose PrivacyIDEA client points at the mock server. Configuration's only
        /// constructor reads the Windows registry, so it is created uninitialized: the no-JS OTP path reads
        /// only defaulting fields off it (OtpHint, AutoSubmitLength, DisablePasskey) and never touches the
        /// forward-headers/custom-params config, because the null request short-circuits those helpers.
        /// </summary>
        private Adapter NewAdapter()
        {
            var adapter = new Adapter();

            System.Type configType = typeof(Adapter).Assembly.GetType("PrivacyIDEAADFSProvider.Configuration");
            Assert.IsNotNull(configType, "Could not locate the internal Configuration type via reflection.");
            object config = RuntimeHelpers.GetUninitializedObject(configType);
            SetPrivateField(adapter, "_config", config);

            PrivacyIDEA pi = TestHelpers.PIPointedAt(_server);
            SetPrivateField(adapter, "_privacyIDEA", pi);

            return adapter;
        }

        private static void SetPrivateField(object target, string field, object value)
        {
            FieldInfo fi = target.GetType().GetField(field, BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.IsNotNull(fi, $"Field {field} not found on {target.GetType().Name}.");
            fi.SetValue(target, value);
        }

        private static Dictionary<string, object> MinimalContext() => new Dictionary<string, object>
        {
            ["userid"] = "alice",
            ["domain"] = "example.com",
        };

        private void StubValidateCheckAccept() =>
            _server.Given(
                    Request.Create()
                        .WithPath("/validate/check")
                        .UsingPost()
                        .WithBody(b => b != null && b.Contains("user=alice") && b.Contains("pass=123456")))
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpFixtures.SimpleAccept));

        [TestMethod]
        public void EmptyFormResult_WithValidOtp_Succeeds()
        {
            // The hidden formResult is posted present but empty (no page JavaScript ran). A valid OTP must
            // still authenticate: result null signals success and the adapter emits the OTP auth-method claim.
            StubValidateCheckAccept();
            var adapter = NewAdapter();
            var proof = new FakeProofData(new Dictionary<string, object>
            {
                ["formResult"] = "",
                ["otp"] = "123456",
            });
            var ctx = new FakeAuthContext(MinimalContext());

            IAdapterPresentation result = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] claims);

            Assert.IsNull(result, "A successful authentication returns null (no form to present again).");
            Assert.AreEqual(1, claims.Length);
            Assert.AreEqual(OtpAuthMethod, claims[0].Value);
        }

        [TestMethod]
        public void MissingFormResult_WithValidOtp_Succeeds()
        {
            // The formResult key is absent entirely (a bare no-JS POST).
            StubValidateCheckAccept();
            var adapter = NewAdapter();
            var proof = new FakeProofData(new Dictionary<string, object> { ["otp"] = "123456" });
            var ctx = new FakeAuthContext(MinimalContext());

            IAdapterPresentation result = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] claims);

            Assert.IsNull(result);
            Assert.AreEqual(1, claims.Length);
            Assert.AreEqual(OtpAuthMethod, claims[0].Value);
        }

        [TestMethod]
        public void NonStringFormResult_WithValidOtp_Succeeds()
        {
            // A non-string value must route through `as string` to the no-JS path, not crash on a cast.
            StubValidateCheckAccept();
            var adapter = NewAdapter();
            var proof = new FakeProofData(new Dictionary<string, object>
            {
                ["formResult"] = 42,
                ["otp"] = "123456",
            });
            var ctx = new FakeAuthContext(MinimalContext());

            IAdapterPresentation result = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] claims);

            Assert.IsNull(result);
            Assert.AreEqual(1, claims.Length);
            Assert.AreEqual(OtpAuthMethod, claims[0].Value);
        }

        [TestMethod]
        public void EmptyFormResult_WrongOtp_ReturnsErrorFormNotSuccess()
        {
            // A no-JS submit with a wrong OTP must re-present a form (not authenticate, not crash).
            _server.Given(
                    Request.Create().WithPath("/validate/check").UsingPost())
                .RespondWith(Response.Create().WithStatusCode(200).WithBody(OtpFixtures.SimpleReject));
            var adapter = NewAdapter();
            var proof = new FakeProofData(new Dictionary<string, object>
            {
                ["formResult"] = "",
                ["otp"] = "000000",
            });
            var ctx = new FakeAuthContext(MinimalContext());

            IAdapterPresentation result = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] claims);

            Assert.IsNotNull(result, "A rejected OTP must return a form, not null (which would signal success).");
            Assert.AreEqual(0, claims.Length);
        }
    }
}
