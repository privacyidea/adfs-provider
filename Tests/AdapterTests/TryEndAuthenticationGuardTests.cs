using System.Collections.Generic;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using Microsoft.IdentityServer.Web.Authentication.External;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using privacyIDEAADFSProvider;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;

namespace Tests.AdapterTests
{
    /// <summary>
    /// Regression tests for the null-safety guards at the top of Adapter.TryEndAuthentication that still
    /// degrade to an error form: a null authentication context, and a non-empty formResult that is not
    /// parseable JSON ("null" or malformed). An empty, whitespace, missing, or non-string formResult is a
    /// different case — it is the no-JavaScript OTP path (NoJavaScriptSubmitTests), not an error — because
    /// the page JavaScript only populates formResult on submit, and a legacy WebView (issue #90) or the
    /// device-registration/OAuth passive flow (urn:ms-drs, issue #77) posts it empty.
    /// </summary>
    [TestClass]
    public class TryEndAuthenticationGuardTests
    {
        /// <summary>Minimal IProofData carrying the posted form fields.</summary>
        private sealed class FakeProofData : IProofData
        {
            public Dictionary<string, object> Properties { get; }
            public FakeProofData(Dictionary<string, object> properties) => Properties = properties;
        }

        /// <summary>Minimal IAuthenticationContext backed by a mutable data dictionary.</summary>
        private sealed class FakeAuthContext : IAuthenticationContext
        {
            public int Lcid => 1033;
            public string ActivityId => "activity";
            public string ContextId => "context";
            public Dictionary<string, object> Data { get; }
            public FakeAuthContext(Dictionary<string, object> data) => Data = data;
        }

        /// <summary>
        /// Builds an Adapter with the two private collaborators TryEndAuthentication needs to reach the
        /// guards. Configuration's only constructor reads the Windows registry, so it is instantiated
        /// uninitialized (its exact field values are irrelevant to the guard paths, which return before
        /// touching the server). PrivacyIDEA just needs to be non-null so the "not initialized" check passes.
        /// </summary>
        private static Adapter NewAdapter()
        {
            var adapter = new Adapter();

            System.Type configType = typeof(Adapter).Assembly.GetType("PrivacyIDEAADFSProvider.Configuration");
            Assert.IsNotNull(configType, "Could not locate the internal Configuration type via reflection.");
            object config = RuntimeHelpers.GetUninitializedObject(configType);
            SetPrivateField(adapter, "_config", config);

            var pi = new PrivacyIDEA("http://localhost:59999", "test", sslVerify: false);
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

        [TestMethod]
        public void FormResultLiteralNull_ReturnsRetryForm_NoNullReference()
        {
            // JsonConvert.DeserializeObject<FormResult>("null") returns null; the second guard must catch it.
            var adapter = NewAdapter();
            var proof = new FakeProofData(new Dictionary<string, object> { ["formResult"] = "null" });
            var ctx = new FakeAuthContext(MinimalContext());

            IAdapterPresentation result = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] claims);

            Assert.IsNotNull(result);
            Assert.AreEqual(0, claims.Length);
        }

        [TestMethod]
        public void FormResultMalformedJson_ReturnsRetryForm_NoJsonException()
        {
            // A non-empty formResult that isn't valid JSON must not let a JsonException escape as a 500;
            // it degrades to the retryable error form like the null/empty cases.
            var adapter = NewAdapter();
            var proof = new FakeProofData(new Dictionary<string, object> { ["formResult"] = "not json {" });
            var ctx = new FakeAuthContext(MinimalContext());

            IAdapterPresentation result = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] claims);

            Assert.IsNotNull(result);
            Assert.AreEqual(0, claims.Length);
        }

        [TestMethod]
        public void NullAuthContext_ReturnsRetryForm_NoNullReference()
        {
            // A null context must not NRE (nor throw ExternalAuthenticationException, whose constructor
            // rejects a null context); it degrades to the retryable error form.
            var adapter = NewAdapter();
            var proof = new FakeProofData(new Dictionary<string, object> { ["formResult"] = "{}" });

            IAdapterPresentation result = adapter.TryEndAuthentication(null, proof, null, out Claim[] claims);

            Assert.IsNotNull(result, "Expected a presentation form, not null (which would signal success).");
            Assert.AreEqual(0, claims.Length);
        }

        [TestMethod]
        public void NullAuthContextData_ReturnsRetryForm_NoNullReference()
        {
            var adapter = NewAdapter();
            var proof = new FakeProofData(new Dictionary<string, object> { ["formResult"] = "{}" });
            var ctx = new FakeAuthContext(null);

            IAdapterPresentation result = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] claims);

            Assert.IsNotNull(result);
            Assert.AreEqual(0, claims.Length);
        }
    }
}
