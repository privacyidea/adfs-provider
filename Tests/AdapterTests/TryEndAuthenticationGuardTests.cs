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
    /// Regression tests for the null-safety guards at the top of Adapter.TryEndAuthentication.
    /// Historically, a passive federation request that reached the handler with an empty/unparseable
    /// formResult (the hidden field is only populated by the page JavaScript on submit) or a null
    /// authentication context threw a NullReferenceException straight out of TryEndAuthentication.
    /// This was observed against the device-registration/OAuth relying party (urn:ms-drs), where the
    /// form can be posted without the page JS having run. The guards must turn those into a graceful
    /// retry form / ExternalAuthenticationException instead.
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
        public void FormResultEmptyString_ReturnsRetryForm_NoNullReference()
        {
            // The hidden field is posted present but empty when the page JS never populated it.
            var adapter = NewAdapter();
            var proof = new FakeProofData(new Dictionary<string, object> { ["formResult"] = "" });
            var ctx = new FakeAuthContext(MinimalContext());

            IAdapterPresentation result = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] claims);

            Assert.IsNotNull(result, "Expected a presentation form, not null (which would signal success).");
            Assert.AreEqual(0, claims.Length);
        }

        [TestMethod]
        public void FormResultWhitespace_ReturnsRetryForm_NoNullReference()
        {
            var adapter = NewAdapter();
            var proof = new FakeProofData(new Dictionary<string, object> { ["formResult"] = "   " });
            var ctx = new FakeAuthContext(MinimalContext());

            IAdapterPresentation result = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] claims);

            Assert.IsNotNull(result);
            Assert.AreEqual(0, claims.Length);
        }

        [TestMethod]
        public void FormResultMissing_ReturnsRetryForm_NoNullReference()
        {
            var adapter = NewAdapter();
            var proof = new FakeProofData(new Dictionary<string, object>());
            var ctx = new FakeAuthContext(MinimalContext());

            IAdapterPresentation result = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] claims);

            Assert.IsNotNull(result);
            Assert.AreEqual(0, claims.Length);
        }

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
        public void FormResultNonString_ReturnsRetryForm_NoInvalidCast()
        {
            // A non-string value must not blow up on the (string) cast; `as string` routes it to the guard.
            var adapter = NewAdapter();
            var proof = new FakeProofData(new Dictionary<string, object> { ["formResult"] = 42 });
            var ctx = new FakeAuthContext(MinimalContext());

            IAdapterPresentation result = adapter.TryEndAuthentication(ctx, proof, null, out Claim[] claims);

            Assert.IsNotNull(result);
            Assert.AreEqual(0, claims.Length);
        }

        [TestMethod]
        [ExpectedException(typeof(ExternalAuthenticationException))]
        public void NullAuthContext_ThrowsExternalAuthenticationException_NotNullReference()
        {
            var adapter = NewAdapter();
            var proof = new FakeProofData(new Dictionary<string, object> { ["formResult"] = "{}" });

            adapter.TryEndAuthentication(null, proof, null, out _);
        }

        [TestMethod]
        [ExpectedException(typeof(ExternalAuthenticationException))]
        public void NullAuthContextData_ThrowsExternalAuthenticationException_NotNullReference()
        {
            var adapter = NewAdapter();
            var proof = new FakeProofData(new Dictionary<string, object> { ["formResult"] = "{}" });
            var ctx = new FakeAuthContext(null);

            adapter.TryEndAuthentication(ctx, proof, null, out _);
        }
    }
}
