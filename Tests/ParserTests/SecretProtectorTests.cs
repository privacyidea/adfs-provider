using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;

namespace Tests.ParserTests
{
    /// <summary>
    /// Coverage for the marker-based detection that decides whether a stored secret is already
    /// DPAPI-encrypted or is legacy plaintext that must be migrated. The DPAPI Protect/Unprotect
    /// round-trip itself is not exercised here: ProtectedData is a Windows .NET Framework API that
    /// does not load under the net8.0 test host, and these tests deliberately only touch the pure
    /// string logic so they never JIT it.
    /// </summary>
    [TestClass]
    public class SecretProtectorTests
    {
        [TestMethod]
        public void IsProtected_True_ForMarkedValue()
        {
            Assert.IsTrue(SecretProtector.IsProtected("enc:AQAAANCMnd8BFdERjHoAwE/Cl+s"));
        }

        [TestMethod]
        public void IsProtected_False_ForPlaintext()
        {
            Assert.IsFalse(SecretProtector.IsProtected("hunter2"));
        }

        [TestMethod]
        public void IsProtected_False_ForEmptyOrNull()
        {
            Assert.IsFalse(SecretProtector.IsProtected(""));
            Assert.IsFalse(SecretProtector.IsProtected(null));
        }

        [TestMethod]
        public void IsProtected_False_WhenMarkerNotAtStart()
        {
            // A plaintext password that merely contains "enc:" somewhere must not be mistaken for ciphertext.
            Assert.IsFalse(SecretProtector.IsProtected("my enc:pass"));
        }
    }
}
