using System;
using System.Text;
using PrivacyIDEAADFSProvider.PrivacyIDEA_Client;
using WireMock.Server;

namespace Tests
{
    internal static class TestHelpers
    {
        /// <summary>
        /// Builds a PrivacyIDEA client pointed at the given mock server. SSL verification
        /// is disabled because WireMock serves plain HTTP.
        /// </summary>
        public static PrivacyIDEA PIPointedAt(WireMockServer server, string userAgent = "test")
        {
            return new PrivacyIDEA(server.Urls[0], userAgent, sslVerify: false);
        }

        /// <summary>
        /// Builds a syntactically-valid JWT with the given expiry. Signature is a fixed
        /// dummy string; the client never validates it, it only decodes the payload to
        /// read the `exp` claim for the cache window.
        /// </summary>
        public static string MakeJwt(DateTime expiryUtc)
        {
            long expSeconds = ((DateTimeOffset)DateTime.SpecifyKind(expiryUtc, DateTimeKind.Utc)).ToUnixTimeSeconds();
            const string header = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"; // {"typ":"JWT","alg":"HS256"}
            string payloadJson = "{\"exp\":" + expSeconds + "}";
            string payload = Convert.ToBase64String(Encoding.UTF8.GetBytes(payloadJson))
                .Replace('+', '-').Replace('/', '_').TrimEnd('=');
            return header + "." + payload + ".dummy";
        }

        /// <summary>
        /// /auth response body that wraps the given JWT in privacyIDEA's response envelope.
        /// </summary>
        public static string AuthResponse(string jwt)
        {
            return "{\"result\":{\"status\":true,\"value\":{\"token\":\"" + jwt + "\"}}}";
        }
    }
}
