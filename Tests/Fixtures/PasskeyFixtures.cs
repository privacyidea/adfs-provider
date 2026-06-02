namespace Tests.Fixtures
{
    /// <summary>
    /// Response bodies for passkey authentication and passkey registration via
    /// enroll_via_multichallenge.
    /// </summary>
    internal static class PasskeyFixtures
    {
        /// /validate/initialize response that starts a usernameless passkey login.
        /// Carries a `passkey` object in detail with its own transaction_id.
        public const string PasskeyInitChallenge = @"{
            ""detail"": {
                ""passkey"": {
                    ""challenge"": ""challenge-bytes-go-here"",
                    ""rpId"": ""sso.example.com"",
                    ""transaction_id"": ""44444444444444444444"",
                    ""user_verification"": ""preferred""
                }
            },
            ""result"": {""authentication"": ""CHALLENGE"", ""status"": true, ""value"": false}
        }";

        /// /validate/check ACCEPT after a passkey sign response. detail.username is the
        /// user that was actually authenticated — the client uses this to guard against
        /// a passkey from someone other than the user trying to log in.
        public const string PasskeyAuthAccept = @"{
            ""detail"": {
                ""username"": ""alice"",
                ""message"": ""Authentication successful""
            },
            ""result"": {""authentication"": ""ACCEPT"", ""status"": true, ""value"": true}
        }";

        /// Same ACCEPT but for a different user, for testing the "wrong user" guard.
        public const string PasskeyAuthAcceptDifferentUser = @"{
            ""detail"": {
                ""username"": ""bob"",
                ""message"": ""Authentication successful""
            },
            ""result"": {""authentication"": ""ACCEPT"", ""status"": true, ""value"": true}
        }";

        /// CHALLENGE that asks the user to register a passkey
        /// (enroll_via_multichallenge=PASSKEY). The `passkey_registration` field
        /// carries the full CredentialCreationOptions payload as a JSON string.
        public const string PasskeyRegistrationChallenge = @"{
            ""detail"": {
                ""client_mode"": ""webauthn"",
                ""enroll_via_multichallenge"": true,
                ""enroll_via_multichallenge_optional"": false,
                ""message"": ""Please confirm the registration with your passkey!"",
                ""multi_challenge"": [{
                    ""client_mode"": ""webauthn"",
                    ""message"": ""Please confirm the registration with your passkey!"",
                    ""passkey_registration"": {
                        ""rp"": {""id"": ""sso.example.com"", ""name"": ""privacyIDEA""},
                        ""user"": {""id"": ""dXNlcg"", ""name"": ""alice"", ""displayName"": ""Alice""},
                        ""challenge"": ""regchallenge"",
                        ""pubKeyCredParams"": [{""alg"": -7, ""type"": ""public-key""}]
                    },
                    ""serial"": ""PIPK00001234"",
                    ""transaction_id"": ""55555555555555555555"",
                    ""type"": ""passkey""
                }],
                ""serial"": ""PIPK00001234"",
                ""transaction_id"": ""55555555555555555555"",
                ""type"": ""passkey""
            },
            ""result"": {""authentication"": ""CHALLENGE"", ""status"": true, ""value"": false}
        }";
    }
}
