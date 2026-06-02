namespace Tests.Fixtures
{
    /// <summary>
    /// Response bodies for the plain OTP / passthru / error paths of /validate/check.
    /// </summary>
    internal static class OtpFixtures
    {
        /// Successful TOTP authentication, no challenge involved.
        public const string SimpleAccept = @"{
            ""detail"": {
                ""message"": ""matching 1 tokens"",
                ""otplen"": 6,
                ""serial"": ""TOTP00001234"",
                ""type"": ""totp""
            },
            ""result"": {""authentication"": ""ACCEPT"", ""status"": true, ""value"": true}
        }";

        /// Wrong OTP value — REJECT, no transaction id.
        public const string SimpleReject = @"{
            ""detail"": {""message"": ""wrong otp value""},
            ""result"": {""authentication"": ""REJECT"", ""status"": true, ""value"": false}
        }";

        /// CHALLENGE response from validate/check: a token type that requires
        /// challenge-response (HOTP), no enrollment image.
        public const string OtpChallenge = @"{
            ""detail"": {
                ""client_mode"": ""interactive"",
                ""message"": ""Please enter the OTP"",
                ""multi_challenge"": [{
                    ""client_mode"": ""interactive"",
                    ""message"": ""Please enter the OTP"",
                    ""serial"": ""OATH0000DEAD"",
                    ""transaction_id"": ""11111111111111111111"",
                    ""type"": ""hotp""
                }],
                ""serial"": ""OATH0000DEAD"",
                ""transaction_id"": ""11111111111111111111"",
                ""type"": ""hotp""
            },
            ""result"": {""authentication"": ""CHALLENGE"", ""status"": true, ""value"": false}
        }";

        /// Server-side error: status=false with a populated error.code / error.message.
        /// Returned with HTTP 400 by the server, but the parser only sees the body.
        public const string ServerError = @"{
            ""detail"": null,
            ""result"": {
                ""error"": {""code"": 904, ""message"": ""ERR904: User not found""},
                ""status"": false
            }
        }";

        /// Final ACCEPT after answering an outstanding challenge.
        public const string ChallengeCompletionAccept = @"{
            ""detail"": {""message"": ""Found matching challenge"", ""serial"": ""OATH0000DEAD""},
            ""result"": {""authentication"": ""ACCEPT"", ""status"": true, ""value"": true}
        }";

        /// preferred_client_mode=interactive should be translated to "otp" by the parser
        /// (the field rewriting is part of PIResponse.FromJSON).
        public const string PreferredClientModeInteractive = @"{
            ""detail"": {
                ""message"": ""Please enter the OTP"",
                ""preferred_client_mode"": ""interactive"",
                ""multi_challenge"": [{
                    ""client_mode"": ""interactive"",
                    ""message"": ""Please enter the OTP"",
                    ""serial"": ""OATH0000DEAD"",
                    ""transaction_id"": ""22222222222222222222"",
                    ""type"": ""hotp""
                }],
                ""transaction_id"": ""22222222222222222222"",
                ""type"": ""hotp""
            },
            ""result"": {""authentication"": ""CHALLENGE"", ""status"": true, ""value"": false}
        }";

        /// preferred_client_mode=poll should be translated to "push".
        public const string PreferredClientModePoll = @"{
            ""detail"": {
                ""message"": ""Please confirm on your device"",
                ""preferred_client_mode"": ""poll"",
                ""multi_challenge"": [{
                    ""client_mode"": ""poll"",
                    ""message"": ""Please confirm on your device"",
                    ""serial"": ""PIPU000012AB"",
                    ""transaction_id"": ""33333333333333333333"",
                    ""type"": ""push""
                }],
                ""transaction_id"": ""33333333333333333333"",
                ""type"": ""push""
            },
            ""result"": {""authentication"": ""CHALLENGE"", ""status"": true, ""value"": false}
        }";
    }
}
