namespace Tests.Fixtures
{
    /// <summary>
    /// Response bodies for WebAuthn challenges. Covers single-credential and the
    /// multi-credential case the parser merges via MergedSignRequest().
    /// </summary>
    internal static class WebAuthnFixtures
    {
        /// Single WebAuthn challenge — one allowed credential.
        public const string SingleWebAuthnChallenge = @"{
            ""detail"": {
                ""client_mode"": ""webauthn"",
                ""message"": ""Please confirm with your WebAuthn token"",
                ""multi_challenge"": [{
                    ""attributes"": {
                        ""webAuthnSignRequest"": {
                            ""allowCredentials"": [{
                                ""id"": ""credential-id-1"",
                                ""transports"": [""usb"", ""nfc""],
                                ""type"": ""public-key""
                            }],
                            ""challenge"": ""challenge-bytes"",
                            ""rpId"": ""sso.example.com"",
                            ""timeout"": 60000,
                            ""userVerification"": ""preferred""
                        }
                    },
                    ""client_mode"": ""webauthn"",
                    ""message"": ""Please confirm with your WebAuthn token"",
                    ""serial"": ""WAN00001111"",
                    ""transaction_id"": ""66666666666666666666"",
                    ""type"": ""webauthn""
                }],
                ""serial"": ""WAN00001111"",
                ""transaction_id"": ""66666666666666666666"",
                ""type"": ""webauthn""
            },
            ""result"": {""authentication"": ""CHALLENGE"", ""status"": true, ""value"": false}
        }";

        /// Two WebAuthn challenges issued together — same user has multiple devices.
        /// The client merges them into one sign request with two allowed credentials.
        public const string DualWebAuthnChallenge = @"{
            ""detail"": {
                ""client_mode"": ""webauthn"",
                ""message"": ""Please confirm with your WebAuthn token"",
                ""multi_challenge"": [
                    {
                        ""attributes"": {
                            ""webAuthnSignRequest"": {
                                ""allowCredentials"": [{
                                    ""id"": ""cred-A"",
                                    ""transports"": [""usb""],
                                    ""type"": ""public-key""
                                }],
                                ""challenge"": ""challenge-bytes"",
                                ""rpId"": ""sso.example.com"",
                                ""timeout"": 60000,
                                ""userVerification"": ""preferred""
                            }
                        },
                        ""client_mode"": ""webauthn"",
                        ""message"": ""Please confirm with your WebAuthn token A"",
                        ""serial"": ""WAN0000AAAA"",
                        ""transaction_id"": ""77777777777777777777"",
                        ""type"": ""webauthn""
                    },
                    {
                        ""attributes"": {
                            ""webAuthnSignRequest"": {
                                ""allowCredentials"": [{
                                    ""id"": ""cred-B"",
                                    ""transports"": [""nfc""],
                                    ""type"": ""public-key""
                                }],
                                ""challenge"": ""challenge-bytes"",
                                ""rpId"": ""sso.example.com"",
                                ""timeout"": 60000,
                                ""userVerification"": ""preferred""
                            }
                        },
                        ""client_mode"": ""webauthn"",
                        ""message"": ""Please confirm with your WebAuthn token B"",
                        ""serial"": ""WAN0000BBBB"",
                        ""transaction_id"": ""77777777777777777777"",
                        ""type"": ""webauthn""
                    }
                ],
                ""transaction_id"": ""77777777777777777777"",
                ""type"": ""webauthn""
            },
            ""result"": {""authentication"": ""CHALLENGE"", ""status"": true, ""value"": false}
        }";
    }
}
