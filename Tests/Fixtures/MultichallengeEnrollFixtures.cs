namespace Tests.Fixtures
{
    /// <summary>
    /// Captured response bodies for the enroll-via-multichallenge flow. Each constant is
    /// a representative server response; the parser only inspects JSON structure, so PNG
    /// payloads and long otpauth secrets are abbreviated to keep the strings readable.
    /// </summary>
    internal static class MultichallengeEnrollFixtures
    {
        /// HOTP enroll-via-multichallenge CHALLENGE — mandatory enrollment.
        public const string HotpEnrollChallenge = @"{
            ""detail"": {
                ""client_mode"": ""interactive"",
                ""enroll_via_multichallenge"": true,
                ""enroll_via_multichallenge_optional"": false,
                ""image"": ""data:image/png;base64,STUB"",
                ""link"": ""otpauth://hotp/OATH0000AC38?secret=ABCDEFG"",
                ""message"": ""Please scan the QR code and enter the OTP value!"",
                ""multi_challenge"": [{
                    ""client_mode"": ""interactive"",
                    ""image"": ""data:image/png;base64,STUB"",
                    ""link"": ""otpauth://hotp/OATH0000AC38?secret=ABCDEFG"",
                    ""message"": ""Please scan the QR code and enter the OTP value!"",
                    ""serial"": ""OATH0000AC38"",
                    ""transaction_id"": ""18249856845542401525"",
                    ""type"": ""hotp""
                }],
                ""serial"": ""OATH0000AC38"",
                ""transaction_id"": ""18249856845542401525"",
                ""type"": ""hotp""
            },
            ""result"": {""authentication"": ""CHALLENGE"", ""status"": true, ""value"": false}
        }";

        /// Same shape as HotpEnrollChallenge but with enroll_via_multichallenge_optional=true,
        /// which is what makes the "Not Now" path eligible.
        public const string HotpEnrollChallengeOptional = @"{
            ""detail"": {
                ""client_mode"": ""interactive"",
                ""enroll_via_multichallenge"": true,
                ""enroll_via_multichallenge_optional"": true,
                ""image"": ""data:image/png;base64,STUB"",
                ""link"": ""otpauth://hotp/OATH0000F6AF?secret=ABCDEFG"",
                ""message"": ""Please scan the QR code and enter the OTP value!"",
                ""multi_challenge"": [{
                    ""client_mode"": ""interactive"",
                    ""image"": ""data:image/png;base64,STUB"",
                    ""link"": ""otpauth://hotp/OATH0000F6AF?secret=ABCDEFG"",
                    ""message"": ""Please scan the QR code and enter the OTP value!"",
                    ""serial"": ""OATH0000F6AF"",
                    ""transaction_id"": ""08062584491116057815"",
                    ""type"": ""hotp""
                }],
                ""serial"": ""OATH0000F6AF"",
                ""transaction_id"": ""08062584491116057815"",
                ""type"": ""hotp""
            },
            ""result"": {""authentication"": ""CHALLENGE"", ""status"": true, ""value"": false}
        }";

        /// Email enrollment, first step — server asks for the user's email address. No
        /// image; the prompt itself is the entire challenge.
        public const string EmailEnrollAskForAddress = @"{
            ""detail"": {
                ""client_mode"": ""interactive"",
                ""enroll_via_multichallenge"": true,
                ""enroll_via_multichallenge_optional"": false,
                ""image"": null,
                ""message"": ""Please enter your new email address!"",
                ""multi_challenge"": [{
                    ""client_mode"": ""interactive"",
                    ""image"": null,
                    ""message"": ""Please enter your new email address!"",
                    ""serial"": ""PIEM0000733A"",
                    ""transaction_id"": ""02615784748381378184"",
                    ""type"": ""email""
                }],
                ""serial"": ""PIEM0000733A"",
                ""transaction_id"": ""02615784748381378184"",
                ""type"": ""email""
            },
            ""result"": {""authentication"": ""CHALLENGE"", ""status"": true, ""value"": false}
        }";

        /// Smartphone container enrollment — uses client_mode=poll and a pia:// link.
        public const string SmartphoneEnrollChallenge = @"{
            ""detail"": {
                ""client_mode"": ""poll"",
                ""enroll_via_multichallenge"": true,
                ""enroll_via_multichallenge_optional"": false,
                ""image"": ""data:image/png;base64,STUB"",
                ""link"": ""pia://container/SMPH0000D847?issuer=privacyIDEA&ttl=10"",
                ""message"": ""Please scan the QR code to register the container."",
                ""multi_challenge"": [{
                    ""client_mode"": ""poll"",
                    ""image"": ""data:image/png;base64,STUB"",
                    ""link"": ""pia://container/SMPH0000D847?issuer=privacyIDEA&ttl=10"",
                    ""message"": ""Please scan the QR code to register the container."",
                    ""serial"": ""SMPH0000D847"",
                    ""transaction_id"": ""17359662976761378280"",
                    ""type"": ""smartphone""
                }],
                ""serial"": ""SMPH0000D847"",
                ""transaction_id"": ""17359662976761378280"",
                ""type"": ""smartphone""
            },
            ""result"": {""authentication"": ""CHALLENGE"", ""status"": true, ""value"": false}
        }";

        /// Server ACK after a successful cancel_enrollment=True on an optional enrollment.
        public const string CancelEnrollmentAccept = @"{
            ""detail"": {""message"": ""Cancelled enrollment via multichallenge""},
            ""result"": {""authentication"": ""ACCEPT"", ""status"": true, ""value"": true}
        }";

        /// Server response when cancel_enrollment=True is sent against a non-optional
        /// enrollment — treated as a wrong OTP, REJECT.
        public const string CancelEnrollmentReject = @"{
            ""detail"": {""message"": ""Failed to cancel enrollment via multichallenge""},
            ""result"": {""authentication"": ""REJECT"", ""status"": true, ""value"": false}
        }";
    }
}
