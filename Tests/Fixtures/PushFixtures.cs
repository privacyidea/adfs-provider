namespace Tests.Fixtures
{
    /// <summary>
    /// Response bodies for push authentication: the initial challenge, the poll states
    /// (pending vs accepted), and the final ACCEPT after the smartphone confirms.
    /// </summary>
    internal static class PushFixtures
    {
        /// Push challenge — triggered by /validate/triggerchallenge or by /validate/check
        /// against a push token. client_mode=poll signals the client to poll.
        public const string PushChallenge = @"{
            ""detail"": {
                ""client_mode"": ""poll"",
                ""message"": ""Please confirm the authentication on your mobile device!"",
                ""multi_challenge"": [{
                    ""client_mode"": ""poll"",
                    ""message"": ""Please confirm the authentication on your mobile device!"",
                    ""serial"": ""PIPU0001F75E"",
                    ""transaction_id"": ""02659936574063359702"",
                    ""type"": ""push""
                }],
                ""serial"": ""PIPU0001F75E"",
                ""transaction_id"": ""02659936574063359702"",
                ""type"": ""push""
            },
            ""result"": {""authentication"": ""CHALLENGE"", ""status"": true, ""value"": false}
        }";

        /// push_code_to_phone challenge — type=push but client_mode=interactive: the smartphone shows a
        /// short code after the user confirms, which the user types into the OTP input. It can never be
        /// answered by polling, so the client must NOT offer the push-poll option for it.
        public const string CodeToPhoneChallenge = @"{
            ""detail"": {
                ""attributes"": {""hideResponseInput"": false},
                ""client_mode"": ""interactive"",
                ""message"": ""Please enter the code displayed on your smartphone."",
                ""multi_challenge"": [{
                    ""attributes"": {""hideResponseInput"": false},
                    ""client_mode"": ""interactive"",
                    ""message"": ""Please enter the code displayed on your smartphone."",
                    ""serial"": ""PIPU0001F75E"",
                    ""transaction_id"": ""00110530786071310297"",
                    ""type"": ""push""
                }],
                ""preferred_client_mode"": ""interactive"",
                ""serial"": ""PIPU0001F75E"",
                ""transaction_id"": ""00110530786071310297"",
                ""type"": ""push""
            },
            ""result"": {""authentication"": ""CHALLENGE"", ""status"": true, ""value"": false}
        }";

        /// /validate/polltransaction response while the user has not yet confirmed.
        public const string PollPending = @"{
            ""detail"": {""challenge_status"": ""pending""},
            ""result"": {""status"": true, ""value"": false}
        }";

        /// /validate/polltransaction response once the smartphone has confirmed.
        public const string PollAccepted = @"{
            ""detail"": {""challenge_status"": ""accept""},
            ""result"": {""status"": true, ""value"": true}
        }";

        /// Final /validate/check ACCEPT after a confirmed push (empty pass + transaction id).
        public const string PushFinalAccept = @"{
            ""detail"": {""message"": ""Found matching challenge"", ""serial"": ""PIPU0001F75E""},
            ""result"": {""authentication"": ""ACCEPT"", ""status"": true, ""value"": true}
        }";
    }
}
