using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrivacyIDEASDK;
using WireMock.RequestBuilders;
using WireMock.ResponseBuilders;
using WireMock.Server;

namespace Tests
{
    [TestClass]
    public class SDKTests
    {
        WireMockServer server;
        PrivacyIDEA privacyIDEA;

        [TestInitialize]
        public void Setup()
        {
            server = WireMockServer.Start();
            privacyIDEA = new PrivacyIDEA(server.Urls[0], "test", false);
        }

        [TestCleanup]
        public void Cleanup()
        {
            server.Stop();
        }

        [TestMethod]
        public void SimpleOTP()
        {
            server
                .Given(
                    Request.Create()
                    .WithPath("/validate/check")
                    .UsingPost()
                    .WithBody("user=test&pass=test")
                    .WithHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                    )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(200)
                    .WithBody("{\n" +
                        "\"detail\":" +
                        " {\n" +
                            "\"message\": \"matching 1 tokens\",\n" +
                            "\"otplen\": 6,\n" +
                            "\"serial\": \"PISP0001C673\",\n" +
                            "\"threadid\": 140536383567616,\n" +
                            "\"type\": \"totp\"\n" +
                        "},\n" +
                        "\"id\": 1,\n" +
                        "\"jsonrpc\": \"2.0\",\n" +
                        "\"result\": " +
                        "{\n" +
                            "\"status\": true,\n" +
                            "\"value\": true\n" +
                        "},\n" +
                        "\"time\": 1589276995.4397042,\n" +
                        "\"version\": \"privacyIDEA 3.2.1\",\n" +
                        "\"versionnumber\": \"3.2.1\",\n" +
                        "\"signature\": \"rsa_sha256_pss:AAAAAAAAAAA\"}"));

            var resp = privacyIDEA.ValidateCheck("test", "test");

            Assert.IsNotNull(resp);
            Assert.IsTrue(resp.Value);
            Assert.IsTrue(resp.Status);
            Assert.AreEqual("totp", resp.Type);
            Assert.AreEqual("PISP0001C673", resp.Serial);
        }

        [TestMethod]
        public void TriggerChallenges()
        {
            string authToken = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicmVhbG0iOiIiLCJub25jZSI6IjVjOTc4NWM5OWU" +
                "4ZDVhODY5YzUzNGI5ZmY1MWFmNzI2ZjI5OTE2YmYiLCJyb2xlIjoiYWRtaW4iLCJhdXRodHlwZSI6InBhc3N3b3JkIiwiZXhwIjoxNTg5NDUwMzk0LC" +
                "JyaWdodHMiOlsicG9saWN5ZGVsZXRlIiwic3RhdGlzdGljc19yZWFkIiwiYXVkaXRsb2ciLCJlbmFibGUiLCJ1c2VybGlzdCIsInVwZGF0ZXVzZXIiL" +
                "CJhZGR1c2VyIiwiZW5yb2xsU1BBU1MiLCJjYWNvbm5lY3RvcndyaXRlIiwidW5hc3NpZ24iLCJkZWxldGV1c2VyIiwic2V0cGluIiwiZGlzYWJsZSIs" +
                "ImVucm9sbFNTSEtFWSIsImZldGNoX2F1dGhlbnRpY2F0aW9uX2l0ZW1zIiwicHJpdmFjeWlkZWFzZXJ2ZXJfcmVhZCIsImdldHJhbmRvbSIsImVucm9" +
                "sbFNNUyIsIm1yZXNvbHZlcndyaXRlIiwicmFkaXVzc2VydmVyX3dyaXRlIiwiaW1wb3J0dG9rZW5zIiwic2V0X2hzbV9wYXNzd29yZCIsImVucm9sbF" +
                "JFTU9URSIsImVucm9sbFUyRiIsInByaXZhY3lpZGVhc2VydmVyX3dyaXRlIiwiZW5yb2xsUkFESVVTIiwiY29weXRva2VucGluIiwiZW5yb2xsRU1BS" +
                "UwiLCJyZXNldCIsImNhY29ubmVjdG9yZGVsZXRlIiwiZW5yb2xsVkFTQ08iLCJlbnJvbGxSRUdJU1RSQVRJT04iLCJzZXQiLCJnZXRzZXJpYWwiLCJw" +
                "ZXJpb2RpY3Rhc2tfcmVhZCIsImV2ZW50aGFuZGxpbmdfd3JpdGUiLCJtcmVzb2x2ZXJkZWxldGUiLCJyZXNvbHZlcmRlbGV0ZSIsInNtdHBzZXJ2ZXJ" +
                "fd3JpdGUiLCJyYWRpdXNzZXJ2ZXJfcmVhZCIsImVucm9sbDRFWUVTIiwiZW5yb2xsUEFQRVIiLCJlbnJvbGxZVUJJQ08iLCJnZXRjaGFsbGVuZ2VzIi" +
                "wibWFuYWdlc3Vic2NyaXB0aW9uIiwibG9zdHRva2VuIiwiZGVsZXRlIiwiZW5yb2xscGluIiwic21zZ2F0ZXdheV93cml0ZSIsImVucm9sbFBVU0giL" +
                "CJlbnJvbGxNT1RQIiwibWFuYWdlX21hY2hpbmVfdG9rZW5zIiwic3lzdGVtX2RvY3VtZW50YXRpb24iLCJtYWNoaW5lbGlzdCIsInRyaWdnZXJjaGFs" +
                "bGVuZ2UiLCJzdGF0aXN0aWNzX2RlbGV0ZSIsInJlc29sdmVyd3JpdGUiLCJjbGllbnR0eXBlIiwic2V0dG9rZW5pbmZvIiwiZW5yb2xsT0NSQSIsImF" +
                "1ZGl0bG9nX2Rvd25sb2FkIiwiZW5yb2xsUFciLCJlbnJvbGxIT1RQIiwiZW5yb2xsVEFOIiwiZXZlbnRoYW5kbGluZ19yZWFkIiwiY29weXRva2VudX" +
                "NlciIsInRva2VubGlzdCIsInNtdHBzZXJ2ZXJfcmVhZCIsImVucm9sbERBUExVRyIsInJldm9rZSIsImVucm9sbFRPVFAiLCJjb25maWdyZWFkIiwiY" +
                "29uZmlnd3JpdGUiLCJzbXNnYXRld2F5X3JlYWQiLCJlbnJvbGxRVUVTVElPTiIsInRva2VucmVhbG1zIiwiZW5yb2xsVElRUiIsInBvbGljeXJlYWQi" +
                "LCJtcmVzb2x2ZXJyZWFkIiwicGVyaW9kaWN0YXNrX3dyaXRlIiwicG9saWN5d3JpdGUiLCJyZXNvbHZlcnJlYWQiLCJlbnJvbGxDRVJUSUZJQ0FURSI" +
                "sImFzc2lnbiIsImNvbmZpZ2RlbGV0ZSIsImVucm9sbFlVQklLRVkiLCJyZXN5bmMiXX0.HvP_hgA-UJFINXnwoBVmAurqcaaMmwM-AsD1S6chGIM";

            string webAuthnSignRequest1 = "{\n" +
                "            \"allowCredentials\": [\n" +
                "              {\n" +
                "                \"id\": \"83De8z_CNqogB6aCyKs6dWIqwpOpzVoNaJ74lgcpuYN7l-95QsD3z-qqPADqsFlPwBXCMqEPssq75kqHCMQHDA\",\n" +
                "                \"transports\": [\n" +
                "                  \"internal\",\n" +
                "                  \"nfc\",\n" +
                "                  \"ble\",\n" +
                "                  \"usb\"\n" +
                "                ],\n" +
                "                \"type\": \"public-key\"\n" +
                "              }\n" +
                "            ],\n" +
                "            \"challenge\": \"dHzSmZnAhxEq0szRWMY4EGg8qgjeBhJDjAPYKWfd2IE\",\n" +
                "            \"rpId\": \"office.netknights.it\",\n" +
                "            \"timeout\": 60000,\n" +
                "            \"userVerification\": \"preferred\"\n" +
                "          }\n";

            string webAuthnSignRequest2 = "{\n" +
                "            \"allowCredentials\": [\n" +
                "              {\n" +
                "                \"id\": \"83De8z_CNqogB6aCyKs6dWIqwnrijhva23onu230985uc2m08uiowejrtcoml3XCMqEPssq75kqHCMQHDA\",\n" +
                "                \"transports\": [\n" +
                "                  \"internal\",\n" +
                "                  \"nfc\",\n" +
                "                  \"ble\",\n" +
                "                  \"usb\"\n" +
                "                ],\n" +
                "                \"type\": \"public-key\"\n" +
                "              }\n" +
                "            ],\n" +
                "            \"challenge\": \"dHzSmZnAhxEqvtw34v43v2335vc25c22IE\",\n" +
                "            \"rpId\": \"office.netknights.it\",\n" +
                "            \"timeout\": 60000,\n" +
                "            \"userVerification\": \"preferred\"\n" +
                "          }\n";

            string mergedSignRequests = "{\n" +
                "            \"challenge\": \"dHzSmZnAhxEq0szRWMY4EGg8qgjeBhJDjAPYKWfd2IE\",\n" +
                "            \"rpId\": \"office.netknights.it\",\n" +
                "            \"timeout\": 60000,\n" +
                "            \"userVerification\": \"preferred\",\n" +
                "            \"allowCredentials\": [\n" +
                "              {\n" +
                "                \"id\": \"83De8z_CNqogB6aCyKs6dWIqwpOpzVoNaJ74lgcpuYN7l-95QsD3z-qqPADqsFlPwBXCMqEPssq75kqHCMQHDA\",\n" +
                "                \"transports\": [\n" +
                "                  \"internal\",\n" +
                "                  \"nfc\",\n" +
                "                  \"ble\",\n" +
                "                  \"usb\"\n" +
                "                ],\n" +
                "                \"type\": \"public-key\"\n" +
                "              },\n" +
                "              {\n" +
                "                \"id\": \"83De8z_CNqogB6aCyKs6dWIqwnrijhva23onu230985uc2m08uiowejrtcoml3XCMqEPssq75kqHCMQHDA\",\n" +
                "                \"transports\": [\n" +
                "                  \"internal\",\n" +
                "                  \"nfc\",\n" +
                "                  \"ble\",\n" +
                "                  \"usb\"\n" +
                "                ],\n" +
                "                \"type\": \"public-key\"\n" +
                "              }\n" +
                "            ]\n" +
                "          }";

            // Auth token response
            server.Given(
                    Request.Create()
                    .WithPath("/auth")
                    .UsingPost()
                    .WithBody("username=admin&password=admin")
                    .WithHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                    )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(200)
                    .WithBody("{\n" +
                                "    \"id\": 1,\n" +
                                "    \"jsonrpc\": \"2.0\",\n" +
                                "    \"result\": {\n" +
                                "        \"status\": true,\n" +
                                "        \"value\": {\n" +
                                "            \"log_level\": 20,\n" +
                                "            \"menus\": [\n" +
                                "                \"components\",\n" +
                                "                \"machines\"\n" +
                                "            ],\n" +
                                "            \"realm\": \"\",\n" +
                                "            \"rights\": [\n" +
                                "                \"policydelete\",\n" +
                                "                \"resync\"\n" +
                                "            ],\n" +
                                "            \"role\": \"admin\",\n" +
                                "            \"token\": \"" + authToken + "\",\n" +
                                "            \"username\": \"admin\",\n" +
                                "            \"logout_time\": 120,\n" +
                                "            \"default_tokentype\": \"hotp\",\n" +
                                "            \"user_details\": false,\n" +
                                "            \"subscription_status\": 0\n" +
                                "        }\n" +
                                "    },\n" +
                                "    \"time\": 1589446794.8502703,\n" +
                                "    \"version\": \"privacyIDEA 3.2.1\",\n" +
                                "    \"versionnumber\": \"3.2.1\",\n" +
                                "    \"signature\": \"rsa_sha256_pss:\"\n" +
                                "}"));

            // Trigger challenge response
            server
                .Given(
                    Request.Create()
                    .WithPath("/validate/triggerchallenge")
                    .UsingPost()
                    .WithBody("user=test")
                    .WithHeader("Authorization", authToken)
                    .WithHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
                    )
                .RespondWith(
                    Response.Create()
                    .WithStatusCode(200)
                    .WithBody("{\n" +
                                "  \"detail\": {\n" +
                                "    \"attributes\": null,\n" +
                                "    \"message\": \"Bitte geben Sie einen OTP-Wert ein: , Please confirm the authentication on your mobile device!\",\n" +
                                "    \"messages\": [\n" +
                                "      \"Bitte geben Sie einen OTP-Wert ein: \",\n" +
                                "      \"Please confirm the authentication on your mobile device!\"\n" +
                                "    ],\n" +
                                "    \"multi_challenge\": [\n" +
                                "      {\n" +
                                "        \"attributes\": null,\n" +
                                "        \"message\": \"Bitte geben Sie einen OTP-Wert ein: \",\n" +
                                "        \"serial\": \"OATH00020121\",\n" +
                                "        \"transaction_id\": \"02659936574063359702\",\n" +
                                "        \"type\": \"hotp\"\n" +
                                "      },\n" +
                                "      {\n" +
                                "        \"attributes\": null,\n" +
                                "        \"message\": \"Please confirm the authentication on your mobile device!\",\n" +
                                "        \"serial\": \"PIPU0001F75E\",\n" +
                                "        \"transaction_id\": \"02659936574063359702\",\n" +
                                "        \"type\": \"push\"\n" +
                                "      },\n" +
                                "      {\n" +
                                "        \"attributes\": {\n" +
                                "          \"hideResponseInput\": true,\n" +
                                "          \"img\": \"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
                                "          \"webAuthnSignRequest\": " + webAuthnSignRequest1 +
                                "        },\n" +
                                "        \"message\": \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)\",\n" +
                                "        \"serial\": \"WAN00025CE7\",\n" +
                                "        \"transaction_id\": \"16786665691788289392\",\n" +
                                "        \"type\": \"webauthn\"\n" +
                                "      },\n" +
                                "      {\n" +
                                "        \"attributes\": {\n" +
                                "          \"hideResponseInput\": true,\n" +
                                "          \"img\": \"static/img/FIDO-U2F-Security-Key-444x444.png\",\n" +
                                "          \"webAuthnSignRequest\": " + webAuthnSignRequest2 +
                                "        },\n" +
                                "        \"message\": \"Please confirm with your WebAuthn token (Yubico U2F EE Serial 6173234565)\",\n" +
                                "        \"serial\": \"WAN0002TER\",\n" +
                                "        \"transaction_id\": \"16786665691788289392\",\n" +
                                "        \"type\": \"webauthn\"\n" +
                                "      }\n" +
                                "    ],\n" +
                                "    \"serial\": \"PIPU0001F75E\",\n" +
                                "    \"threadid\": 140040525666048,\n" +
                                "    \"transaction_id\": \"02659936574063359702\",\n" +
                                "    \"transaction_ids\": [\n" +
                                "      \"02659936574063359702\",\n" +
                                "      \"02659936574063359702\"\n" +
                                "    ],\n" +
                                "    \"type\": \"push\"\n" +
                                "  },\n" +
                                "  \"id\": 1,\n" +
                                "  \"jsonrpc\": \"2.0\",\n" +
                                "  \"result\": {\n" +
                                "    \"status\": true,\n" +
                                "    \"value\": false\n" +
                                "  },\n" +
                                "  \"time\": 1589360175.594304,\n" +
                                "  \"version\": \"privacyIDEA 3.2.1\",\n" +
                                "  \"versionnumber\": \"3.2.1\",\n" +
                                "  \"signature\": \"rsa_sha256_pss:AAAAAAAAAA\"\n" +
                                "}"));

            privacyIDEA.SetServiceAccount("admin", "admin");

            var resp = privacyIDEA.TriggerChallenges("test");

            Assert.IsNotNull(resp);
            Assert.AreEqual(false, resp.Value);
            Assert.AreEqual(true, resp.Status);
            Assert.AreEqual("02659936574063359702", resp.TransactionID);
            Assert.AreEqual("Bitte geben Sie einen OTP-Wert ein: , Please confirm the authentication on your mobile device!", resp.Message);

            Assert.IsTrue(resp.TriggeredTokenTypes().Contains("push"));
            Assert.IsTrue(resp.TriggeredTokenTypes().Contains("hotp"));
            Assert.IsTrue(resp.TriggeredTokenTypes().Contains("webauthn"));

            var c1 = resp.Challenges.Find(item => item.Type == "push");
            Assert.AreEqual("PIPU0001F75E", c1.Serial);
            Assert.AreEqual("Please confirm the authentication on your mobile device!", c1.Message);
            Assert.AreEqual(c1.Attributes.Count, 0);

            var c2 = resp.Challenges.Find(item => item.Type == "hotp");
            Assert.AreEqual("OATH00020121", c2.Serial);
            Assert.AreEqual("Bitte geben Sie einen OTP-Wert ein: ", c2.Message);
            Assert.AreEqual(c2.Attributes.Count, 0);

            var c3 = resp.Challenges.Find(item => item.Type == "webauthn");
            Assert.AreEqual("WAN00025CE7", c3.Serial);
            Assert.AreEqual("Please confirm with your WebAuthn token (Yubico U2F EE Serial 61730834)", c3.Message);
            var signRequest = resp.MergedSignRequest();
            Assert.IsFalse(string.IsNullOrEmpty(signRequest));
            Assert.AreEqual(RemoveWhitespace(mergedSignRequests), RemoveWhitespace(signRequest));
        }

        public static string RemoveWhitespace(string str)
        {
            return string.Join("", str.Split(default(string[]), StringSplitOptions.RemoveEmptyEntries));
        }
    }
}
