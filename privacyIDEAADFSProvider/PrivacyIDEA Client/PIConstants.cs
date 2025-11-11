using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrivacyIDEAADFSProvider.PrivacyIDEA_Client
{
    internal class PIConstants
    {
        public const string USER_AGENT = "User-Agent";

        // SERVER RESPONSE
        public const string RESULT = "result";
        public const string STATUS = "status";
        public const string ERROR = "error";
        public const string CODE = "code";
        public const string MESSAGE = "message";
        public const string DETAIL = "detail";
        public const string VALUE = "value";
        public const string CHALLENGE = "challenge";
        public const string SERIAL = "serial";
        public const string TYPE = "type";
        public const string TRANSACTION_ID = "transaction_id";
        public const string IMAGE = "image";
        public const string CLIENT_MODE = "client_mode";
        public const string ATTRIBUTES = "attributes";
        public const string GOOGLEURL = "googleurl";
        public const string ALLOW_CREDENTIALS = "allowCredentials";
        public const string AUTHENTICATION = "authentication";
        public const string PREFERRED_CLIENT_MODE = "preferred_client_mode";
        public const string INTERACTIVE = "interactive";
        public const string POLL = "poll";
        public const string PASSKEY = "passkey";
        public const string PASSKEY_CHALLENGE = "passkey_challenge";
        public const string MULTI_CHALLENGE = "multi_challenge";
        public const string PASSKEY_REGISTRATION = "passkey_registration";
        public const string LINK = "link";
        public const string WEBAUTHNSIGNREQUEST = "webAuthnSignRequest";

        // REQUEST PARAMETERS
        public const string REALM = "realm";
        public const string TOKEN_TYPE = "token_type";
        public const string USERNAME = "username";
        public const string PASS = "pass";
        public const string OTP = "otp";

        // TOKEN TYPES
        public const string TOKEN_TYPE_OTP = "otp";
        public const string TOKEN_TYPE_PUSH = "push";
        public const string TOKEN_TYPE_PASSKEY = "passkey";
        public const string TOKEN_TYPE_WEBAUTHN = "webauthn";
    }
}
