namespace PrivacyIDEAADFSProvider.PrivacyIDEA_Client
{
    internal class PIConstants
    {
        // ENDPOINTS
        public const string AUTH_ENDPOINT = "/auth";
        public const string POLLTRANSACTION_ENDPOINT = "/validate/polltransaction";
        public const string TRIGGERCHALLENGE_ENDPOINT = "/validate/triggerchallenge";
        public const string VALIDATE_INITIALIZE_ENDPOINT = "/validate/initialize";
        public const string TOKEN_ENDPOINT = "/token/";
        public const string TOKEN_INIT_ENDPOINT = "/token/init";
        public const string VALIDATE_CHECK_ENDPOINT = "/validate/check";
        public const string POST = "POST";
        public const string GET = "GET";

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
        public const string CANCEL_ENROLLMENT = "cancel_enrollment";

        // REQUEST PARAMETERS
        public const string REALM = "realm";
        public const string TOKEN_TYPE = "token_type";
        public const string USERNAME = "username";
        public const string PASS = "pass";
        public const string OTP = "otp";
        public const string USER = "user";
        public const string GENKEY = "genkey";
        public const string TOTP = "totp";
        public const string ORIGIN = "Origin";
        public const string PASSWORD = "password";
        public const string USER_AGENT = "User-Agent";

        // TOKEN TYPES
        public const string TOKEN_TYPE_OTP = "otp";
        public const string TOKEN_TYPE_PUSH = "push";
        public const string TOKEN_TYPE_PASSKEY = "passkey";
        public const string TOKEN_TYPE_WEBAUTHN = "webauthn";

        // FIDO2 PARAMETERS
        public const string CREDENTIALID = "credentialId";
        public const string CREDENTIAL_ID = "credential_id";
        public const string CLIENTDATA = "clientdata";
        public const string CLIENTDATAJSON = "clientdatajson";
        public const string CLIENTDATAJSON_CAM = "clientDataJSON";
        public const string SIGNATUREDATA = "signaturedata";
        public const string SIGNATURE = "signature";
        public const string AUTHENTICATORDATA = "authenticatordata";
        public const string AUTHENTICATORDATA_CAM = "authenticatorData";
        public const string USERHANDLE = "userhandle";
        public const string USERHANDLE_CAM = "userHandle";
        public const string RAW_ID = "raw_id";
        public const string RAWID = "rawid";
        public const string RAWID_CAM = "rawId";
        public const string ASSERTIONCLIENTEXTENSIONS = "assertionclientextensions";
        public const string AUTHENTICATORATTACHMENT = "authenticatorattachment";
        public const string AUTHENTICATORATTACHMENT_CAM = "authenticatorAttachment";
        public const string ATTESTATIONOBJECT = "attestationobject";
        public const string ATTESTATIONOBJECT_CAM = "attestationObject";

        public const string MEDIA_TYPE_URLENCODED = "application/x-www-form-urlencoded";
    }
}
