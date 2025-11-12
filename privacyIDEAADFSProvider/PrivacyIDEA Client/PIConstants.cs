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

        // ADAPTER
        public const string NOT_USED = "not used";
        public const string AUTH_SUCCESS = "authSuccess";
        public const string USERID = "userid";
        public const string DOMAIN = "domain";
        public const string FORM_RESULT = "formResult";
        public const string PUSH_AVAILABLE = "pushAvailable";
        public const string TRANSACTIONID = "transactionid";
        public const string CLIENT = "client";
        public const string CLIENT_USER_AGENT = "client_user_agent";
        public const string X_FORWARDED_FOR = "X-Forwarded-For";
        public const string UNKNOWN = "unknown";
        public const string PRIVACYIDEA_ADFS_USERAGENT = "PrivacyIDEA-ADFS/";
        public const string DATE_FORMAT = "yyyy-MM-ddTHH\\:mm\\:ss;";
        public const string EVENT_LOG_ADFS_ADMIN = "AD FS/Admin";
        public const string EVENT_LOG_SOURCE = "privacyIDEAProvider";
        public const string STREAM_WRITER_LOG = "C:\\PrivacyIDEA-ADFS log.txt";
        public const string MS_SCHEMA_CLAIM_AUTHENTICATIONMETHOD = "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod";
        public const string MS_SCHEMA_AUTHMETHOD_OTP = "http://schemas.microsoft.com/ws/2012/12/authmethod/otp";

        // FORM
        public const string ENROLLMENT_IMG = "enrollmentImg";
        public const string ENROLLMENT_LINK = "enrollmentLink";
        public const string DISABLE_OTP = "disableOTP";
        public const string AUTH_COUNTER = "authCounter";
        public const string PREVIOUS_RESPONSE = "previousResponse";

        // PASSKEY
        public const string PASSKEY_REGISTRATION_SERIAL = "passkey_registration_serial";

        // TOKEN'S TRANSACTION ID
        public const string PUSH_TRANSACTION_ID = "push_transaction_id";
        public const string WEBAUTHN_TRANSACTION_ID = "webauthn_transaction_id";
        public const string PASSKEY_TRANSACTION_ID = "passkey_transaction_id";
        public const string OTP_TRANSACTION_ID = "otp_transaction_id";

        // MODE
        public const string MODE = "mode";
        public const string PUSH_MODE = "push";
        public const string OTP_MODE = "otp";
        public const string WEBAUTHN_MODE = "webauthn";
        public const string PASSKEY_MODE = "passkey";
    }
}
