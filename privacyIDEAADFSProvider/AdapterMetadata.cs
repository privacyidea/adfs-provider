using System.Collections.Generic;
using System.Linq;
using Microsoft.IdentityServer.Web.Authentication.External;

namespace privacyIDEAADFSProvider
{
    class AdapterMetadata : IAuthenticationAdapterMetadata
    {
        public string AdapterVersion { get; set; }

        private static readonly int[] s_lcids =
        {
            // German
            1031,   // de-DE
            3079,   // de-AT
            2055,   // de-CH
            5127,   // de-LI
            4103,   // de-LU
            // English
            1033,   // en-US
            2057,   // en-GB
            3081,   // en-AU
            4105,   // en-CA
            6153,   // en-IE
            5129,   // en-NZ
            7177,   // en-ZA
            16393   // en-IN
        };

        private static readonly string[] s_authenticationMethods =
        {
            "http://schemas.microsoft.com/ws/2012/12/authmethod/otp",
            "http://schemas.microsoft.com/ws/2012/12/authmethod/privacyidea"
        };

        private static readonly Dictionary<int, string> s_friendlyNames =
            s_lcids.ToDictionary(i => i, _ => "privacyIDEA AD FS Provider");

        private static readonly Dictionary<int, string> s_descriptions =
            s_lcids.ToDictionary(i => i, _ => "AD FS Provider to authenticate with privacyIDEA.");

        private static readonly string[] s_identityClaims =
        {
            "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"
        };

        /// Returns the name of the provider that will be shown in the AD FS management UI (not visible to end users)
        public string AdminName => "privacyIDEA-ADFSProvider_" + AdapterVersion;

        /// Returns an array of strings containing URIs indicating the set of authentication methods implemented by the adapter
        /// AD FS requires that, if authentication is successful, the method actually employed will be returned by the
        /// final call to TryEndAuthentication(). If no authentication method is returned, or the method returned is not
        /// one of the methods listed in this property, the authentication attempt will fail.
        public virtual string[] AuthenticationMethods => s_authenticationMethods;

        /// Returns an array indicating which languages are supported by the provider. AD FS uses this information
        /// to determine the best language\locale to display to the user.
        public int[] AvailableLcids => s_lcids;

        /// Returns a Dictionary containing the set of localized friendly names of the provider, indexed by lcid.
        /// These Friendly Names are displayed in the "choice page" offered to the user when there is more than
        /// one secondary authentication provider available.
        public Dictionary<int, string> FriendlyNames => s_friendlyNames;

        /// Returns a Dictionary containing the set of localized descriptions (hover over help) of the provider, indexed by lcid.
        /// These descriptions are displayed in the "choice page" offered to the user when there is more than one
        /// secondary authentication provider available.
        public Dictionary<int, string> Descriptions => s_descriptions;

        /// Returns an array indicating the type of claim that the adapter uses to identify the user being authenticated.
        /// Note that although the property is an array, only the first element is currently used.
        /// MUST BE ONE OF THE FOLLOWING
        /// "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"
        /// "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
        /// "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
        /// "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid"
        public string[] IdentityClaims => s_identityClaims;

        public bool RequiresIdentity => true;
    }
}
