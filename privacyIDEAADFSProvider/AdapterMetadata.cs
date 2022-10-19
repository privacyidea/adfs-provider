using System.Collections.Generic;
using Microsoft.IdentityServer.Web.Authentication.External;

namespace privacyIDEAADFSProvider
{
    class AdapterMetadata : IAuthenticationAdapterMetadata
    {
        public string AdapterVersion { get; set; }

        static readonly List<int> LCIDS = new List<int>
                {
                    1033,   // en-us
                    1031,   // de-de
                    2057    // en-gb
                };

        public void AdapterMetadataInit()
        {
        }

        /// Returns the name of the provider that will be shown in the AD FS management UI (not visible to end users)
        public string AdminName
        {
            get { return "privacyIDEA-ADFSProvider_" + AdapterVersion; }
        }

        /// Returns an array of strings containing URIs indicating the set of authentication methods implemented by the adapter 
        /// AD FS requires that, if authentication is successful, the method actually employed will be returned by the
        /// final call to TryEndAuthentication(). If no authentication method is returned, or the method returned is not
        /// one of the methods listed in this property, the authentication attempt will fail.
        public virtual string[] AuthenticationMethods
        {
            get { return new[] { "http://schemas.microsoft.com/ws/2012/12/authmethod/otp" }; }
        }

        /// Returns an array indicating which languages are supported by the provider. AD FS uses this information
        /// to determine the best language\locale to display to the user.
        public int[] AvailableLcids
        {
            get => LCIDS.ToArray();
        }

        /// Returns a Dictionary containing the set of localized friendly names of the provider, indexed by lcid. 
        /// These Friendly Names are displayed in the "choice page" offered to the user when there is more than 
        /// one secondary authentication provider available.
        public Dictionary<int, string> FriendlyNames
        {
            get
            {
                Dictionary<int, string> friendlyNames = new Dictionary<int, string>();
                // Friendly name is the same for any LCID
                foreach (int i in LCIDS)
                {
                    friendlyNames.Add(i, "privacyIDEA AD FS Provider");
                }

                return friendlyNames;
            }
        }

        /// Returns a Dictionary containing the set of localized descriptions (hover over help) of the provider, indexed by lcid. 
        /// These descriptions are displayed in the "choice page" offered to the user when there is more than one 
        /// secondary authentication provider available.
        public Dictionary<int, string> Descriptions
        {
            get
            {
                Dictionary<int, string> descriptions = new Dictionary<int, string>();
                foreach (int i in LCIDS)
                {
                    descriptions.Add(i, "AD FS Provider to authenticate with privacyIDEA.");
                }
                return descriptions;
            }
        }

        /// Returns an array indicating the type of claim that that the adapter uses to identify the user being authenticated.
        /// Note that although the property is an array, only the first element is currently used.
        /// MUST BE ONE OF THE FOLLOWING
        /// "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname"
        /// "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn"
        /// "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
        /// "http://schemas.microsoft.com/ws/2008/06/identity/claims/primarysid"
        public string[] IdentityClaims
        {
            get { return new[] { "http://schemas.microsoft.com/ws/2008/06/identity/claims/windowsaccountname" }; }
        }

        //All external providers must return a value of "true" for this property.
        public bool RequiresIdentity
        {
            get { return true; }
        }
    }
}
