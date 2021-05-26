using Microsoft.IdentityServer.Web.Authentication.External;
using System.Diagnostics;

namespace privacyIDEAADFSProvider
{
    class AdapterPresentationForm : IAdapterPresentationForm
    {
        //public UITranslation[] translations;
        public string ErrorMessage { get; set; } = "";
        public string Message { get; set; } = "";
        public string PushMessage { get; set; } = "";
        public string PushAvailable { get; set; } = "0";
        public string Mode { get; set; } = "otp";
        public string AutoSubmit { get; set; } = "0";
        public string WebAuthnSignRequest { get; set; } = "";
        public string OtpAvailable { get; set; } = "1";
        public string AuthCounter { get; set; } = "0";

        public AdapterPresentationForm(/*UITranslation[] translations*/)
        {
            //this.translations = translations;
        }

        /// Returns the HTML Form fragment that contains the adapter user interface. This data will be included in the web page that is presented
        /// to the client.
        public string GetFormHtml(int lcid)
        {
            string otptext = "One-Time-Password";
            string submittext = "Submit";
            string htmlTemplate = Resources.AuthPage;
            /*
            if (translations != null)
            {
                foreach (UITranslation translation in translations)
                {
                    Debug.WriteLine("ID3A_ADFSadapter: Detected language LCID:" + lcid);

                    if ((int)translation.LCID == (int)lcid)
                    {
                        if (!string.IsNullOrEmpty(translation.errormessage)) errormessage = translation.errormessage;
                        if (!string.IsNullOrEmpty(translation.otptext)) otptext = translation.otptext;
                        if (!string.IsNullOrEmpty(translation.submittext)) submittext = translation.submittext;
                        break;
                    }
                }
            }
            */
            htmlTemplate = htmlTemplate.Replace("#ERROR#", !string.IsNullOrEmpty(this.ErrorMessage) ? this.ErrorMessage : "");
            htmlTemplate = htmlTemplate.Replace("#OTPTEXT#", otptext);
            htmlTemplate = htmlTemplate.Replace("#SUBMIT#", submittext);
            htmlTemplate = htmlTemplate.Replace("#MESSAGE#", Message);
            htmlTemplate = htmlTemplate.Replace("#authCounter#", AuthCounter);
            htmlTemplate = htmlTemplate.Replace("#mode#", Mode);
            htmlTemplate = htmlTemplate.Replace("#pushAvailable#", PushAvailable);
            htmlTemplate = htmlTemplate.Replace("#otpAvailable#", OtpAvailable);
            htmlTemplate = htmlTemplate.Replace("#webAuthnSignRequest#", WebAuthnSignRequest);
            htmlTemplate = htmlTemplate.Replace("#pushMessage#", PushMessage);
            htmlTemplate = htmlTemplate.Replace("#modeChanged#", "0");
            htmlTemplate = htmlTemplate.Replace("#pollInterval#", "1");
            htmlTemplate = htmlTemplate.Replace("#autoSubmit#", AutoSubmit);

            return htmlTemplate;
        }

        /// Return any external resources, ie references to libraries etc., that should be included in 
        /// the HEAD section of the presentation form html. 
        public string GetFormPreRenderHtml(int lcid)
        {
            return null;
        }

        //returns the title string for the web page which presents the HTML form content to the end user
        public string GetPageTitle(int lcid)
        {
            return "privacyIDEA AD FS";
        }

    }
}
