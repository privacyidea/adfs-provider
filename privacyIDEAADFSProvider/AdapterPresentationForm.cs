﻿using Microsoft.IdentityServer.Web.Authentication.External;
using PrivacyIDEASDK;
using System.Collections.Generic;

namespace privacyIDEAADFSProvider
{
    class AdapterPresentationForm : IAdapterPresentationForm
    {
        public string ErrorMessage { get; set; } = "";
        public string OtpHint { get; set; } = "";
        public string Message { get; set; } = "";
        public string PushMessage { get; set; } = "";
        public string PushAvailable { get; set; } = "0";
        public string Mode { get; set; } = "otp";
        public string AutoSubmit { get; set; } = "0";
        public string WebAuthnSignRequest { get; set; } = "";
        public string OtpAvailable { get; set; } = "1";
        public string AuthCounter { get; set; } = "0";
        public string EnrollmentText { get; set; } = @"
                <p style=""color:red""><i>It appears your account has not previously setup Multi-Factor Authentication (MFA). <b>Please carefully follow the below instructions - they will only be shown once!</b></i><p>
                <br/>                
                <ol>
                    <li>
                      Download and/or install a TOTP compliant MFA app or Password Manager if you haven't already. Here are some recommendations:
                      <ul>
                         #ENROLLAPPS#
                      </ul>
                    </li>
                    <li> 
                      Scan the following QR code or copy the text below into your MFA app of choice
                         <img id=""enrollmentImg"" src=""#ENROLLIMG#"" width=""325px"" alt>
                         <input id = ""enrollmentValue"" value=""#ENROLLVAL#"" class=""text"" size=""30"" readonly/>
                         <button onclick=""copyTOTP()"" style=""background-color: #4CAF50; border: none; color: white; padding: 8px 10px; text-align: center; text-decoration: none; display: inline-block;"">Copy text</button>
                    </li>
                    <li>Please paste the the code generated by your application into the box below.</li>
                 </ol>";
        public string EnrollmentUrl { get; set; } = "";
        public string EnrollmentImg { get; set; } = "";
        public List<string> EnrollmentApps { get; set; } = new List<string>() {
            "privacyIDEA Authenticator <a target=\"_blank\" href=\"https://play.google.com/store/apps/details?id=it.netknights.piauthenticator&hl=en_US&gl=US\">(Android)</a> <a target=\"_blank\" href=\"https://apps.apple.com/us/app/privacyidea-authenticator/id1445401301\">(iOS)</a>",
            "Google Authenticator <a target=\"_blank\" href=\"https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=en_US&gl=US\">(Android)</a> <a target=\"_blank\" href=\"https://apps.apple.com/us/app/google-authenticator/id388497605\">(iOS)</a>",
            "Authy <a target=\"_blank\" href=\"https://authy.com/download/\">(Mobile/Desktop)</a>"
        };

        public AdapterPresentationForm()
        {
        }

        /// Returns the HTML Form fragment that contains the adapter user interface. This data will be included in the web page that is presented
        /// to the client.
        public string GetFormHtml(int lcid)
        {
            string otptext = "One-Time-Password";
            if (!string.IsNullOrEmpty(OtpHint))
            {
                otptext = OtpHint;
            }
            string submittext = "Submit";
            string htmlTemplate = Resources.AuthPage;

            if(!(string.IsNullOrEmpty(EnrollmentImg) || string.IsNullOrEmpty(EnrollmentUrl)))
            {
                htmlTemplate = htmlTemplate.Replace("#ENROLLMENT#", EnrollmentText);

                // Enumerate EnrollmentApps
                string enrollappstxt = "";
                foreach (var app in EnrollmentApps)
                {
                    enrollappstxt += "<li>" + app + "</li>";
                }

                htmlTemplate = htmlTemplate.Replace("#ENROLLAPPS#", enrollappstxt);
                htmlTemplate = htmlTemplate.Replace("#ENROLLVAL#", EnrollmentUrl);
                htmlTemplate = htmlTemplate.Replace("#ENROLLIMG#", EnrollmentImg);
            }
            else
            {
                htmlTemplate = htmlTemplate.Replace("#ENROLLMENT#", "");
            }

            htmlTemplate = htmlTemplate.Replace("#ERROR#", !string.IsNullOrEmpty(this.ErrorMessage) ? this.ErrorMessage : "");
            htmlTemplate = htmlTemplate.Replace("#OTPTEXT#", otptext);
            htmlTemplate = htmlTemplate.Replace("#SUBMIT#", submittext);
            htmlTemplate = htmlTemplate.Replace("#MESSAGE#", Message);
            htmlTemplate = htmlTemplate.Replace("#authCounter#", AuthCounter);
            htmlTemplate = htmlTemplate.Replace("#mode#", Mode);
            htmlTemplate = htmlTemplate.Replace("#pushAvailable#", PushAvailable);
            htmlTemplate = htmlTemplate.Replace("#otpAvailable#", OtpAvailable);
            // Replace the quotes of the WebAuthnSignRequest json string with the entity name for html
            htmlTemplate = htmlTemplate.Replace("#webAuthnSignRequest#", WebAuthnSignRequest.Replace("\"", "&quot;"));
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
