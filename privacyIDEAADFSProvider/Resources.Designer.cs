﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated by a tool.
//     Runtime Version:4.0.30319.42000
//
//     Changes to this file may cause incorrect behavior and will be lost if
//     the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace PrivacyIDEAADFSProvider {
    using System;
    
    
    /// <summary>
    ///   A strongly-typed resource class, for looking up localized strings, etc.
    /// </summary>
    // This class was auto-generated by the StronglyTypedResourceBuilder
    // class via a tool like ResGen or Visual Studio.
    // To add or remove a member, edit your .ResX file then rerun ResGen
    // with the /str option, or rebuild your VS project.
    [global::System.CodeDom.Compiler.GeneratedCodeAttribute("System.Resources.Tools.StronglyTypedResourceBuilder", "17.0.0.0")]
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute()]
    [global::System.Runtime.CompilerServices.CompilerGeneratedAttribute()]
    internal class Resources {
        
        private static global::System.Resources.ResourceManager resourceMan;
        
        private static global::System.Globalization.CultureInfo resourceCulture;
        
        [global::System.Diagnostics.CodeAnalysis.SuppressMessageAttribute("Microsoft.Performance", "CA1811:AvoidUncalledPrivateCode")]
        internal Resources() {
        }
        
        /// <summary>
        ///   Returns the cached ResourceManager instance used by this class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Resources.ResourceManager ResourceManager {
            get {
                if (object.ReferenceEquals(resourceMan, null)) {
                    global::System.Resources.ResourceManager temp = new global::System.Resources.ResourceManager("PrivacyIDEAADFSProvider.Resources", typeof(Resources).Assembly);
                    resourceMan = temp;
                }
                return resourceMan;
            }
        }
        
        /// <summary>
        ///   Overrides the current thread's CurrentUICulture property for all
        ///   resource lookups using this strongly typed resource class.
        /// </summary>
        [global::System.ComponentModel.EditorBrowsableAttribute(global::System.ComponentModel.EditorBrowsableState.Advanced)]
        internal static global::System.Globalization.CultureInfo Culture {
            get {
                return resourceCulture;
            }
            set {
                resourceCulture = value;
            }
        }
        
        /// <summary>
        ///   Looks up a localized string similar to &lt;div id=&quot;loginArea&quot;&gt;
        ///    &lt;!--Enrollment Message--&gt;
        ///    &lt;div id=&quot;enrollmentBlock&quot;&gt;
        ///        #ENROLLMENT#
        ///    &lt;/div&gt;
        ///    &lt;form method=&quot;post&quot; id=&quot;loginForm&quot;&gt;
        ///        &lt;!-- These inputs are required by the presentation framework. Do not modify or remove --&gt;
        ///        &lt;input id=&quot;authMethod&quot; type=&quot;hidden&quot; name=&quot;AuthMethod&quot; value=&quot;%AuthMethod%&quot; /&gt;
        ///        &lt;input id=&quot;context&quot; type=&quot;hidden&quot; name=&quot;Context&quot; value=&quot;%Context%&quot; /&gt;
        ///        &lt;!-- End inputs are required by the presentation framework. --&gt;
        ///
        ///
        ///        &lt; [rest of string was truncated]&quot;;.
        /// </summary>
        internal static string AuthPage {
            get {
                return ResourceManager.GetString("AuthPage", resourceCulture);
            }
        }
    }
}
