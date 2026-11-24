## 2026-11-11 v1.5.0

### Features
* "Remember this device" login. The provider can now offer a checkbox that stores a persistent cookie after a successful login, so the second factor is skipped on the next login from that browser. It has three required gates: the plugin switch `enable_remember_device=1`, an API key (the new encrypted `api_key` setting), and a privacyIDEA server that offers the feature (a `remember_device` policy, scope `auth`); it also needs `https`. The cookie is a rotating token (a replayed value is treated as theft and revokes the user's devices) and is `Secure` + `SameSite=Lax`. It is not `Strict`, because a `Strict` cookie is not sent in sign-ins that start on another site, such as a redirect from Microsoft 365 with Windows Integrated Authentication, so the device would never be recognized there; the README explains the trade-off. It is not `HttpOnly`, because an AD FS adapter cannot set a response header and the page sets the cookie with JavaScript. It works for one-time-password, push, WebAuthn and passkey logins, and for a passkey registration.
* The login page works in Internet Explorer 11 and in the legacy Edge engine (EdgeHTML 18), which older Office sign-in windows embed. The page script is now plain ES5 and checks for newer browser functions before it uses them. Before, these engines rejected the whole script: the page showed every login option, push did not poll, and a remembered device did not sign in. Internet Explorer 11 has no WebAuthn, so the page hides the security key and passkey options there. If the page script cannot run at all, the page falls back to the no-JavaScript form.
* One-time-password login now works without JavaScript. The login page built the hidden `formResult` field with JavaScript, so a client that does not run it — a legacy embedded WebView such as Outlook's (#90), or a passive federation flow like device registration / Windows Hello for Business provisioning (`urn:ms-drs`, #77) — could not submit. An empty or missing `formResult` is now treated as a plain OTP submit: the user types the one-time password and selects Submit, and the server validates it. This replaces the earlier behavior, where that case returned a retryable error form (v1.4.1).
* Push login works without JavaScript through a manual "I confirmed on my device" button. With JavaScript the page polls on a timer; without it, each button press re-posts the form and polls the transaction once. The button is shown only in push mode when JavaScript is disabled.
* Switching between one-time password and push works without JavaScript. When both are offered, the page shows a "Use push" or "Use one-time password" button that re-renders the form in the other mode. A no-JavaScript client can now reach push whenever a push token is triggered, not only when the server sets `preferred_client_mode=poll`.
* The login page hides the options that only work with JavaScript (WebAuthn, passkey, and the buttons that switch to them, plus copy-to-clipboard) when JavaScript is disabled, and reveals the enrollment QR code, so a no-JavaScript client sees a clean form. WebAuthn and passkey still require JavaScript and a browser that supports them.
* The login page is available in German and French. Before, the provider declared German and French to AD FS, but every text of the page was English. AD FS chooses the language from the browser. Every other language gets English. The page title and the description on the AD FS choice page are translated too.
* Push login is easier to use with a keyboard, speech input or a screen reader. The page checks every `push_poll_interval` seconds (new setting, default 3). Before, it reloaded after 3, 2 and 2 seconds and then every second. After each check, the focus goes back to the control that had it. The user can stop the automatic check and confirm with the "I confirmed on my device" button. The page also stops by itself after 5 minutes.
* A push that the user declines or cancels on the device ends the push check with a message. Before, the page kept saying "Authentication not confirmed yet!" until the challenge expired. This needs privacyIDEA 3.10 or later (3.14 for a cancelled push).

### Fixes
* The installer now checks for .NET Framework 4.8 before it installs any file. The provider targets 4.8, which is in-box on Windows Server 2022 and later, but not on Server 2016 or 2019. On a machine without it, the installer stops up front with a message and a download link, instead of installing a provider that AD FS cannot load. A manual run of `Install.ps1` already made this check (#110).
* `Install.ps1` replaces a registration of another provider version. AD FS ties a registration to one assembly version, and before, `Install.ps1` skipped registration whenever the name existed, so after a manual DLL update AD FS kept loading the old version. The provider stays in the authentication policy lists it was in.
* An MSI upgrade keeps the provider enabled. The old version's uninstall records the global authentication policy lists that contain the provider, and the new version's install puts it back into them. This works for upgrades from 1.5.0 on (see the upgrade note below).
* The uninstall stops with an error, before it removes anything, when AD FS refuses to unregister the provider. Before, it removed the assembly anyway, which could leave AD FS registered to a missing assembly and break every sign-in that uses the provider.
* The MSI runs `Install.ps1` and `Uninstall.ps1` in 64-bit PowerShell. Before, it ran them in 32-bit PowerShell, which reads the 32-bit registry view and did not find the configuration key. So an MSI installation never hardened the access control list of the configuration key (added in 1.4.0). The hardening only worked when you ran `Install.ps1` by hand.
* An install or upgrade keeps the `forward_headers`, `tls_version` and `service_realm` settings. The installer has no fields for them, and before, it wrote them with an empty value on every install and upgrade.
* A newer build of the same version replaces the installed build. Before, the MSI installed it as a second entry in Programs and Features, kept the old DLL (Windows Installer does not overwrite a file of an equal version), and AD FS kept running the old code. If you later removed one of the two entries, its uninstall unregistered the provider while the other entry stayed listed.

### Upgrade notes
* **Upgrading from 1.4.x or older:** the old version's uninstaller takes the provider out of the AD FS global authentication policy and does not record it. After the upgrade, enable the provider again as an additional authentication method (AD FS Management > Authentication Methods, or `Set-AdfsGlobalAuthenticationPolicy -AdditionalAuthenticationProvider`). Upgrades from 1.5.0 on keep it enabled.
* **Access control list of the configuration key:** the 1.5.0 MSI hardens it (see Fixes). After the installation, only `SYSTEM`, `Administrators` and the AD FS service account can read the key. If another tool or account reads the key, give it read access again. If `Install.ps1` cannot find or resolve the AD FS service account, it does not change the access control list and writes a warning.

### Other changes
* The one-time-password input now uses `autocomplete="one-time-code"` instead of `new-password`. Browsers and password managers no longer offer to save the one-time password as a credential.
* Accessibility of the login page (WCAG 2.2):
  * The one-time-password field has a visible label also when the server sends no challenge message, which is the default configuration. Before, it had only a placeholder, which disappears while the user types.
  * The buttons "OTP" and "Not Now" had an `aria-label` with other words ("Use One-Time-Password", "Skip enrollment"). A speech-input user who said the visible text did not reach them. The buttons now have no `aria-label`, and "Other Login Options" is the name of their group.
  * A failed or cancelled WebAuthn or passkey prompt shows a message. Before, the page only wrote to the browser console.
  * The buttons use the blue of the AD FS default theme (`#0067b8`) and a darker gray, and error texts use the theme's `error` class. The old colors had a contrast below 4.5:1 with white text.
  * The page title names the task ("Verify your identity") instead of the product.

## 2026-07-21 v1.4.1

### Fixes
* Fixed a `NullReferenceException` in `TryEndAuthentication` that surfaced as "An error occurred during a passive federation request." when the login form was posted without the page JavaScript having populated the hidden `formResult` field (observed with the device-registration/OAuth relying party `urn:ms-drs`). An empty, whitespace, `"null"`, non-string, or malformed-JSON `formResult`, and a null authentication context, now degrade to a retryable error form instead of crashing (#78).

## 2026-07-02 v1.4.0

Support for privacyIDEA 3.13 features:
* push_code_to_phone
* enroll_via_multichallenge_optional
* enroll_via_multichallenge for smartphone containers

Secret handling:
* The `service_pass` is now encrypted at rest with Windows DPAPI. Existing plaintext values (and values typed directly into the registry) are migrated to encrypted storage automatically the first time the provider reads them, with a one-time warning written to the event log.
* The installer hardens the ACL on the configuration registry key so the `service_pass` is no longer readable by non-admin users on the machine.

Security hardening:
* New `forward_client_ip` and `forward_client_user_agent` settings forward the client IP (as the `client` parameter) and the client `User-Agent` header (as the `client_user_agent` parameter) to privacyIDEA for server-side policy decisions. When forwarding the client IP, set the new `trusted_proxies` setting to the IP(s)/CIDR(s) of your reverse proxy so a spoofed `X-Forwarded-For` from a client reaching AD FS directly cannot bypass IP-based policies.
* When SSL/TLS certificate validation is disabled (`disable_ssl=1`), the provider now writes a warning to the Windows Application event log on every service start, so this insecure state can be audited.
* Deprecated TLS versions requested via `tls_version` (`tls11` and older) are now rejected: the provider logs a warning and falls back to the system-default negotiation (TLS 1.2/1.3) instead of downgrading.

Other changes:
* Added more German-speaking LCIDs (de-AT, de-CH, de-LI, de-LU).
* Updated the event log location this application writes to. It now writes to the general Windows **Application** log with the source "privacyIDEAProvider" (if an earlier version registered the source under a different log, it is moved to Application automatically). The event source is removed on uninstall.
* The installer now checks for .NET Framework 4.8 and aborts with instructions if it is missing.
* The service password field in the installer is masked.
* The debug log location is now configurable via the `log_path` registry setting (defaults to the previous `C:\PrivacyIDEA-ADFS log.txt`).

## 2025-06-02 v1.3.0

**Use this version only with privacyIDEA 3.11 or higher**
* Passkey. Unfortunately, usernameless is not possible with AD FS, see the README for recommendations for the use of this plugin. Passkey login can be disabled with the disable_passkey=1 setting.
* Passkey enrollment via validate.
* Changed the parameter names when doing WebAuthn to be uniform with passkey. That is why privacyIDEA 3.11 is required for WebAuthn to work.
* Added auto_submit_otp_length setting to set a OTP digit count for which to automatically submit the form.
* Removed preferred_client_mode setting in favor of the policy in the privacyIDEA server. 

## 2023-03-27 v1.2.0

### Features
* Token enrollment via challenge-response
* Preferred client mode can be set from the server


## 2022-10-20 v1.1.1

### Enhancement
* Add German (de-de) and British English (en-gb) as supported languages.


## 2022-08-25 v1.1.0

### Features
* Option to enroll TOTP token if the user has none. This requires a service account to be set (#17)
* Option to forward selected headers (#24)
* Option to set the TLS version explicitly. By default the system version is used as advised by Microsoft (#23)
* Option to set a custom hint for the OTP input (#21)
* Option to set the preferred token type (if such token was triggered, see docs) (#32)

### Fixes
* If a user has multiple WebAuth token, all of them will be usable now (#29)


## 2021-07-20 v1.0.0

### Fixes
* Fixed an issue that would prevent multiple consecutive challenges from working


## 2021-07-06 v0.10.0

### Features
* WebAuthn
* Configurable Windows Domain to privacyIDEA realm mapping


## 2021-06-10 v0.9.0

### Features
* OTP Token like HOTP and TOTP
* Challenge-Response with Email and SMS
* Push Token
* MSI Installer
