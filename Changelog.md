## 2026-11-11 v1.5.0

### Features
* "Remember this device" login. The provider can now offer a checkbox that stores a persistent cookie after a successful login, so the second factor is skipped on the next login from that browser. It has three required gates: the plugin switch `enable_remember_device=1`, an API key (the new encrypted `api_key` setting), and a privacyIDEA server that offers the feature (a `remember_device` policy, scope `auth`); it also needs `https`. The cookie is a rotating token (a replayed value is treated as theft and revokes the user's devices) and is `Secure` + `SameSite=Strict`; it is not `HttpOnly`, because an AD FS adapter cannot set a response header and the page sets the cookie with JavaScript. Offered for one-time-password and push logins; WebAuthn and passkey do not issue it.
* One-time-password login now works without JavaScript. The login page built the hidden `formResult` field with JavaScript, so a client that does not run it — a legacy embedded WebView such as Outlook's (#90), or a passive federation flow like device registration / Windows Hello for Business provisioning (`urn:ms-drs`, #77) — could not submit. An empty or missing `formResult` is now treated as a plain OTP submit: the user types the one-time password and selects Submit, and the server validates it. This replaces the earlier behavior, where that case returned a retryable error form (v1.4.1).
* Push login works without JavaScript through a manual "I confirmed on my device" button. With JavaScript the page polls on a timer; without it, each button press re-posts the form and polls the transaction once. The button is shown only in push mode when JavaScript is disabled.
* Switching between one-time password and push works without JavaScript. When both are offered, the page shows a "Use push" or "Use one-time password" button that re-renders the form in the other mode. A no-JavaScript client can now reach push whenever a push token is triggered, not only when the server sets `preferred_client_mode=poll`.
* The login page hides the options that only work with JavaScript (WebAuthn, passkey, and the buttons that switch to them, plus copy-to-clipboard) when JavaScript is disabled, and reveals the enrollment QR code, so a no-JavaScript client sees a clean form. WebAuthn and passkey still require JavaScript and a browser that supports them.

### Other changes
* The one-time-password input now uses `autocomplete="one-time-code"` instead of `new-password`. Browsers and password managers no longer offer to save the one-time password as a credential.

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
