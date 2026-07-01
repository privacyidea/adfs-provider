# Acknowledgement
This project builds on Stephan Traub's [original provider v1.3.8.2](https://github.com/sbidy/privacyIDEA-ADFSProvider/tree/f66100713e650d134ac50fcbd3965b71ae588d47). 

## Requirements
The [.NET Framework 4.8](https://dotnet.microsoft.com/download/dotnet-framework/net48) is required on the target machine. It is included in-box on Windows Server 2022 and newer, but **not** on Server 2016 (ships with 4.6.2) or Server 2019 (ships with 4.7.2) — installing the ADFS role does not add it. On those versions install .NET Framework 4.8 first (it is also commonly delivered via Windows Update). `Install.ps1` checks for it and aborts with instructions if it is missing.

## Configuration
Starting with v1.3.0, this provider *can* be used as primary authentication method in ADFS. However, ADFS will inject a form to request the username before this provider, even if it is configured as primary, which makes the experience of passkey usernameless authentication not great in ADFS.
You could then choose to add "Forms Authentication" as additional, to have the password checked in the last step. Alternatively, have only this provider as primary and none as additional, if you are sure that there has been a multifactor authentication with this provider. This would be the case if you use passkey or webauthn with user_verification=required, because the PIN/Biometrics is the second factor.


The provider is configured using the registry. The keys are located at `HKEY_LOCAL_MACHINE\SOFTWARE\NetKnights GmbH\PrivacyIDEA-ADFS`.
After changing the configuration, the AD FS Service has to be restarted for the changes to become active. This can be done using the PowerShell command `Restart-Service adfssrv`.

`Install.ps1` hardens the access control list on this key: by default `HKLM\SOFTWARE` grants the local *Users* group read access, which would let any non-admin on the machine read the `service_pass` in cleartext. After installation only `SYSTEM`, `Administrators`, and the AD FS service account can access the key. If you create the configuration key *after* running the installer, re-run `Install.ps1` so the ACL is applied.

The `service_pass` is additionally encrypted at rest using Windows DPAPI. You can enter it as plaintext (via the installer dialog or directly in the registry); the provider encrypts it in place the first time it reads it, replacing the value with an `enc:`-prefixed ciphertext. To change it later, simply enter a new plaintext value — it will be re-encrypted on the next read. This protects the password in registry exports and backups; it is *not* a boundary against a local administrator, who on an AD FS server already controls the token-signing key.

DPAPI encryption is bound to the machine, so an encrypted value cannot be decrypted on a different server (e.g. after a restore, clone, or migration). On a new machine — including each node of an AD FS farm — enter the password again and it will be re-encrypted locally. The provider logs an event if it finds an `enc:` value it cannot decrypt.

| Key Name | Explanation |
| ----- | ----- |
| url | The url of the privacyIDEA server. Has to include https://! |
| disable_ssl | Set to `1` if ssl verification should be disabled. DO NOT DISABLE THIS IN A PRODUCTION ENVIRONMENT! While active, the provider writes a warning to the Windows Application event log on every service start, since disabling certificate validation leaves the connection to privacyIDEA open to interception. |
| debug_log | Set to `1` if a detailed debug log should be written. By default it is located at `C:\PrivacyIDEA-ADFS log.txt`; use `log_path` to change the location. |
| log_path | The full path of the file the debug log is written to when `debug_log` is enabled. Defaults to `C:\PrivacyIDEA-ADFS log.txt`. Missing parent directories are created automatically on the first write, provided the AD FS service account has permission to create them. If the location still cannot be written (e.g. insufficient permissions or an invalid drive), the provider logs a single error to the Windows Application event log and keeps retrying on subsequent writes. |
| enable_enrollment | Set to `1` if users should automatically enroll a TOTP code if they do not have any other tokens enrolled. **!!! This feature is deprecated in favor of the new enrollment that can be controlled from the privacyIDEA server starting v3.8.0, and will be removed in a future version of this provider. !!!** |
| realm | Set the realm that should be appended to every request. If this is empty, the realm parameter will be omitted from requests. |
| service_user | Set the username of a privacyIDEA service account that can be used to trigger challenges. Configuring this is only required to use the `trigger_challenges` or `enable_enrollment` settings! |
| service_pass | Set the password of a privacyIDEA service account that can be used to trigger challenges. Configuring this is only required to use the `trigger_challenges` or `enable_enrollment` settings! |
| service_realm | Set the realm of a privacyIDEA service account that can be used to trigger challenges. This realm setting can be used if the service account is found in a different realm than the other one specified. |
| trigger_challenges | Set this to `1` to trigger challenges prior to the login using the configured service account. This setting takes precedence over `send_empty_pass`. |
| send_empty_pass | Set this to `1` to send a request to validate/check with the username and an empty pass prior to the login. This can be used to trigger challenges depending on the configuration in privacyIDEA and **requires no service account**. If `trigger_challenges` is enabled, this setting has no effect. |
| use_upn | Set this to `1` to use the Windows UPN (person@company.com) as the username for requests to privacyIDEA. |
| tls_version | If you want to pin the TLS version, set it to `tls12` or `tls13`. TLS 1.2 is the minimum; deprecated values (`tls11` and older) are rejected — the provider logs a warning to the event log and uses the system-default negotiation (TLS 1.2/1.3) instead. Other/unrecognized values are ignored and the TLS version stays at the system default. |
| forward_headers | If you want to forward specific headers to the privacyIDEA server, you can set them here. If the header does not exist or has no value, it will be ignored. The headers names should be separated with ','. |
| ~~preferred_token_type~~ | ~~Set the token type for which the UI should be first shown. This only matters if such token was triggered before. Possible values are `otp`, `push` or `webauthn`. The default is OTP mode.~~ **!!! This feature has been removed in v1.3.0 in favor of the preferred_client_mode policy in the privacyIDEA Server. !!!** |
| auto_submit_otp_length | Set an OTP digit count for which to automatically submit the form |
| disable_passkey | Disable the "Passkey Login" button |
| otp_hint | The hint that is shown in the input field. The default is 'One-Time-Password' |
| forward_client_ip | Set to `1` to forward the client IP to privacyIDEA (as the `client` parameter), so server-side policies can use it. See the security note below on `trusted_proxies`. |
| forward_client_user_agent | Set to `1` to forward the client's `User-Agent` header to privacyIDEA. |
| trusted_proxies | Comma-separated list of reverse-proxy IPs or CIDR ranges (e.g. `10.0.0.5, 192.168.10.0/24`) that are allowed to set `X-Forwarded-For`. When set, the forwarded client IP is only trusted if the request actually arrived from one of these proxies. **Strongly recommended whenever `forward_client_ip` is enabled** — see the note below. |

### Domain to Realm Mapping
It is possible to map different Windows domains to different privacyIDEA realms. To achieve this, add the subkey `HKLM\SOFTWARE\Netknights GmbH\PrivacyIDEA-ADFS\realm-mapping`. Now you can add REG_SZ entries that have the name of the Windows domain and the value of the corresponding privacyIDEA realm. Note that the realm mapping takes precedence over the general realm that can be configured as explained in the previous section.

### Forwarding the client IP (`X-Forwarded-For`) safely
`X-Forwarded-For` is set by the caller and can be forged. If privacyIDEA uses the client IP for policy decisions (geo-fencing, IP allow/deny lists, conditional MFA), a request that reaches AD FS directly could spoof this header and bypass those policies. To prevent that, set `trusted_proxies` to the IP(s)/CIDR(s) of your reverse proxy: the forwarded IP is then only trusted when the request actually originates from a listed proxy, and the real connection IP is used otherwise.

If `trusted_proxies` is left empty, the provider keeps the previous behavior of trusting `X-Forwarded-For` unconditionally — this is kept for backward compatibility but is **not recommended** when IP-based policies are in use.

## Signing and verifying the installer
The dll that is created by this solution requires to be strong-name signed to be deployed. Change the key file to your own in the project settings of the provider.

Officially distributed installer packages are additionally Authenticode code-signed. Before deploying a release, verify the signature on the `.msi`:

- PowerShell: `Get-AuthenticodeSignature .\<installer>.msi` — `Status` must be `Valid`, and confirm the listed signer matches the publisher you obtained the package from.
- Or right-click the file → **Properties → Digital Signatures**.

Do not install a package whose signature is missing or invalid.

A Software Bill of Materials (CycloneDX `bom.json`) listing the third-party components is generated by CI and attached to published releases (see `.github/workflows/ci.yml`).

## Windows Server 2019
If you use a Windows Server 2019 please activate TLS 1.x for your .NET because TLS 1.0 is deprecated.
Adding `"SchUseStrongCrypto"=dword:00000001` to `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft.NETFramework\v4.0.30319`
and `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft.NETFramework\v4.0.30319` fixes the problem.

## Event Log
Errors will be written to the Windows **Application** event log under the `privacyIDEAProvider` source. To get a more detailed log, activate the `debug_log` setting as explained in the next section.

## Logging and personal data
The detailed debug log (`debug_log`, written to `C:\PrivacyIDEA-ADFS log.txt`) is **off by default** and should only be enabled while troubleshooting. When enabled, it contains personal data and should be treated accordingly:

- **Usernames, UPNs and domains** are recorded so that an authentication can be traced end to end. This is required for the log to be useful for diagnostics and for security auditing.
- **Full server responses** from privacyIDEA are recorded as well; these may include token serials and any user attributes the server returns.
- **Secrets are masked.** The service account password (`password`), the user credential (`pass`, which in privacyIDEA carries the static PIN in front of the OTP) and the `Authorization` header (JWT) are redacted before anything is written. One-time values such as transaction IDs are not secrets and are logged in clear text.

This log lives on your own AD FS server and is under your control as the data controller. To meet your obligations (GDPR / ISO 27001):

- Keep `debug_log` disabled in normal operation and re-disable it once a problem is resolved.
- Restrict read access to the log file to administrators, and define a retention period after which it is deleted.
- Treat the file as in scope for your access-control, retention and audit-logging controls.

## Debugging
Errors in the provider can be found by looking at the Windows Event Log or activating the `debug_log` setting.
If the installer fails to install/uninstall the Provider, a logfile for that process can be created using the `cmd`:

install:      `msiexec /i ADFSProvider.msi /L*V install.log`

uninstall:    `msiexec /x ADFSProvider.msi /L*V uninstall.log`

The problematic part will probably be found in the last third of the log file.

If the provider fails to uninstall, you can uninstall it manually by navigating to `C:\Program Files\PrivacyIDEA AD FS\` and run the uninstall script. Doing this will leave the registry untouched and the provider in the installed software list. To remove it from the list, remove it's registry entry at `HKLM\SOFTWARE\Classes\Installer\Products\`.
