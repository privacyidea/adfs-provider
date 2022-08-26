# Acknowledgement
This project builds on Stephan Traub's [original provider v1.3.8.2](https://github.com/sbidy/privacyIDEA-ADFSProvider/tree/f66100713e650d134ac50fcbd3965b71ae588d47). 

## Preface
If you face issues, please check the sections below on how to generate information that can be used to find the problem.

## Requirements
To use the provider, the [.NET Framework 4.8](https://dotnet.microsoft.com/download/dotnet-framework/net48) is required on the target machine.

## Signing
The dll that is created by this solution requires to be signed to be deployed. Change the key file to your own in the project settings of the provider.

## Windows Server 2019
If you use a Windows Server 2019 please activate TLS 1.x for your .NET because TLS 1.0 is deprecated.
Adding `"SchUseStrongCrypto"=dword:00000001` to `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft.NETFramework\v4.0.30319`
and `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft.NETFramework\v4.0.30319` fixes the problem.

## Installation
Run the MSI.

## Event Log
Errors will be written to the Windows Event Log in the `AD FS/Admin` category. To get a more detailed log, activate the `debug_log` setting as explained in the next section.

## Configuration
The provider is configured using the registry. The keys are located at `HKEY_LOCAL_MACHINE\SOFTWARE\NetKnights GmbH\PrivacyIDEA-ADFS`.
After changing the configuration, the AD FS Service has to be restarted for the changes to become active. This can be done using the PowerShell command `Restart-Service adfssrv`.

| Key Name | Explanation |
| ----- | ----- |
| url | The url of the privacyIDEA server. Has to include https://! |
| disable_ssl | Set to `1` if ssl verification should be disabled. DO NOT DISABLE THIS IN A PRODUCTION ENVIRONMENT! |
| debug_log | Set to `1` if a detailed debug log should be written. It will be located at `C:\PrivacyIDEA-ADFS log.txt`. |
| enable_enrollment | Set to `1` if users should automatically enroll a TOTP code if they do not have any other tokens enrolled. |
| realm | Set the realm that should be appended to every request. If this is empty, the realm parameter will be omitted from requests. |
| service_user | Set the username of a privacyIDEA service account that can be used to trigger challenges. Configuring this is only required to use the `trigger_challenges` or `enable_enrollment` settings! |
| service_pass | Set the password of a privacyIDEA service account that can be used to trigger challenges. Configuring this is only required to use the `trigger_challenges` or `enable_enrollment` settings! |
| service_realm | Set the realm of a privacyIDEA service account that can be used to trigger challenges. This realm setting can be used if the service account is found in a different realm than the other one specified. |
| trigger_challenges | Set this to `1` to trigger challenges prior to the login using the configured service account. This setting takes precedence over `send_empty_pass`. |
| send_empty_pass | Set this to `1` to send a request to validate/check with the username and an empty pass prior to the login. This can be used to trigger challenges depending on the configuration in privacyIDEA and **requires no service account**. If `trigger_challenges` is enabled, this setting has no effect. |
| use_upn | Set this to `1` to use the Windows UPN (person@company.com) as the username for requests to privacyIDEA. |
| tls_version | If you want to explicite the TLS version, set it to: `tls11`, `tls12` or `tls13`. Other values will be ignored and TLS version will stay as system default. |
| forward_headers | If you want to forward specific headers to the privacyIDEA server, you can set them here. If the header does not exist or has no value, it will be ignored. The headers names should be separated with ','. |
| preferred_token_type | Set the token type for which the UI should be first shown. This only matters if such token was triggered before. Possible values are `otp`, `push`, `u2f` and `webauthn`. The default is OTP mode. |

### Domain to Realm Mapping
It is possible to map different Windows domains to different privacyIDEA realms. To achieve this, add the subkey `HKLM\SOFTWARE\Netknights GmbH\PrivacyIDEA-ADFS\realm-mapping`. Now you can add REG_SZ entries that have the name of the Windows domain and the value of the corresponding privacyIDEA realm. Note that the realm mapping takes precedence over the general realm that can be configured as explained in the previous section.

## Debugging
Errors in the provider can be found by looking at the Windows Event Log or activating the `debug_log` setting.
If the installer fails to install/uninstall the Provider, a logfile for that process can be created using the `cmd`:

install:      `msiexec /i ADFSProvider.msi /L*V install.log`

uninstall:    `msiexec /x ADFSProvider.msi /L*V uninstall.log`

The problematic part will probably be found in the last third of the log file.

If the provider fails to uninstall, you can uninstall it manually by navigating to `C:\Program Files\PrivacyIDEA AD FS\` and run the uninstall script. Doing this will leave the registry untouched and the provider in the installed software list. To remove it from the list, remove it's registry entry at `HKLM\SOFTWARE\Classes\Installer\Products\`.
