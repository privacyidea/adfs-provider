# Acknowledgement
This project builds on Stephan Traub's [original provider v1.3.8.2](https://github.com/sbidy/privacyIDEA-ADFSProvider/tree/f66100713e650d134ac50fcbd3965b71ae588d47). 

# Signing
The dll that is created by this solution requires to be signed to be deployed. Change the key file to your own in the project settings of the provider.

## Windows Server 2019
If you use a Windows Server 2019 please activate TLS 1.x for your .NET because TLS 1.0 is deprecated.
Adding `"SchUseStrongCrypto"=dword:00000001` to `HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft.NETFramework\v4.0.30319`
and `HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft.NETFramework\v4.0.30319` fixes the problem.