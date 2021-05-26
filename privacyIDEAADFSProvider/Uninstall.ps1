#Requires -RunAsAdministrator

# Unset the provider from both primary and additional
$providers = (Get-AdfsGlobalAuthenticationPolicy).AdditionalAuthenticationProvider
$providers.Remove("privacyIDEA-ADFSProvider") 
Set-AdfsGlobalAuthenticationPolicy -AdditionalAuthenticationProvider $providers

# Unregister the provider and restart the AD FS service
Set-Location -Path "C:\Program Files\PrivacyIDEA AD FS"
$myPath = Get-Location
$myDll = 'privacyIDEA-ADFSProvider.dll'
$myDllFullName = (get-item $myDll).FullName

Unregister-AdfsAuthenticationProvider -Name "privacyIDEA-ADFSProvider" -Confirm:$false -ErrorAction Stop
[System.Reflection.Assembly]::LoadWithPartialName("System.EnterpriseServices")
$publish = New-Object System.EnterpriseServices.Internal.Publish
$publish.GacRemove($myDllFullName)

Restart-Service adfssrv