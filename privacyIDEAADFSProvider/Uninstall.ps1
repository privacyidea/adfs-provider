#Requires -RunAsAdministrator

# Unset the provider from both primary and additional
$policy = Get-AdfsGlobalAuthenticationPolicy

$primaryIntranetProviders = $policy.PrimaryIntranetAuthenticationProvider
$primaryIntranetProviders.Remove("privacyIDEA-ADFSProvider") 
Set-AdfsGlobalAuthenticationPolicy -AdditionalAuthenticationProvider $primaryIntranetProviders

$primaryExtranetProviders = $policy.PrimaryExtranetAuthenticationProvider
$primaryExtranetProviders.Remove("privacyIDEA-ADFSProvider") 
Set-AdfsGlobalAuthenticationPolicy -AdditionalAuthenticationProvider $primaryExtranetProviders

$additionalProviders = $policy.AdditionalAuthenticationProvider
$additionalProviders.Remove("privacyIDEA-ADFSProvider") 
Set-AdfsGlobalAuthenticationPolicy -AdditionalAuthenticationProvider $additionalProviders

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