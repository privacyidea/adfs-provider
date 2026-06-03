#Requires -RunAsAdministrator

# Unset the provider from both primary and additional
$policy = Get-AdfsGlobalAuthenticationPolicy

$primaryIntranetProviders = $policy.PrimaryIntranetAuthenticationProvider
$primaryIntranetProviders.Remove("privacyIDEAADFSProvider") 
Set-AdfsGlobalAuthenticationPolicy -AdditionalAuthenticationProvider $primaryIntranetProviders

$primaryExtranetProviders = $policy.PrimaryExtranetAuthenticationProvider
$primaryExtranetProviders.Remove("privacyIDEAADFSProvider") 
Set-AdfsGlobalAuthenticationPolicy -AdditionalAuthenticationProvider $primaryExtranetProviders

$additionalProviders = $policy.AdditionalAuthenticationProvider
$additionalProviders.Remove("privacyIDEAADFSProvider") 
Set-AdfsGlobalAuthenticationPolicy -AdditionalAuthenticationProvider $additionalProviders

# Unregister the provider and restart the AD FS service
Set-Location -Path "C:\Program Files\PrivacyIDEA AD FS"
$myPath = Get-Location
$myDll = 'privacyIDEA-ADFSProvider.dll'
$myDllFullName = (get-item $myDll).FullName

Unregister-AdfsAuthenticationProvider -Name "privacyIDEAADFSProvider" -Confirm:$false -ErrorAction Stop
[System.Reflection.Assembly]::LoadWithPartialName("System.EnterpriseServices")
$publish = New-Object System.EnterpriseServices.Internal.Publish
$publish.GacRemove($myDllFullName)

# Remove the event log source registered by Install.ps1.
if ([System.Diagnostics.EventLog]::SourceExists("privacyIDEAProvider"))
{
    [System.Diagnostics.EventLog]::DeleteEventSource("privacyIDEAProvider")
}
# Clean up the stray classic "AD FS/Admin" log key if an older (buggy) install left one. This only
# exists on affected machines; on a healthy server "AD FS/Admin" is a channel, not a classic log.
if ([System.Diagnostics.EventLog]::Exists("AD FS/Admin"))
{
    try { Remove-EventLog -LogName "AD FS/Admin" } catch { Write-Host "Could not remove stray 'AD FS/Admin' event log: $_" }
}

Restart-Service adfssrv