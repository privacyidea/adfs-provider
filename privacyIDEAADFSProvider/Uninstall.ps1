#Requires -RunAsAdministrator

# Detach the provider from every global auth policy list so Unregister is allowed. Each list is cast to
# List[string] before .Remove (the value Get-AdfsGlobalAuthenticationPolicy returns can be a fixed-size
# array, on which .Remove throws), and each is written back via its OWN parameter — earlier versions
# wrote the primary lists back via -AdditionalAuthenticationProvider, which never cleared the primary
# assignment and clobbered the additional list, so the following Unregister failed with "in use".
$policy = Get-AdfsGlobalAuthenticationPolicy
$name = "privacyIDEAADFSProvider"

if ($policy.PrimaryIntranetAuthenticationProvider -contains $name)
{
    $list = [System.Collections.Generic.List[string]]$policy.PrimaryIntranetAuthenticationProvider
    [void]$list.Remove($name)
    Set-AdfsGlobalAuthenticationPolicy -PrimaryIntranetAuthenticationProvider $list
}
if ($policy.PrimaryExtranetAuthenticationProvider -contains $name)
{
    $list = [System.Collections.Generic.List[string]]$policy.PrimaryExtranetAuthenticationProvider
    [void]$list.Remove($name)
    Set-AdfsGlobalAuthenticationPolicy -PrimaryExtranetAuthenticationProvider $list
}
if ($policy.AdditionalAuthenticationProvider -contains $name)
{
    $list = [System.Collections.Generic.List[string]]$policy.AdditionalAuthenticationProvider
    [void]$list.Remove($name)
    Set-AdfsGlobalAuthenticationPolicy -AdditionalAuthenticationProvider $list
}

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

Restart-Service adfssrv