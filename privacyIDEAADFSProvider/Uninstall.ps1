#Requires -RunAsAdministrator

# Detach the provider from every global auth policy list so Unregister is allowed. Each list is cast to
# List[string] before .Remove (the value Get-AdfsGlobalAuthenticationPolicy returns can be a fixed-size
# array, on which .Remove throws), and each is written back via its OWN parameter — earlier versions
# wrote the primary lists back via -AdditionalAuthenticationProvider, which never cleared the primary
# assignment and clobbered the additional list, so the following Unregister failed with "in use".
$policy = Get-AdfsGlobalAuthenticationPolicy
$name = "privacyIDEAADFSProvider"

# Wrapped so a policy-update quirk (e.g. AD FS rejecting an empty primary list if this provider was the
# sole primary method) doesn't abort the whole uninstall before GAC removal. If detach fails, the later
# Unregister may report "in use" — surface that rather than leaving the machine half-uninstalled.
try
{
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
}
catch
{
    Write-Warning "Could not fully detach the provider from the global auth policy: $_"
}

# Unregister the provider and restart the AD FS service
# Work from the folder this script was installed into, rather than a hardcoded path, so a non-default
# install location still works.
Set-Location -Path $PSScriptRoot
$myPath = Get-Location
$myDll = 'privacyIDEA-ADFSProvider.dll'
$myDllFullName = (get-item $myDll).FullName

# Best-effort cleanup: each step is wrapped so one failure (for example Unregister reporting the provider
# is still in use because the detach above failed) does not abort the rest and leave the machine
# half-uninstalled.
try
{
    Unregister-AdfsAuthenticationProvider -Name "privacyIDEAADFSProvider" -Confirm:$false -ErrorAction Stop
}
catch
{
    Write-Warning "Could not unregister the provider (it may still be in use): $_. Continuing with cleanup."
}

try
{
    [System.Reflection.Assembly]::LoadWithPartialName("System.EnterpriseServices") | Out-Null
    $publish = New-Object System.EnterpriseServices.Internal.Publish
    $publish.GacRemove($myDllFullName)
}
catch
{
    Write-Warning "Could not remove the assembly from the GAC: $_"
}

# Wipe the secrets from the configuration key. The MSI removes the values it authored, but a manual run of
# this script (the README's manual-uninstall path) otherwise leaves service_pass and api_key behind. On a
# major upgrade this runs for the old version and the new install re-writes the values from its prefilled
# properties, so the secrets are preserved across an upgrade while a real uninstall clears them.
try
{
    $configKey = 'HKLM:\SOFTWARE\Netknights GmbH\PrivacyIDEA-ADFS'
    foreach ($secret in 'service_pass', 'api_key')
    {
        Remove-ItemProperty -Path $configKey -Name $secret -ErrorAction SilentlyContinue
    }
}
catch
{
    Write-Warning "Could not remove the secret registry values: $_"
}

# Remove the event log source registered by Install.ps1.
try
{
    if ([System.Diagnostics.EventLog]::SourceExists("privacyIDEAProvider"))
    {
        [System.Diagnostics.EventLog]::DeleteEventSource("privacyIDEAProvider")
    }
}
catch
{
    Write-Warning "Could not remove the event log source: $_"
}

Restart-Service adfssrv