#Requires -RunAsAdministrator

$name = "privacyIDEAADFSProvider"
$configKeyPath = 'HKLM:\SOFTWARE\Netknights GmbH\PrivacyIDEA-ADFS'

# Work from the folder this script was installed into, rather than a hardcoded path, so a non-default
# install location still works.
Set-Location -Path $PSScriptRoot
$myDll = 'privacyIDEA-ADFSProvider.dll'
$myDllFullName = (Get-Item $myDll).FullName

# The global authentication policy lists that can contain the provider. Install.ps1 uses the same keys.
$policyLists = @{
    'PrimaryIntranet' = 'PrimaryIntranetAuthenticationProvider'
    'PrimaryExtranet' = 'PrimaryExtranetAuthenticationProvider'
    'Additional'      = 'AdditionalAuthenticationProvider'
}

# Returns the keys of the policy lists that contain the provider.
function Get-PolicyMembership
{
    $policy = Get-AdfsGlobalAuthenticationPolicy
    $member = @()
    foreach ($key in $policyLists.Keys)
    {
        if (@($policy.($policyLists[$key])) -contains $name) { $member += $key }
    }
    return ,$member
}

# Adds the provider to, or removes it from, the given policy lists. Each list is cast to a List[string] (the
# value Get-AdfsGlobalAuthenticationPolicy returns can be a fixed-size array) and written back through its OWN
# parameter. Earlier versions wrote the primary lists back via -AdditionalAuthenticationProvider, which never
# cleared the primary assignment and clobbered the additional list, so the following Unregister failed with
# "in use".
function Set-PolicyMembership([string[]]$Lists, [bool]$Add)
{
    $policy = Get-AdfsGlobalAuthenticationPolicy
    foreach ($key in $Lists)
    {
        $property = $policyLists[$key]
        if (-not $property) { continue }
        $list = New-Object 'System.Collections.Generic.List[string]'
        foreach ($entry in @($policy.$property)) { if ($entry) { $list.Add([string]$entry) } }
        if ($Add) { if (-not $list.Contains($name)) { $list.Add($name) } }
        else { [void]$list.Remove($name) }
        $arguments = @{}
        $arguments[$property] = $list.ToArray()
        Set-AdfsGlobalAuthenticationPolicy @arguments
    }
}

# Take the provider out of AD FS: out of every global authentication policy list (Unregister fails while it is
# in one), then unregister it.
#
# If that fails, stop with an error BEFORE anything is removed. Removing the assembly from the GAC while AD FS is
# still registered to it breaks every sign-in that uses the provider, and on an MSI upgrade the new version would
# then find a registration that points to a missing assembly. The non-zero exit makes the MSI roll back, so the
# provider stays installed and working. The policy lists are restored first.
#
# The lists that contained the provider are recorded in the policy_membership value. On an MSI upgrade the new
# version's Install.ps1 (run with -Upgrade right after this script) puts the provider back into the same lists,
# so the upgrade keeps it enabled.
if (-not (Get-Command Unregister-AdfsAuthenticationProvider -ErrorAction SilentlyContinue))
{
    Write-Warning "The AD FS cmdlets were not found, so the provider is not unregistered. Continuing with the cleanup."
}
else
{
    $membership = @()
    try
    {
        # -ErrorAction Stop: if AD FS cannot be reached, do not mistake that for "not registered".
        if (Get-AdfsAuthenticationProvider -Name $name -ErrorAction Stop -WarningAction SilentlyContinue)
        {
            $membership = Get-PolicyMembership
            if ($membership.Count -gt 0 -and (Test-Path $configKeyPath))
            {
                Set-ItemProperty -Path $configKeyPath -Name 'policy_membership' -Value ($membership -join ',')
            }
            Set-PolicyMembership -Lists $membership -Add $false
            Unregister-AdfsAuthenticationProvider -Name $name -Confirm:$false -ErrorAction Stop
        }
        else
        {
            Write-Host "The provider '$name' is not registered with AD FS. Continuing with the cleanup."
        }
    }
    catch
    {
        $reason = $_
        try
        {
            Set-PolicyMembership -Lists $membership -Add $true
        }
        catch
        {
            Write-Warning "Could not put the provider back into the global authentication policy lists ($($membership -join ', ')): $_"
        }
        Remove-ItemProperty -Path $configKeyPath -Name 'policy_membership' -ErrorAction SilentlyContinue
        Write-Error ("Could not unregister the provider from AD FS: $reason The provider stays installed. Make sure " +
            "that the AD FS service runs, remove the provider from every authentication policy that uses it, then " +
            "run the uninstall again.")
        exit 1
    }
}

# From here on, AD FS no longer references the assembly. Each step is wrapped, so that one failure does not
# abort the rest of the cleanup.
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
# policy_membership is kept on purpose: the new version's Install.ps1 reads it on an upgrade.
try
{
    foreach ($secret in 'service_pass', 'api_key')
    {
        Remove-ItemProperty -Path $configKeyPath -Name $secret -ErrorAction SilentlyContinue
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

try
{
    Restart-Service adfssrv
}
catch
{
    Write-Warning "Could not restart adfssrv: $_. Restart it manually to finish applying the changes."
}
