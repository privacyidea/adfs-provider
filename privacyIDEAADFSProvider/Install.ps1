#Requires -RunAsAdministrator
# Install the provider
param(
    # Set by the MSI when it replaces an older version (major upgrade). Install.ps1 then puts the provider
    # back into the global authentication policy lists that Uninstall.ps1 of the old version recorded.
    [switch]$Upgrade
)

# The provider targets .NET Framework 4.8. This is in-box on Windows Server 2022+, but NOT on
# Server 2016 (ships 4.6.2) or 2019 (ships 4.7.2) — installing the ADFS role does not pull it in.
# Fail fast with a clear message instead of letting ADFS silently refuse to load the assembly.
# Release >= 528040 means 4.8 or later (https://learn.microsoft.com/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed).
$netRelease = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Release
if (-not $netRelease -or $netRelease -lt 528040)
{
    # exit 1 (not return): run via the MSI as `powershell.exe -File`, `return` exits with code 0, so the
    # CAQuietExec custom action (Return="check") would treat it as success and install anyway. A non-zero
    # exit makes the MSI abort, which is the whole point of failing fast here.
    Write-Error (".NET Framework 4.8 is required but was not detected on this machine. " +
        "Install it from https://dotnet.microsoft.com/download/dotnet-framework/net48 (a reboot may be required), " +
        "then re-run this script.")
    exit 1
}

# Work from the folder this script was installed into, rather than a hardcoded path, so a non-default
# install location (for example msiexec INSTALLFOLDER=...) still works.
Set-Location -Path $PSScriptRoot

$myPath = Get-Location
$myDll = 'privacyIDEA-ADFSProvider.dll'
$myDllFullName = (get-item $myDll).FullName

function Gac-Util
{
    param (
        [parameter(Mandatory = $true)][string] $assembly
    )
    try
    {
        $Error.Clear()

        [Reflection.Assembly]::LoadWithPartialName("System.EnterpriseServices") | Out-Null
        [System.EnterpriseServices.Internal.Publish] $publish = New-Object System.EnterpriseServices.Internal.Publish

        if (!(Test-Path $assembly -type Leaf) ) 
            { throw "The assembly $assembly does not exist" }

        if ([System.Reflection.Assembly]::LoadFile($assembly).GetName().GetPublicKey().Length -eq 0 ) 
            { throw "The assembly $assembly must be strongly signed" }

        $publish.GacInstall($assembly)

        Write-Host "`t`t$($MyInvocation.InvocationName): Assembly $assembly gacced"
    }
    catch
    {
        # Re-throw so a GAC failure (missing file, unsigned assembly, or no permission) aborts the install
        # with a clear error, instead of being swallowed and surfacing later as a confusing registration
        # failure. Note: Publish.GacInstall itself does not report failure, so a silent GAC problem is still
        # caught downstream by the registration step below (which is wrapped and reports clearly).
        throw "Failed to install '$assembly' into the GAC: $_"
    }
}

# Event log source for provider errors.
#
# IMPORTANT: the source is registered in the standard "Application" log. Do NOT use "AD FS/Admin":
# that is an ETW *channel* owned by the AD FS publisher (Event Viewer > Applications and Services
# Logs > AD FS > Admin). Registering it through the classic event-log API makes Windows create a
# bogus  HKLM\SYSTEM\CurrentControlSet\Services\EventLog\AD FS/Admin  key that shadows the channel.
# Earlier versions of this script did that; we now simply log to "Application" instead. We do NOT
# touch any pre-existing "AD FS/Admin" classic log key — only re-point our own source if needed.
$source = "privacyIDEAProvider"
$logName = "Application"

# Re-point the source if an older install bound it to the wrong log (e.g. "AD FS/Admin").
if ([System.Diagnostics.EventLog]::SourceExists($source) -and
    [System.Diagnostics.EventLog]::LogNameFromSourceName($source, ".") -ne $logName)
{
    [System.Diagnostics.EventLog]::DeleteEventSource($source)
}

if (!([System.Diagnostics.EventLog]::SourceExists($source)))
{
    New-EventLog -LogName $logName -Source $source
    Write-Host "Event source '$source' registered in the '$logName' log."
}

# Harden the ACL on the configuration key. It holds secrets (service_pass today, an API key later).
# By default HKLM\SOFTWARE grants BUILTIN\Users read, so any non-admin on this box can read the
# service password in cleartext — the realistic, auditable hole. We strip that: only SYSTEM and
# Administrators get full control, and the AD FS service account gets read (it is what actually needs
# the value at runtime). This is defense-in-depth + compliance, NOT a hard boundary: anyone already
# running as SYSTEM/admin or the AD FS identity on this Tier-0 box owns the token-signing key anyway.
$configKeyPath = 'HKLM:\SOFTWARE\Netknights GmbH\PrivacyIDEA-ADFS'
if (Test-Path $configKeyPath)
{
    try
    {
        $acl = Get-Acl $configKeyPath
        # Disable inheritance and drop the inherited ACEs (the second $false) so BUILTIN\Users no
        # longer carries down read from the parent SOFTWARE key.
        $acl.SetAccessRuleProtection($true, $false)
        # Clear any stray explicit ACEs so we end up with exactly the three rules below.
        foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRule($rule) }

        $full = [System.Security.AccessControl.RegistryRights]::FullControl
        # Read + SetValue: the provider reads its config and re-writes the service password encrypted
        # (DPAPI write-back) the first time it finds a plaintext value. SetValue (not full write) keeps
        # this least-privilege — the service account cannot create or delete subkeys.
        $readWrite = [System.Security.AccessControl.RegistryRights]::ReadKey -bor `
                     [System.Security.AccessControl.RegistryRights]::SetValue
        # ContainerInherit so the realm-mapping subkey inherits the same protection.
        $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit
        $noProp = [System.Security.AccessControl.PropagationFlags]::None
        $allow = [System.Security.AccessControl.AccessControlType]::Allow

        # Well-known SIDs, so this works regardless of OS display language.
        $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')      # LocalSystem
        $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')  # BUILTIN\Administrators
        $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($system, $full, $inherit, $noProp, $allow)))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($admins, $full, $inherit, $noProp, $allow)))

        # Grant the actual AD FS service identity read access. It is whatever adfssrv runs as — a gMSA,
        # a domain account, or a built-in identity. LocalSystem is already covered above, so skip it.
        #
        # CRITICAL: we have just disabled inheritance (stripping BUILTIN\Users' read). If we cannot
        # determine or resolve the service account, committing this ACL would leave the account with NO
        # access and the provider would fail to read its config -> total MFA outage. So if the account is
        # unknown/unresolvable, we DO NOT apply the hardened ACL; we warn and leave the key as-is.
        $adfsAccount = (Get-CimInstance Win32_Service -Filter "Name='adfssrv'" -ErrorAction SilentlyContinue).StartName
        $applyAcl = $true
        if (-not $adfsAccount)
        {
            $applyAcl = $false
            Write-Warning ("Could not determine the AD FS service account (adfssrv). Skipping ACL hardening to " +
                "avoid locking the provider out of its configuration. Harden $configKeyPath manually if required.")
        }
        elseif ($adfsAccount -notin @('LocalSystem', 'NT AUTHORITY\System'))
        {
            try
            {
                $sid = (New-Object System.Security.Principal.NTAccount($adfsAccount)).Translate([System.Security.Principal.SecurityIdentifier])
                $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($sid, $readWrite, $inherit, $noProp, $allow)))
                Write-Host "Granted read/set-value on the configuration key to the AD FS service account '$adfsAccount'."
            }
            catch
            {
                $applyAcl = $false
                Write-Warning ("Could not resolve the AD FS service account '$adfsAccount': $_. Skipping ACL " +
                    "hardening to avoid locking the provider out of its configuration. Grant '$adfsAccount' read " +
                    "on $configKeyPath manually, then re-run this script.")
            }
        }

        if ($applyAcl)
        {
            Set-Acl -Path $configKeyPath -AclObject $acl
            Write-Host "Hardened ACL on $configKeyPath (removed non-admin read access)."
        }
    }
    catch
    {
        Write-Warning "Could not harden the ACL on ${configKeyPath}: $_"
    }
}
else
{
    Write-Host "Configuration key $configKeyPath not found yet. Create it and re-run this script to harden its ACL."
}

Gac-Util $myDllFullName

$appFullName = ([system.reflection.assembly]::loadfile($myDllFullName)).FullName

$typeName = "privacyIDEAADFSProvider.Adapter, "+$appFullName

# This script only makes sense on an AD FS server. If the AD FS cmdlets are absent, say so clearly instead
# of failing later with a cryptic "term is not recognized" error.
if (-not (Get-Command Register-AdfsAuthenticationProvider -ErrorAction SilentlyContinue))
{
    Write-Error ("The AD FS cmdlets were not found. Run this on an AD FS server with the AD FS role " +
        "installed.")
    exit 1
}

$name = "privacyIDEAADFSProvider"
# AD FS ties a registration to one assembly version. The registered AdminName carries that version
# (privacyIDEA-ADFSProvider_<version>, see AdapterMetadata.AdminName).
$newVersion = [System.Reflection.AssemblyName]::GetAssemblyName($myDllFullName).Version.ToString()
$expectedAdminName = "privacyIDEA-ADFSProvider_$newVersion"

# The global authentication policy lists that can contain the provider. Uninstall.ps1 uses the same keys.
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

# Adds the provider to, or removes it from, the given policy lists. Each list is written back through its own
# parameter.
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

# Register the provider, or replace a registration of another version.
#
# - Same version registered: nothing to do. The README tells admins to re-run this script to apply the ACL after
#   they create the configuration key, so a re-run must not fail. No restart is needed for an ACL change.
# - Another version registered (for example after the DLL was replaced by hand): replace the registration, so
#   that AD FS does not stay on the old assembly. Unregister fails while the provider is in a policy list, so the
#   provider leaves its lists first and goes back into the same lists afterwards. If the replacement fails, the
#   old registration is restored (the old assembly is still in the GAC, versions sit side by side).
# - Not registered: register. On an MSI upgrade (-Upgrade), put the provider back into the policy lists that
#   Uninstall.ps1 of the old version recorded in the policy_membership value.
#
# Wrapped so that a registration or restart failure reports clearly and aborts the MSI (non-zero exit).
try
{
    $registered = Get-AdfsAuthenticationProvider -Name $name -ErrorAction Stop -WarningAction SilentlyContinue
    if ($registered -and $registered.AdminName -eq $expectedAdminName)
    {
        Write-Host "The provider '$name' is already registered with version $newVersion. Skipping registration."
    }
    elseif ($registered)
    {
        $oldVersion = $registered.AdminName -replace '^privacyIDEA-ADFSProvider_', ''
        Write-Host "Replacing the registration of '$name' (version $oldVersion) with version $newVersion."
        $membership = Get-PolicyMembership
        Set-PolicyMembership -Lists $membership -Add $false
        try
        {
            Unregister-AdfsAuthenticationProvider -Name $name -Confirm:$false -ErrorAction Stop
            Register-AdfsAuthenticationProvider -TypeName $typeName -Name $name -ErrorAction Stop
        }
        catch
        {
            $reason = $_
            if (-not (Get-AdfsAuthenticationProvider -Name $name -ErrorAction SilentlyContinue -WarningAction SilentlyContinue))
            {
                try
                {
                    $oldAssembly = [System.Reflection.AssemblyName]::GetAssemblyName($myDllFullName)
                    $oldAssembly.Version = [Version]$oldVersion
                    Register-AdfsAuthenticationProvider -TypeName ("privacyIDEAADFSProvider.Adapter, " + $oldAssembly.FullName) `
                        -Name $name -ErrorAction Stop
                }
                catch
                {
                    Write-Warning "Could not restore the registration of version ${oldVersion}: $_"
                }
            }
            Set-PolicyMembership -Lists $membership -Add $true
            throw $reason
        }
        Set-PolicyMembership -Lists $membership -Add $true
        Restart-Service adfssrv
    }
    else
    {
        Register-AdfsAuthenticationProvider -TypeName $typeName -Name $name -ErrorAction Stop
        $recorded = (Get-ItemProperty -Path $configKeyPath -Name 'policy_membership' -ErrorAction SilentlyContinue).policy_membership
        if ($Upgrade -and $recorded)
        {
            Set-PolicyMembership -Lists ($recorded -split ',') -Add $true
            Write-Host "Put the provider back into the global authentication policy lists: $recorded."
        }
        Restart-Service adfssrv
    }
    # The recorded lists are used once. Remove them, so that a later fresh install does not pick them up.
    Remove-ItemProperty -Path $configKeyPath -Name 'policy_membership' -ErrorAction SilentlyContinue
}
catch
{
    Write-Error "Failed to register the provider with AD FS or restart the service: $_"
    exit 1
}