#Requires -RunAsAdministrator
# Install the provider

# The provider targets .NET Framework 4.8. This is in-box on Windows Server 2022+, but NOT on
# Server 2016 (ships 4.6.2) or 2019 (ships 4.7.2) — installing the ADFS role does not pull it in.
# Fail fast with a clear message instead of letting ADFS silently refuse to load the assembly.
# Release >= 528040 means 4.8 or later (https://learn.microsoft.com/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed).
$netRelease = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Release
if (-not $netRelease -or $netRelease -lt 528040)
{
    Write-Error (".NET Framework 4.8 is required but was not detected on this machine. " +
        "Install it from https://dotnet.microsoft.com/download/dotnet-framework/net48 (a reboot may be required), " +
        "then re-run this script.")
    return
}

Set-Location -Path "C:\Program Files\PrivacyIDEA AD FS"

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
        Write-Host "`t`t$($MyInvocation.InvocationName): $_"
    }
}

# Event log source for provider errors.
#
# IMPORTANT: the source is registered in the standard "Application" log. Do NOT use "AD FS/Admin":
# that is an ETW *channel* owned by the AD FS publisher (Event Viewer > Applications and Services
# Logs > AD FS > Admin). Registering it through the classic event-log API makes Windows create a
# bogus  HKLM\SYSTEM\CurrentControlSet\Services\EventLog\AD FS/Admin  key that shadows the channel,
# which breaks AD FS event logging entirely and has been observed to block Windows Update servicing.
# Earlier versions of this script did exactly that; the block below stops doing it and repairs
# machines that were already affected.
$source = "privacyIDEAProvider"
$logName = "Application"

# Repair: remove the stray classic "AD FS/Admin" log key left by older installers. On a healthy
# server "AD FS/Admin" exists only as a channel (under WINEVT), never as a classic log, so
# EventLog::Exists returns $false there and this is a no-op.
if ([System.Diagnostics.EventLog]::Exists("AD FS/Admin"))
{
    try
    {
        Remove-EventLog -LogName "AD FS/Admin"
        Write-Host "Removed stray classic 'AD FS/Admin' event log created by a previous install."
    }
    catch
    {
        Write-Host "Could not remove stray 'AD FS/Admin' event log: $_"
    }
}

# Re-point the source if an older install bound it to the wrong log.
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
$configKeyPath = 'HKLM:\SOFTWARE\NetKnights GmbH\PrivacyIDEA-ADFS'
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
        $adfsAccount = (Get-CimInstance Win32_Service -Filter "Name='adfssrv'" -ErrorAction SilentlyContinue).StartName
        if ($adfsAccount -and $adfsAccount -notin @('LocalSystem', 'NT AUTHORITY\System'))
        {
            try
            {
                $sid = (New-Object System.Security.Principal.NTAccount($adfsAccount)).Translate([System.Security.Principal.SecurityIdentifier])
                $acl.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($sid, $readWrite, $inherit, $noProp, $allow)))
                Write-Host "Granted read/set-value on the configuration key to the AD FS service account '$adfsAccount'."
            }
            catch
            {
                # Don't abort the install over this — but make it loud, because the provider can't read
                # its config if the service account has no access, and SYSTEM/Admins still do.
                Write-Warning ("Could not resolve the AD FS service account '$adfsAccount' to grant it read access: $_. " +
                    "If the provider fails to read its configuration, grant '$adfsAccount' read on $configKeyPath manually.")
            }
        }

        Set-Acl -Path $configKeyPath -AclObject $acl
        Write-Host "Hardened ACL on $configKeyPath (removed non-admin read access)."
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

Register-AdfsAuthenticationProvider -TypeName $typeName -Name "privacyIDEAADFSProvider"

Restart-Service adfssrv