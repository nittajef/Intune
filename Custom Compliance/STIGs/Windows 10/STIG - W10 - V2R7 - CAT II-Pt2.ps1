##
# Microsoft Windows 10 Security Technical Implementation Guide
# Version: 2, Release: 7 Benchmark Date: 07 Jun 2023
#
# PowerShell script and accompanying JSON file for Intune Custom Compliance
# were generated with: https://github.com/nittajef/Intune/
##


#
# Gather data used across multiple rule checks
#

$AuditPolicy = @{}
auditpol /get /category:* /r | ConvertFrom-Csv | % { $AuditPolicy[$_.Subcategory] = $_.'Inclusion Setting' }

$ComputerInfo = Get-ComputerInfo | Select-Object -Property WindowsProductName,OsBuildNumber,OsArchitecture

# Determine the "Domain SID" that the machine is a member of
$id = new-object System.Security.Principal.NTAccount($env:COMPUTERNAME + "$")
$id.Translate([System.Security.Principal.SecurityIdentifier]).toString() -match "(^S-1-5-\d+-\d+-\d+-\d+-)\d+$" | Out-Null
$DomainSID = $Matches[1]

$LocalUsers = Get-LocalUser

$v1507 = "10240"
$v1607 = "14393"
$v1809 = "17763"
$v21H2 = "19044"
$LTSB = @($v1507, $v1607, $v1809, $v21H2)

# Create hash of local security policies (exported in .ini format)
# Ref: Ingest .ini file: https://devblogs.microsoft.com/scripting/use-powershell-to-work-with-any-ini-file/
$SPFile = [System.Environment]::GetEnvironmentVariable('TEMP','Machine') + "\secpol.cfg"
secedit /export /cfg $SPFile | Out-Null

$SecurityPolicy = @{}  
switch -regex -file $SPFile
{
    "^\[(.+)\]$" # Section
    {
        $section = $matches[1]
        $SecurityPolicy[$section] = @{}
    }
    "(.+?)\s*=\s*(.*)" # Key
    {
        if (!($section))
        {
            $section = "No-Section"
            $SecurityPolicy[$section] = @{}
        }
        $name,$value = $matches[1..2]
        $SecurityPolicy[$section][$name] = $value
    }
}
Remove-Item -Force $SPFile -Confirm:$false


##
# V-220774
# The system must be configured to audit System - Other System Events failures.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Audit Other System Events records information related to cryptographic key operations and the Windows Firewall
# service.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective. 
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*"
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# System >> Other System Events - Failure
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> System >> "Audit Other System Events" with "Failure"
# selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220774r569187_rule
# STIG ID: WN10-AU-000135
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Other System Events' -match "Failure") {
        $V220774 = $true
    } else {
        $V220774 = $false
    }
} catch {
    $V220774 = $false
}

##
# V-220775
# The system must be configured to audit System - Security State Change successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Security State Change records events related to changes in the security state, such as startup and shutdown of
# the system.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# System >> Security State Change - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> System >> "Audit Security State Change" with "Success"
# selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220775r851978_rule
# STIG ID: WN10-AU-000140
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Security State Change' -match "Success") {
        $V220775 = $true
    } else {
        $V220775 = $false
    }
} catch {
    $V220775 = $false
}

##
# V-220776
# The system must be configured to audit System - Security System Extension successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Security System Extension records events related to extension code being loaded by the security subsystem.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# System >> Security System Extension - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> System >> "Audit Security System Extension" with
# "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220776r851979_rule
# STIG ID: WN10-AU-000150
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Security System Extension' -match "Success") {
        $V220776 = $true
    } else {
        $V220776 = $false
    }
} catch {
    $V220776 = $false
}

##
# V-220777
# The system must be configured to audit System - System Integrity failures.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# System Integrity records events related to violations of integrity to the security subsystem.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# System >> System Integrity - Failure
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> System >> "Audit System Integrity" with "Failure"
# selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220777r851980_rule
# STIG ID: WN10-AU-000155
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'System Integrity' -match "Failure") {
        $V220777 = $true
    } else {
        $V220777 = $false
    }
} catch {
    $V220777 = $false
}

##
# V-220778
# The system must be configured to audit System - System Integrity successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  Collecting this data
# is essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# System Integrity records events related to violations of integrity to the security subsystem.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following.  If the system does not audit the following, this is a
# finding:
#
# System >> System Integrity - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> System >> "Audit System Integrity" with "Success"
# selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220778r851981_rule
# STIG ID: WN10-AU-000160
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'System Integrity' -match "Success") {
        $V220778 = $true
    } else {
        $V220778 = $false
    }
} catch {
    $V220778 = $false
}

##
# V-220779
# The Application event log size must be configured to 32768 KB or greater.
#
##
# DISCUSSION: 
# Inadequate log size will cause the log to fill up quickly.  This may prevent audit events from being recorded
# properly and require frequent attention by administrative personnel.
#
##
# CHECK: 
# If the system is configured to send audit records directly to an audit server, this is NA.  This must be
# documented with the ISSO.
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive:  HKEY_LOCAL_MACHINE
# Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\
#
# Value Name:  MaxSize
#
# Value Type:  REG_DWORD
# Value:  0x00008000 (32768) (or greater)
#
##
# FIX: 
# If the system is configured to send audit records directly to an audit server, this is NA.  This must be
# documented with the ISSO.
#
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Event Log Service >> Application >> "Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log
# Size (KB)" of "32768" or greater.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220779r877391_rule
# STIG ID: WN10-AU-000500
# REFERENCE: 
##
try {
    if ($AppEventLogSize) {
        $size = $AppEventLogSize
    } else {
        $size = 32768
    }
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application\" -Name MaxSize -ErrorAction Stop) -ge $size) {
        $V220779 = $true
    } else {
        $V220779 = $false
    }
} catch {
    $V220779 = $false
}

##
# V-220780
# The Security event log size must be configured to 1024000 KB or greater.
#
##
# DISCUSSION: 
# Inadequate log size will cause the log to fill up quickly.  This may prevent audit events from being recorded
# properly and require frequent attention by administrative personnel.
#
##
# CHECK: 
# If the system is configured to send audit records directly to an audit server, this is NA. This must be
# documented with the ISSO.
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\
#
# Value Name: MaxSize
#
# Value Type: REG_DWORD
# Value: 0x000fa000 (1024000) (or greater)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Event Log Service >> Security >> "Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log
# Size (KB)" of "1024000" or greater.
#
# If the system is configured to send audit records directly to an audit server, documented with the ISSO.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220780r877391_rule
# STIG ID: WN10-AU-000505
# REFERENCE: 
##
try {
    if ($SecEventLogSize) {
        $size = $SecEventLogSize
    } else {
        $size = 1024000
    }
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\" -Name MaxSize -ErrorAction Stop) -eq 1024000) {
        $V220780 = $true
    } else {
        $V220780 = $false
    }
} catch {
    $V220780 = $false
}

##
# V-220781
# The System event log size must be configured to 32768 KB or greater.
#
##
# DISCUSSION: 
# Inadequate log size will cause the log to fill up quickly.  This may prevent audit events from being recorded
# properly and require frequent attention by administrative personnel.
#
##
# CHECK: 
# If the system is configured to send audit records directly to an audit server, this is NA.  This must be
# documented with the ISSO.
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive:  HKEY_LOCAL_MACHINE
# Registry Path:  \SOFTWARE\Policies\Microsoft\Windows\EventLog\System\
#
# Value Name:  MaxSize
#
# Value Type:  REG_DWORD
# Value:  0x00008000 (32768) (or greater)
#
##
# FIX: 
# If the system is configured to send audit records directly to an audit server, this is NA.  This must be
# documented with the ISSO.
#
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Event Log Service >> System >> "Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size
# (KB)" of "32768" or greater.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220781r877391_rule
# STIG ID: WN10-AU-000510
# REFERENCE: 
##
try {
    if ($SysEventLogSize) {
        $size = $SysEventLogSize
    } else {
        $size = 32768
    }
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\" -Name MaxSize -ErrorAction Stop) -eq 1024000) {
        $V220781 = $true
    } else {
        $V220781 = $false
    }
} catch {
    $V220781 = $false
}

##
# V-220782
# Windows 10 permissions for the Application event log must prevent access by non-privileged accounts.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  The Application event
# log may be  susceptible to tampering if proper permissions are not applied.
#
##
# CHECK: 
# Verify the permissions on the Application event log (Application.evtx). Standard user accounts or groups must
# not have access. The default permissions listed below satisfy this requirement.
#
# Eventlog - Full Control
# SYSTEM - Full Control
# Administrators - Full Control
#
# The default location is the "%SystemRoot%\SYSTEM32\WINEVT\LOGS" directory. They may have been moved to another
# folder.
#
# If the permissions for these files are not as restrictive as the ACLs listed, this is a finding.
#
# NOTE: If "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" has Special Permissions, this would not be a
# finding.
#
##
# FIX: 
# Ensure the permissions on the Application event log (Application.evtx) are configured to prevent standard user
# accounts or groups from having access. The default permissions listed below satisfy this requirement.
#
# Eventlog - Full Control
# SYSTEM - Full Control
# Administrators - Full Control
#
# The default location is the "%SystemRoot%\SYSTEM32\WINEVT\LOGS" directory.
#
# If the location of the logs has been changed, when adding Eventlog to the permissions, it must be entered as
# "NT Service\Eventlog".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220782r569187_rule
# STIG ID: WN10-AU-000515
# REFERENCE: 
##
try {
    $acl = Get-Acl -Path (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" -Name File)
    
    $V220782 = $true
    foreach ($entry in $acl.Access) {
        if ($entry.IdentityReference.Value -in @("NT SERVICE\EventLog", "NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
            $entry.FileSystemRights -eq "FullControl") {
            # Okay as default permissions        
        } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES") {
            # Also okay if this has special permissions, not sure on detailed permissions
        } else {
            $V220782 = $false
        }
    }
} catch {
    $V220782 = $false
}

##
# V-220783
# Windows 10 permissions for the Security event log must prevent access by non-privileged accounts.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  The Security event log
# may disclose sensitive information or be  susceptible to tampering if proper permissions are not applied.
#
##
# CHECK: 
# Verify the permissions on the Security event log (Security.evtx). Standard user accounts or groups must not
# have access. The default permissions listed below satisfy this requirement.
#
# Eventlog - Full Control
# SYSTEM - Full Control
# Administrators - Full Control
#
# The default location is the "%SystemRoot%\SYSTEM32\WINEVT\LOGS" directory. They may have been moved to another
# folder.
#
# If the permissions for these files are not as restrictive as the ACLs listed, this is a finding.
#
# NOTE: If "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" has Special Permissions, this would not be a
# finding.
#
##
# FIX: 
# Ensure the permissions on the Security event log (Security.evtx) are configured to prevent standard user
# accounts or groups from having access.  The default permissions listed below satisfy this requirement.
#
# Eventlog - Full Control
# SYSTEM - Full Control
# Administrators - Full Control
#
# The default location is the "%SystemRoot%\SYSTEM32\WINEVT\LOGS" directory.
#
# If the location of the logs has been changed, when adding Eventlog to the permissions, it must be entered as
# "NT Service\Eventlog".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220783r569187_rule
# STIG ID: WN10-AU-000520
# REFERENCE: 
##
try {
    $acl = Get-Acl -Path (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name File)
    
    $V220783 = $true
    foreach ($entry in $acl.Access) {
        if ($entry.IdentityReference.Value -in @("NT SERVICE\EventLog", "NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
            $entry.FileSystemRights -eq "FullControl") {
            # Okay as default permissions        
        } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES") {
            # Also okay if this has special permissions, not sure on detailed permissions
        } else {
            $V220783 = $false
        }
    }
} catch {
    $V220783 = $false
}

##
# V-220784
# Windows 10 permissions for the System event log must prevent access by non-privileged accounts.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks.  Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised.  The System event log
# may be  susceptible to tampering if proper permissions are not applied.
#
##
# CHECK: 
# Verify the permissions on the System event log (System.evtx). Standard user accounts or groups must not have
# access. The default permissions listed below satisfy this requirement.
#
# Eventlog - Full Control
# SYSTEM - Full Control
# Administrators - Full Control
#
# The default location is the "%SystemRoot%\SYSTEM32\WINEVT\LOGS" directory. They may have been moved to another
# folder.
#
# If the permissions for these files are not as restrictive as the ACLs listed, this is a finding.
#
# NOTE: If "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES" has Special Permissions, this would not be a
# finding.
#
##
# FIX: 
# Ensure the permissions on the System event log (System.evtx) are configured to prevent standard user accounts
# or groups from having access. The default permissions listed below satisfy this requirement.
#
# Eventlog - Full Control
# SYSTEM - Full Control
# Administrators - Full Control
#
# The default location is the "%SystemRoot%\SYSTEM32\WINEVT\LOGS" directory.
#
# If the location of the logs has been changed, when adding Eventlog to the permissions, it must be entered as
# "NT Service\Eventlog".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220784r569187_rule
# STIG ID: WN10-AU-000525
# REFERENCE: 
##
try {
    $acl = Get-Acl -Path (Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System" -Name File)
    
    $V220784 = $true
    foreach ($entry in $acl.Access) {
        if ($entry.IdentityReference.Value -in @("NT SERVICE\EventLog", "NT AUTHORITY\SYSTEM", "BUILTIN\Administrators") -and
            $entry.FileSystemRights -eq "FullControl") {
            # Okay as default permissions        
        } elseif ($entry.IdentityReference.Value -eq "APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES") {
            # Also okay if this has special permissions, not sure on detailed permissions
        } else {
            $V220784 = $false
        }
    }
} catch {
    $V220784 = $false
}

##
# V-220786
# Windows 10 must be configured to audit Other Policy Change Events Failures.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Audit Other Policy Change Events contains events about EFS Data Recovery Agent policy changes, changes in
# Windows Filtering Platform filter, status on Security policy settings updates for local Group Policy settings,
# Central Access Policy changes, and detailed troubleshooting events for Cryptographic Next Generation (CNG)
# operations.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following. If the system does not audit the following, this is a
# finding:
#
# Policy Change  >> Other Policy Change Events - Failure
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Policy Change>> "Audit Other Policy Change Events" with
# "Failure" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220786r569187_rule
# STIG ID: WN10-AU-000555
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Other Policy Change Events' -match "Failure") {
        $V220786 = $true
    } else {
        $V220786 = $false
    }
} catch {
    $V220786 = $false
}

##
# V-220787
# Windows 10 must be configured to audit other Logon/Logoff Events Successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Audit Other Logon/Logoff Events determines whether Windows generates audit events for other logon or logoff
# events. Logon events are essential to understanding user activity and detecting potential attacks.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following. If the system does not audit the following, this is a
# finding:
#
# Logon/Logoff  >> Other Logon/Logoff Events - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Logon/Logoff >> "Audit Other Logon/Logoff Events" with
# "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220787r569187_rule
# STIG ID: WN10-AU-000560
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Other Logon/Logoff Events' -match "Success") {
        $V220787 = $true
    } else {
        $V220787 = $false
    }
} catch {
    $V220787 = $false
}

##
# V-220788
# Windows 10 must be configured to audit other Logon/Logoff Events Failures.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Audit Other Logon/Logoff Events determines whether Windows generates audit events for other logon or logoff
# events. Logon events are essential to understanding user activity and detecting potential attacks.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following. If the system does not audit the following, this is a
# finding:
#
# Logon/Logoff  >> Other Logon/Logoff Events - Failure
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Logon/Logoff >> "Audit Other Logon/Logoff Events" with
# "Failure" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220788r569187_rule
# STIG ID: WN10-AU-000565
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Other Logon/Logoff Events' -match "Failure") {
        $V220788 = $true
    } else {
        $V220788 = $false
    }
} catch {
    $V220788 = $false
}

##
# V-220789
# Windows 10 must be configured to audit Detailed File Share Failures.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Audit Detailed File Share allows the auditing of attempts to access files and folders on a shared folder.
#
# The Detailed File Share setting logs an event every time a file or folder is accessed, whereas the File Share
# setting only records one event for any connection established between a client and file share. Detailed File
# Share audit events include detailed information about the permissions or other criteria used to grant or deny
# access.
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a command prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following. If the system does not audit the following, this is a
# finding:
#
# Object Access  >> Detailed File Share - Failure
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Object Access >> "Audit Detailed File Share" with
# "Failure" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220789r819664_rule
# STIG ID: WN10-AU-000570
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'Detailed File Share' -match "Failure") {
        $V220789 = $true
    } else {
        $V220789 = $false
    }
} catch {
    $V220789 = $false
}

##
# V-220790
# Windows 10 must be configured to audit MPSSVC Rule-Level Policy Change Successes.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Audit MPSSVC Rule-Level Policy Change determines whether the operating system generates audit events when
# changes are made to policy rules for the Microsoft Protection Service (MPSSVC.exe). 
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following. If the system does not audit the following, this is a
# finding:
#
# Policy Change  >> MPSSVC Rule-Level Policy Change - Success
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Policy Change >> "Audit MPSSVC Rule-Level Policy
# Change" with "Success" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220790r569187_rule
# STIG ID: WN10-AU-000575
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'MPSSVC Rule-Level Policy Change' -match "Success") {
        $V220790 = $true
    } else {
        $V220790 = $false
    }
} catch {
    $V220790 = $false
}

##
# V-220791
# Windows 10 must be configured to audit MPSSVC Rule-Level Policy Change Failures.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Audit MPSSVC Rule-Level Policy Change determines whether the operating system generates audit events when
# changes are made to policy rules for the Microsoft Protection Service (MPSSVC.exe). 
#
##
# CHECK: 
# Security Option "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit
# policy category settings" must be set to "Enabled" (WN10-SO-000030) for the detailed auditing subcategories to
# be effective.
#
# Use the AuditPol tool to review the current Audit Policy configuration:
# Open a Command Prompt with elevated privileges ("Run as Administrator").
# Enter "AuditPol /get /category:*".
#
# Compare the AuditPol settings with the following. If the system does not audit the following, this is a
# finding:
#
# Policy Change  >> MPSSVC Rule-Level Policy Change - Failure
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Advanced
# Audit Policy Configuration >> System Audit Policies >> Policy Change >> "Audit MPSSVC Rule-Level Policy
# Change" with "Failure" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220791r569187_rule
# STIG ID: WN10-AU-000580
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\" -Name SCENoApplyLegacyAuditPolicy -ErrorAction Stop) -eq 1 -and
        $AuditPolicy.'MPSSVC Rule-Level Policy Change' -match "Failure") {
        $V220791 = $true
    } else {
        $V220791 = $false
    }
} catch {
    $V220791 = $false
}

##
# V-220792
# Camera access from the lock screen must be disabled.
#
##
# DISCUSSION: 
# Enabling camera access from the lock screen could allow for unauthorized use.  Requiring logon will ensure the
# device is only used by authorized personnel.
#
##
# CHECK: 
# If the device does not have a camera, this is NA.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Personalization\
#
# Value Name: NoLockScreenCamera
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# If the device does not have a camera, this is NA.
#
# Configure the policy value for Computer Configuration >> Administrative Templates >> Control Panel >>
# Personalization >> "Prevent enabling lock screen camera" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220792r569187_rule
# STIG ID: WN10-CC-000005
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\" -Name NoLockScreenCamera -ErrorAction Stop) -eq 1) {
        $V220792 = $true
    } else {
        $V220792 = $false
    }
} catch {
    $V220792 = $false
}


##
# V-220793
# Windows 10 must cover or disable the built-in or attached camera when not in use.
#
##
# DISCUSSION: 
# It is detrimental for operating systems to provide, or install by default, functionality exceeding
# requirements or mission objectives. These unnecessary capabilities or services are often overlooked and
# therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.
#
# Failing to disconnect from collaborative computing devices (i.e., cameras) can result in subsequent
# compromises of organizational information. Providing easy methods to physically disconnect from such devices
# after a collaborative computing session helps to ensure that participants actually carry out the disconnect
# activity without having to go through complex and tedious procedures.
#
# Satisfies: SRG-OS-000095-GPOS-00049, SRG-OS-000370-GPOS-00155
#
##
# CHECK: 
# If the device or operating system does not have a camera installed, this requirement is not applicable.
#
# This requirement is not applicable to mobile devices (smartphones and tablets) where the use of the camera is
# a local AO decision.
#
# This requirement is not applicable to dedicated VTC suites located in approved VTC locations that are
# centrally managed.
#
# For an external camera, if there is not a method for the operator to manually disconnect the camera at the end
# of collaborative computing sessions, this is a finding.
#
# For a built-in camera, the camera must be protected by a camera cover (e.g., laptop camera cover slide) when
# not in use. 
#
# If the built-in camera is not protected with a camera cover, or if the built-in camera is not disabled in the
# bios, this is a finding.
#
# If the camera is not disconnected or covered, the following registry entry is required:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# RegistryPath\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam
#
# Value Name: Value
# Value Data: Deny
#
# If "Value" is set to a value other than "Deny" and the collaborative computing device has not been authorized
# for use, this is a finding.
#
##
# FIX: 
# If the camera is not disconnected or covered, the following registry entry is required:
#  
# Registry Hive: HKEY_LOCAL_MACHINE
# RegistryPath\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam
#
# Value Name: Value
# Value Data: Deny
#
##
# SEVERITY: CAT II
# RULE ID: SV-220793r819667_rule
# STIG ID: WN10-CC-000007
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name Value -ErrorAction Stop) -eq "Deny") {
        $V220793 = $true
    } else {
        $V220793 = $false
    }
} catch {
    $V220793 = $false
}

##
# V-220794
# The display of slide shows on the lock screen must be disabled.
#
##
# DISCUSSION: 
# Slide shows that are displayed on the lock screen could display sensitive information to unauthorized
# personnel.  Turning off this feature will limit access to the information to a logged on user.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Personalization\
#
# Value Name: NoLockScreenSlideshow
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Control Panel >>
# Personalization >> "Prevent enabling lock screen slide show" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220794r569187_rule
# STIG ID: WN10-CC-000010
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization\" -Name NoLockScreenSlideshow -ErrorAction Stop) -eq 1) {
        $V220794 = $true
    } else {
        $V220794 = $false
    }
} catch {
    $V220794 = $false
}


##
# V-220795
# IPv6 source routing must be configured to highest protection.
#
##
# DISCUSSION: 
# Configuring the system to disable IPv6 source routing protects against spoofing.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\
#
# Value Name: DisableIpSourceRouting
#
# Value Type: REG_DWORD
# Value: 2
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MSS (Legacy) >> "MSS:
# (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)" to
# "Highest protection, source routing is completely disabled".
#
# This policy setting requires the installation of the MSS-Legacy custom templates included with the STIG
# package.  "MSS-Legacy.admx" and " MSS-Legacy.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220795r569187_rule
# STIG ID: WN10-CC-000020
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\" -Name DisableIpSourceRouting -ErrorAction Stop) -eq 2) {
        $V220795 = $true
    } else {
        $V220795 = $false
    }
} catch {
    $V220795 = $false
}


##
# V-220796
# The system must be configured to prevent IP source routing.
#
##
# DISCUSSION: 
# Configuring the system to disable IP source routing protects against spoofing.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\
#
# Value Name: DisableIPSourceRouting
#
# Value Type: REG_DWORD
# Value: 2
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MSS (Legacy) >> "MSS:
# (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)" to "Highest
# protection, source routing is completely disabled".
#
# This policy setting requires the installation of the MSS-Legacy custom templates included with the STIG
# package.  "MSS-Legacy.admx" and " MSS-Legacy.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220796r569187_rule
# STIG ID: WN10-CC-000025
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\" -Name DisableIPSourceRouting -ErrorAction Stop) -eq 2) {
        $V220796 = $true
    } else {
        $V220796 = $false
    }
} catch {
    $V220796 = $false
}


##
# V-220799
# Local administrator accounts must have their privileged token filtered to prevent elevated privileges from
# being used over the network on domain systems.
#
##
# DISCUSSION: 
# A compromised local administrator account can provide means for an attacker to move laterally between domain
# systems.
#
# With User Account Control enabled, filtering the privileged token for built-in administrator accounts will
# prevent the elevated privileges of these accounts from being used over the network.
#
##
# CHECK: 
# If the system is not a member of a domain, this is NA.
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\
#
# Value Name: LocalAccountTokenFilterPolicy
#
# Value Type: REG_DWORD
# Value: 0x00000000 (0)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >>
# "Apply UAC restrictions to local accounts on network logons" to "Enabled".
#
# This policy setting requires the installation of the SecGuide custom templates included with the STIG package.
#  "SecGuide.admx" and "SecGuide.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220799r569187_rule
# STIG ID: WN10-CC-000037
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" -Name LocalAccountTokenFilterPolicy -ErrorAction Stop) -eq 0) {
        $V220799 = $true
    } else {
        $V220799 = $false
    }
} catch {
    $V220799 = $false
}


##
# V-220800
# WDigest Authentication must be disabled.
#
##
# DISCUSSION: 
# When the WDigest Authentication protocol is enabled, plain text passwords are stored in the Local Security
# Authority Subsystem Service (LSASS) exposing them to theft.  WDigest is disabled by default in Windows 10. 
#  This setting ensures this is enforced.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\
#
# Value Name: UseLogonCredential
#
# Type: REG_DWORD
# Value:  0x00000000 (0)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >>
# "WDigest Authentication (disabling may require KB2871997)" to "Disabled".
#
# The patch referenced in the policy title is not required for Windows 10.
#
# This policy setting requires the installation of the SecGuide custom templates included with the STIG package.
#  "SecGuide.admx" and "SecGuide.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220800r569187_rule
# STIG ID: WN10-CC-000038
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\" -Name UseLogonCredential -ErrorAction Stop) -eq 0) {
        $V220800 = $true
    } else {
        $V220800 = $false
    }
} catch {
    $V220800 = $false
}


##
# V-220801
# Run as different user must be removed from context menus.
#
##
# DISCUSSION: 
# The "Run as different user" selection from context menus allows the use of credentials other than the
# currently logged on user.  Using privileged credentials in a standard user session can expose those
# credentials to theft.  Removing this option from context menus helps prevent this from occurring.
#
##
# CHECK: 
# If the following registry values do not exist or are not configured as specified, this is a finding.
# The policy configures the same Value Name, Type and Value under four different registry paths.
#
# Registry Hive:  HKEY_LOCAL_MACHINE
# Registry Paths:  
# \SOFTWARE\Classes\batfile\shell\runasuser\
# \SOFTWARE\Classes\cmdfile\shell\runasuser\
# \SOFTWARE\Classes\exefile\shell\runasuser\
# \SOFTWARE\Classes\mscfile\shell\runasuser\
#
# Value Name:  SuppressionPolicy
#
# Type:  REG_DWORD
# Value:  0x00001000 (4096)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> MS Security Guide >>
# "Remove "Run as Different User" from context menus" to "Enabled".
#
# This policy setting requires the installation of the SecGuide custom templates included with the STIG package.
#  "SecGuide.admx" and "SecGuide.adml" must be copied to the \Windows\PolicyDefinitions and
# \Windows\PolicyDefinitions\en-US directories respectively.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220801r569187_rule
# STIG ID: WN10-CC-000039
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Classes\batfile\shell\runasuser\" -Name SuppressionPolicy -ErrorAction Stop) -eq 4096 -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Classes\cmdfile\shell\runasuser\" -Name SuppressionPolicy -ErrorAction Stop) -eq 4096 -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Classes\exefile\shell\runasuser\" -Name SuppressionPolicy -ErrorAction Stop) -eq 4096 -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Classes\mscfile\shell\runasuser\" -Name SuppressionPolicy -ErrorAction Stop) -eq 4096) {
        $V220801 = $true
    } else {
        $V220801 = $false
    }
} catch {
    $V220801 = $false
}

##
# V-220802
# Insecure logons to an SMB server must be disabled.
#
##
# DISCUSSION: 
# Insecure guest logons allow unauthenticated access to shared folders.  Shared resources on a system must
# require authentication to establish proper access.
#
##
# CHECK: 
# Windows 10 v1507 LTSB version does not include this setting; it is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\
#
# Value Name: AllowInsecureGuestAuth
#
# Type: REG_DWORD
# Value: 0x00000000 (0)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Lanman
# Workstation >> "Enable insecure guest logons" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220802r569187_rule
# STIG ID: WN10-CC-000040
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation\" -Name AllowInsecureGuestAuth -ErrorAction Stop) -eq 0) {
        $V220802 = $true
    } else {
        $V220802 = $false
    }
} catch {
    $V220802 = $false
}


##
# V-220803
# Internet connection sharing must be disabled.
#
##
# DISCUSSION: 
# Internet connection sharing makes it possible for an existing internet connection, such as through wireless,
# to be shared and used by other systems essentially creating a mobile hotspot.  This exposes the system sharing
# the connection to others with potentially malicious purpose.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Network Connections\
#
# Value Name: NC_ShowSharedAccessUI
#
# Type: REG_DWORD
# Value: 0x00000000 (0)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Network
# Connections >> "Prohibit use of Internet Connection Sharing on your DNS domain network" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220803r569187_rule
# STIG ID: WN10-CC-000044
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections\" -Name NC_ShowSharedAccessUI -ErrorAction Stop) -eq 0) {
        $V220803 = $true
    } else {
        $V220803 = $false
    }
} catch {
    $V220803 = $false
}


##
# V-220805
# Windows 10 must be configured to prioritize ECC Curves with longer key lengths first.
#
##
# DISCUSSION: 
# Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.
# By default Windows uses ECC curves with shorter key lengths first.  Requiring ECC curves with longer key
# lengths to be prioritized first helps ensure more secure algorithms are used.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\
#
# Value Name: EccCurves
#
# Value Type: REG_MULTI_SZ
# Value: NistP384 NistP256
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> SSL
# Configuration Settings >> "ECC Curve Order" to "Enabled" with "ECC Curve Order:" including the following in
# the order listed:
#
# NistP384
# NistP256
#
##
# SEVERITY: CAT II
# RULE ID: SV-220805r569187_rule
# STIG ID: WN10-CC-000052
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002\" -Name EccCurves -ErrorAction Stop) -eq "NistP384 NistP256") {
        $V220805 = $true
    } else {
        $V220805 = $false
    }
} catch {
    $V220805 = $false
}

##
# V-220806
# Simultaneous connections to the internet or a Windows domain must be limited.
#
##
# DISCUSSION: 
# Multiple network connections can provide additional attack vectors to a system and must be limited. The
# "Minimize the number of simultaneous connections to the Internet or a Windows Domain" setting prevents systems
# from automatically establishing multiple connections. When both wired and wireless connections are available,
# for example, the less-preferred connection (typically wireless) will be disconnected.
#
##
# CHECK: 
# The default behavior for "Minimize the number of simultaneous connections to the Internet or a Windows Domain"
# is "Enabled".
#
# If the registry value name below does not exist, this is not a finding.
#
# If it exists and is configured with a value of "3", this is not a finding.
#
# If it exists and is configured with a value of "0", this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\
#
# Value Name: fMinimizeConnections
#
# Value Type: REG_DWORD
# Value: 3 (or if the Value Name does not exist)
#
##
# FIX: 
# The default behavior for "Minimize the number of simultaneous connections to the Internet or a Windows Domain"
# is "Enabled".
#
# If this must be corrected, configure the policy value for Computer Configuration >> Administrative Templates
# >> Network >> Windows Connection Manager >> "Minimize the number of simultaneous connections to the Internet
# or a Windows Domain" to "Enabled". 
#
# Under "Options", set "Minimize Policy Options" to "3 = Prevent Wi-Fi When on Ethernet".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220806r890427_rule
# STIG ID: WN10-CC-000055
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\" -Name fMinimizeConnections -ErrorAction Stop) -eq 3) {
        $V220806 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\" -Name fMinimizeConnections -ErrorAction Stop) -eq 0) {
        $V220806 = $false
    } else {
        $V220806 = $false
    }
} catch {
    $V220806 = $true
}

##
# V-220807
# Connections to non-domain networks when connected to a domain authenticated network must be blocked.
#
##
# DISCUSSION: 
# Multiple network connections can provide additional attack vectors to a system and should be limited.  When
# connected to a domain, communication must go through the domain connection.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\
#
# Value Name: fBlockNonDomain
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> Windows
# Connection Manager >> "Prohibit connection to non-domain networks when connected to domain authenticated
# network" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220807r569187_rule
# STIG ID: WN10-CC-000060
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy\" -Name fBlockNonDomain -ErrorAction Stop) -eq 1) {
        $V220807 = $true
    } else {
        $V220807 = $false
    }
} catch {
    $V220807 = $false
}


##
# V-220808
# Wi-Fi Sense must be disabled.
#
##
# DISCUSSION: 
# Wi-Fi Sense automatically connects the system to known hotspots and networks that contacts have shared.  It
# also allows the sharing of the system's known networks to contacts.  Automatically connecting to hotspots and
# shared networks can expose a system to unsecured or potentially malicious systems.
#
##
# CHECK: 
# This is NA as of v1803 of Windows 10; Wi-Fi sense is no longer available.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\
#
# Value Name: AutoConnectAllowedOEM
#
# Type: REG_DWORD
# Value: 0x00000000 (0)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Network >> WLAN Service
# >> WLAN Settings>> "Allow Windows to automatically connect to suggested open hotspots, to networks shared by
# contacts, and to hotspots offering paid services" to "Disabled".   
#
# v1507 LTSB does not include this group policy setting.  It may be configured through other means such as using
# group policy from a later version of Windows 10 or a registry update.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220808r569187_rule
# STIG ID: WN10-CC-000065
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config\" -Name AutoConnectAllowedOEM -ErrorAction Stop) -eq 0) {
        $V220808 = $true
    } else {
        $V220808 = $false
    }
} catch {
    $V220808 = $false
}


##
# V-220809
# Command line data must be included in process creation events.
#
##
# DISCUSSION: 
# Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot
# service disruptions, and analyze compromises that have occurred, as well as detect attacks. Audit logs are
# necessary to provide a trail of evidence in case the system or network is compromised. Collecting this data is
# essential for analyzing the security of information assets and detecting signs of suspicious and unexpected
# behavior.
#
# Enabling "Include command line data for process creation events" will record the command line information with
# the process creation events in the log.  This can provide additional detail when malware has run on a system.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE 
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
#
# Value Name: ProcessCreationIncludeCmdLine_Enabled
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Audit Process
# Creation >> "Include command line in process creation events" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220809r569187_rule
# STIG ID: WN10-CC-000066
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\" -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction Stop) -eq 1) {
        $V220809 = $true
    } else {
        $V220809 = $false
    }
} catch {
    $V220809 = $false
}


##
# V-220810
# Windows 10 must be configured to enable Remote host allows delegation of non-exportable credentials.
#
##
# DISCUSSION: 
# An exportable version of credentials is provided to remote hosts when using credential delegation which
# exposes them to theft on the remote host.  Restricted Admin mode or Remote Credential Guard allow delegation
# of non-exportable credentials providing additional protection of the credentials.  Enabling this configures
# the host to support Restricted Admin mode or Remote Credential Guard.
#
##
# CHECK: 
# This is NA for Windows 10 LTSC\B versions 1507 and 1607.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\
#
# Value Name: AllowProtectedCreds
#
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Credentials
# Delegation >> "Remote host allows delegation of non-exportable credentials" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220810r569187_rule
# STIG ID: WN10-CC-000068
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation\" -Name AllowProtectedCreds -ErrorAction Stop) -eq 1) {
        $V220810 = $true
    } else {
        $V220810 = $false
    }
} catch {
    $V220810 = $false
}


##
# V-220813
# Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers.
#
##
# DISCUSSION: 
# By being launched first by the kernel, ELAM ( Early Launch Antimalware) is ensured to be launched before any
# third-party software, and is therefore able to detect malware in the boot process and prevent it from
# initializing.
#
##
# CHECK: 
# The default behavior is for Early Launch Antimalware - Boot-Start Driver Initialization policy is to enforce
# "Good, unknown and bad but critical" (preventing "bad").
#
# If the registry value name below does not exist, this a finding.
#
# If it exists and is configured with a value of "7", this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SYSTEM\CurrentControlSet\Policies\EarlyLaunch\
#
# Value Name: DriverLoadPolicy
#
# Value Type: REG_DWORD
# Value: 1, 3, or 8 
#
# Possible values for this setting are:
# 8 - Good only
# 1 - Good and unknown
# 3 - Good, unknown and bad but critical
# 7 - All (which includes "Bad" and would be a finding)
#
##
# FIX: 
# Ensure that Early Launch Antimalware - Boot-Start Driver Initialization policy is set to enforce "Good,
# unknown and bad but critical" (preventing "bad").
#
# If this needs to be corrected configure the policy value for Computer Configuration >> Administrative
# Templates >> System >> Early Launch Antimalware >> "Boot-Start Driver Initialization Policy" to "Enabled" with
# "Good, unknown and bad but critical" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220813r569187_rule
# STIG ID: WN10-CC-000085
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\" -Name DriverLoadPolicy -ErrorAction Stop) -in @(1,3,8)) {
        $V220813 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\" -Name DriverLoadPolicy -ErrorAction Stop) -eq 7) {
        $V220813 = $false
    } else {
        $V220813 = $false
    }
} catch {
    $V220813 = $false
}

##
# V-220814
# Group Policy objects must be reprocessed even if they have not changed.
#
##
# DISCUSSION: 
# Enabling this setting and then selecting the "Process even if the Group Policy objects have not changed"
# option ensures that the policies will be reprocessed even if none have been changed. This way, any
# unauthorized changes are forced to match the domain-based group policy settings again.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}
#
# Value Name: NoGPOListChanges
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Group Policy >>
# "Configure registry policy processing" to "Enabled" and select the option "Process even if the Group Policy
# objects have not changed".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220814r569187_rule
# STIG ID: WN10-CC-000090
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}" -Name NoGPOListChanges -ErrorAction Stop) -eq 0) {
        $V220814 = $true
    } else {
        $V220814 = $false
    }
} catch {
    $V220814 = $false
}


##
# V-220815
# Downloading print driver packages over HTTP must be prevented.
#
##
# DISCUSSION: 
# Some features may communicate with the vendor, sending system information or downloading data or components
# for the feature.  Turning off this capability will prevent potentially sensitive information from being sent
# outside the enterprise and uncontrolled updates to the system.  This setting prevents the computer from
# downloading print driver packages over HTTP.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Printers\
#
# Value Name: DisableWebPnPDownload
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Internet
# Communication Management >> Internet Communication settings >> "Turn off downloading of print drivers over
# HTTP" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220815r569187_rule
# STIG ID: WN10-CC-000100
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" -Name DisableWebPnPDownload -ErrorAction Stop) -eq 1) {
        $V220815 = $true
    } else {
        $V220815 = $false
    }
} catch {
    $V220815 = $false
}


##
# V-220816
# Web publishing and online ordering wizards must be prevented from downloading a list of providers.
#
##
# DISCUSSION: 
# Some features may communicate with the vendor, sending system information or downloading data or components
# for the feature.  Turning off this capability will prevent potentially sensitive information from being sent
# outside the enterprise and uncontrolled updates to the system.  This setting prevents Windows from downloading
# a list of providers for the Web publishing and online ordering wizards.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
#
# Value Name: NoWebServices
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Internet
# Communication Management >> Internet Communication settings >> "Turn off Internet download for Web publishing
# and online ordering wizards" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220816r569187_rule
# STIG ID: WN10-CC-000105
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name NoWebServices -ErrorAction Stop) -eq 1) {
        $V220816 = $true
    } else {
        $V220816 = $false
    }
} catch {
    $V220816 = $false
}


##
# V-220817
# Printing over HTTP must be prevented.
#
##
# DISCUSSION: 
# Some features may communicate with the vendor, sending system information or downloading data or components
# for the feature.  Turning off this capability will prevent potentially sensitive information from being sent
# outside the enterprise and uncontrolled updates to the system.  This setting prevents the client computer from
# printing over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Printers\
#
# Value Name: DisableHTTPPrinting
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Internet
# Communication Management >> Internet Communication settings >> "Turn off printing over HTTP" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220817r569187_rule
# STIG ID: WN10-CC-000110
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\" -Name DisableHTTPPrinting -ErrorAction Stop) -eq 1) {
        $V220817 = $true
    } else {
        $V220817 = $false
    }
} catch {
    $V220817 = $false
}


##
# V-220818
# Systems must at least attempt device authentication using certificates.
#
##
# DISCUSSION: 
# Using certificates to authenticate devices to the domain provides increased security over passwords.  By
# default systems will attempt to authenticate using certificates and fall back to passwords if the domain
# controller does not support certificates for devices.  This may also be configured to always use certificates
# for device authentication.
#
##
# CHECK: 
# This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is
# NA.
#
# The default behavior for "Support device authentication using certificate" is "Automatic".
#
# If the registry value name below does not exist, this is not a finding.
#
# If it exists and is configured with a value of "1", this is not a finding.
#
# If it exists and is configured with a value of "0", this is a finding.
#
# Registry Hive:  HKEY_LOCAL_MACHINE
# Registry Path:  \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\
#
# Value Name:  DevicePKInitEnabled
# Value Type:  REG_DWORD
# Value:  1 (or if the Value Name does not exist)
#
##
# FIX: 
# This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is
# NA.
#
# The default behavior for "Support device authentication using certificate" is "Automatic".
#
# If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative
# Templates >> System >> Kerberos >> "Support device authentication using certificate" to "Not Configured or
# "Enabled" with either option selected in "Device authentication behavior using certificate:".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220818r857191_rule
# STIG ID: WN10-CC-000115
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\" -Name DevicePKInitEnabled -ErrorAction Stop) -eq 1) {
        $V220818 = $true
    } else {
        $V220818 = $false
    }
} catch {
    $V220818 = $false
}


##
# V-220819
# The network selection user interface (UI) must not be displayed on the logon screen.
#
##
# DISCUSSION: 
# Enabling interaction with the network selection UI allows users to change connections to available networks
# without signing into Windows.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\
#
# Value Name: DontDisplayNetworkSelectionUI
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >> "Do
# not display network selection UI" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220819r569187_rule
# STIG ID: WN10-CC-000120
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name DontDisplayNetworkSelectionUI -ErrorAction Stop) -eq 1) {
        $V220819 = $true
    } else {
        $V220819 = $false
    }
} catch {
    $V220819 = $false
}


##
# V-220820
# Local users on domain-joined computers must not be enumerated.
#
##
# DISCUSSION: 
# The username is one part of logon credentials that could be used to gain access to a system. Preventing the
# enumeration of users limits this information to authorized personnel.
#
##
# CHECK: 
# This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is
# NA.
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\
#
# Value Name: EnumerateLocalUsers
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# This requirement is applicable to domain-joined systems. For standalone or nondomain-joined systems, this is
# NA.
#
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Logon >>
# "Enumerate local users on domain-joined computers" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220820r857194_rule
# STIG ID: WN10-CC-000130
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name EnumerateLocalUsers -ErrorAction Stop) -eq 0) {
        $V220820 = $true
    } else {
        $V220820 = $false
    }
} catch {
    $V220820 = $false
}


##
# V-220821
# Users must be prompted for a password on resume from sleep (on battery).
#
##
# DISCUSSION: 
# Authentication must always be required when accessing a system.  This setting ensures the user is prompted for
# a password on resume from sleep (on battery).
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\
#
# Value Name: DCSettingIndex
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Power
# Management >> Sleep Settings >> "Require a password when a computer wakes (on battery)" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220821r851986_rule
# STIG ID: WN10-CC-000145
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -Name DCSettingIndex -ErrorAction Stop) -eq 1) {
        $V220821 = $true
    } else {
        $V220821 = $false
    }
} catch {
    $V220821 = $false
}


##
# V-220822
# The user must be prompted for a password on resume from sleep (plugged in).
#
##
# DISCUSSION: 
# Authentication must always be required when accessing a system.  This setting ensures the user is prompted for
# a password on resume from sleep (plugged in).
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\
#
# Value Name: ACSettingIndex
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Power
# Management >> Sleep Settings >> "Require a password when a computer wakes (plugged in)" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220822r851987_rule
# STIG ID: WN10-CC-000150
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\" -Name ACSettingIndex -ErrorAction Stop) -eq 1) {
        $V220822 = $true
    } else {
        $V220822 = $false
    }
} catch {
    $V220822 = $false
}


##
# V-220824
# Unauthenticated RPC clients must be restricted from connecting to the RPC server.
#
##
# DISCUSSION: 
# Configuring RPC to restrict unauthenticated RPC clients from connecting to the RPC server will prevent
# anonymous connections.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Rpc\
#
# Value Name: RestrictRemoteClients
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Remote
# Procedure Call >> "Restrict Unauthenticated RPC clients" to "Enabled" and "Authenticated".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220824r877039_rule
# STIG ID: WN10-CC-000165
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc\" -Name RestrictRemoteClients -ErrorAction Stop) -eq 1) {
        $V220824 = $true
    } else {
        $V220824 = $false
    }
} catch {
    $V220824 = $false
}


##
# V-220830
# Enhanced anti-spoofing for facial recognition must be enabled on Window 10.
#
##
# DISCUSSION: 
# Enhanced anti-spoofing provides additional protections when using facial recognition with devices that support
# it.
#
##
# CHECK: 
# Windows 10 v1507 LTSB version does not include this setting; it is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\
#
# Value Name: EnhancedAntiSpoofing
#
# Value Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Biometrics >> Facial Features >> "Configure enhanced anti-spoofing" to "Enabled". 
#
# v1607:
# The policy name is "Use enhanced anti-spoofing when available".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220830r569187_rule
# STIG ID: WN10-CC-000195
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures\" -Name EnhancedAntiSpoofing -ErrorAction Stop) -eq 1) {
        $V220830 = $true
    } else {
        $V220830 = $false
    }
} catch {
    $V220830 = $false
}


##
# V-220832
# Administrator accounts must not be enumerated during elevation.
#
##
# DISCUSSION: 
# Enumeration of administrator accounts when elevating can provide part of the logon information to an
# unauthorized user.  This setting configures the system to always require users to type in a username and
# password to elevate a running application.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\
#
# Value Name: EnumerateAdministrators
#
# Value Type: REG_DWORD
# Value: 0
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Credential User Interface >> "Enumerate administrator accounts on elevation" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220832r569187_rule
# STIG ID: WN10-CC-000200
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\" -Name EnumerateAdministrators -ErrorAction Stop) -eq 0) {
        $V220832 = $true
    } else {
        $V220832 = $false
    }
} catch {
    $V220832 = $false
}


##
# V-220833
# If Enhanced diagnostic data is enabled it must be limited to the minimum required to support Windows
# Analytics.
#
##
# DISCUSSION: 
# Some features may communicate with the vendor, sending system information or downloading data or components
# for the feature. Limiting this capability will prevent potentially sensitive information from being sent
# outside the enterprise. The "Enhanced" level for telemetry includes additional information beyond "Security"
# and "Basic" on how Windows and apps are used and advanced reliability data. Windows Analytics can use a
# "limited enhanced" level to provide information such as health data for devices.
#
##
# CHECK: 
# This setting requires v1709 or later of Windows 10; it is NA for prior versions.
#
# If "Enhanced" level is enabled for telemetry, this must be configured. If "Security" or "Basic" are
# configured, this is NA. (See V-220834).
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DataCollection\
#
# Value Name: LimitEnhancedDiagnosticDataWindowsAnalytics
#
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Data Collection and Preview Builds >> "Limit Enhanced diagnostic data to the minimum required by Windows
# Analytics" to "Enabled" with "Enable Windows Analytics collection" selected in "Options:".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220833r793250_rule
# STIG ID: WN10-CC-000204
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -Name AllowTelemetry -ErrorAction Stop) -eq 2) {
        if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -Name LimitEnhancedDiagnosticDataWindowsAnalytics -ErrorAction Stop) -eq 1) {
            $V220833 = $true
        } else {
            $V220833 = $false
        }
    } else {
        $V220833 = $true
    }
} catch {
    $V220833 = $false
}

##
# V-220834
# Windows Telemetry must not be configured to Full.
#
##
# DISCUSSION: 
# Some features may communicate with the vendor, sending system information or downloading data or components
# for the feature. Limiting this capability will prevent potentially sensitive information from being sent
# outside the enterprise. The "Security" option for Telemetry configures the lowest amount of data, effectively
# none outside of the Malicious Software Removal Tool (MSRT), Defender and telemetry client settings. "Basic"
# sends basic diagnostic and usage data and may be required to support some Microsoft services. "Enhanced"
# includes additional information on how Windows and apps are used and advanced reliability data. Windows
# Analytics can use a "limited enhanced" level to provide information such as health data for devices.  This
# requires the configuration of an additional setting available with v1709 and later of Windows 10. 
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\DataCollection\
#
# Value Name: AllowTelemetry
#
# Type: REG_DWORD
# Value: 0x00000000 (0) (Security)
# 0x00000001 (1) (Basic)
#
# If an organization is using v1709 or later of Windows 10 this may be configured to "Enhanced" to support
# Windows Analytics. V-82145 must also be configured to limit the Enhanced diagnostic data to the minimum
# required by Windows Analytics. This registry value will then be 0x00000002 (2).
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Data Collection and Preview Builds >> "Allow Telemetry" to "Enabled" with "0 - Security [Enterprise Only]" or
# "1 - Basic" selected in "Options:".   
#
# If an organization is using v1709 or later of Windows 10 this may be configured to "2 - Enhanced" to support
# Windows Analytics. V-82145 must also be configured to limit the Enhanced diagnostic data to the minimum
# required by Windows Analytics.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220834r569187_rule
# STIG ID: WN10-CC-000205
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -Name AllowTelemetry -ErrorAction Stop) -in @(0,1)) {
        $V220834 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" -Name AllowTelemetry -ErrorAction Stop) -eq 2 -and
              $V220833 -eq $true) {
        $V220834 = $true
    } else {
        $V220834 = $false
    }
} catch {
    $V220834 = $false
}

##
# V-220836
# The Windows Defender SmartScreen for Explorer must be enabled.
#
##
# DISCUSSION: 
# Windows Defender SmartScreen helps protect systems from programs downloaded from the internet that may be
# malicious. Enabling Windows Defender SmartScreen will warn or prevent users from running potentially malicious
# programs.
#
##
# CHECK: 
# This is applicable to unclassified systems, for other systems this is NA.
#
# If the following registry values do not exist or are not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\
#
# Value Name: EnableSmartScreen
#
# Value Type: REG_DWORD
# Value: 0x00000001 (1)
#
# And
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\
#
# Value Name: ShellSmartScreenLevel
#
# Value Type: REG_SZ
# Value: Block
#
# v1607 LTSB:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\
#
# Value Name: EnableSmartScreen
#
# Value Type: REG_DWORD
# Value: 0x00000001 (1)
#
# v1507 LTSB:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\System\
#
# Value Name: EnableSmartScreen
#
# Value Type: REG_DWORD
# Value: 0x00000002 (2)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# File Explorer >> "Configure Windows Defender SmartScreen" to "Enabled" with "Warn and prevent bypass"
# selected. 
#
# Windows 10 includes duplicate policies for this setting. It can also be configured under Computer
# Configuration >> Administrative Templates >> Windows Components >> Windows Defender SmartScreen >> Explorer.
#
# v1607 LTSB:
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# File Explorer >> "Configure Windows SmartScreen" to "Enabled". (Selection options are not available.)
#
# v1507 LTSB:
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# File Explorer >> "Configure Windows SmartScreen" to "Enabled" with "Require approval from an administrator
# before running downloaded unknown software" selected.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220836r569187_rule
# STIG ID: WN10-CC-000210
# REFERENCE: 
##
try {
    if (($ComputerInfo.OsBuildNumber -eq $v1507) -and
        (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name EnableSmartScreen -ErrorAction Stop) -eq 2) {
        $V220836 = $true
    } elseif (($ComputerInfo.OsBuildNumber -eq $v1607) -and
              (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name EnableSmartScreen -ErrorAction Stop) -eq 1) {
        $V220836 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name EnableSmartScreen -ErrorAction Stop) -eq 1 -and
              (Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System\" -Name ShellSmartScreenLevel -ErrorAction Stop) -eq "Block") {
        $V220836 = $true
    } else {
        $V220836 = $false
    }
} catch {
    $V220836 = $false
}

##
# V-220837
# Explorer Data Execution Prevention must be enabled.
#
##
# DISCUSSION: 
# Data Execution Prevention (DEP) provides additional protection by performing  checks on memory to help prevent
# malicious code from running.  This setting will prevent Data Execution Prevention from being turned off for
# File Explorer.
#
##
# CHECK: 
# The default behavior is for data execution prevention to be turned on for file explorer.
#
# If the registry value name below does not exist, this is not a finding.
#
# If it exists and is configured with a value of "0", this is not a finding.
#
# If it exists and is configured with a value of "1", this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\Explorer\
#
# Value Name: NoDataExecutionPrevention
#
# Value Type: REG_DWORD
# Value: 0 (or if the Value Name does not exist)
#
##
# FIX: 
# The default behavior is for data execution prevention to be turned on for file explorer.
#
# If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative
# Templates >> Windows Components >> File Explorer >> "Turn off Data Execution Prevention for Explorer" to "Not
# Configured" or "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220837r851992_rule
# STIG ID: WN10-CC-000215
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer\" -Name NoDataExecutionPrevention -ErrorAction Stop) -eq 0) {
        $V220837 = $true
    } else {
        $V220837 = $false
    }
} catch [System.Management.Automation.ItemNotFoundException] {
    $V220837 = $true
} catch {
    $V220837 = $false
}

##
# V-220839
# File Explorer shell protocol must run in protected mode.
#
##
# DISCUSSION: 
# The shell protocol will  limit the set of folders applications can open when run in protected mode. 
#  Restricting files an application can open, to a limited set of folders, increases the security of Windows.
#
##
# CHECK: 
# The default behavior is for shell protected mode to be turned on for file explorer.
#
# If the registry value name below does not exist, this is not a finding.
#
# If it exists and is configured with a value of "0", this is not a finding.
#
# If it exists and is configured with a value of "1", this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\
#
# Value Name: PreXPSP2ShellProtocolBehavior
#
# Value Type: REG_DWORD
# Value: 0 (or if the Value Name does not exist)
#
##
# FIX: 
# The default behavior is for shell protected mode to be turned on for file explorer.
#
# If this needs to be corrected, configure the policy value for Computer Configuration >> Administrative
# Templates >> Windows Components >> File Explorer >> "Turn off shell protocol protected mode" to "Not
# Configured" or "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220839r569187_rule
# STIG ID: WN10-CC-000225
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\" -Name PreXPSP2ShellProtocolBehavior -ErrorAction Stop) -eq 0) {
        $V220839 = $true
    } else {
        $V220839 = $false
    }
} catch [System.Management.Automation.ItemNotFoundException] {
    $V220839 = $true
} catch {
    $V220839 = $false
}

##
# V-220840
# Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for malicious websites in
# Microsoft Edge.
#
##
# DISCUSSION: 
# The Windows Defender SmartScreen filter in Microsoft Edge provides warning messages and blocks potentially
# malicious websites and file downloads.  If users are allowed to ignore warnings from the Windows Defender
# SmartScreen filter they could still access malicious websites.
#
##
# CHECK: 
# This is applicable to unclassified systems, for other systems this is NA.
#
# Windows 10 LTSC\B versions do not include Microsoft Edge, this is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\
#
# Value Name: PreventOverride
#
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Microsoft Edge >> "Prevent bypassing Windows Defender SmartScreen prompts for sites" to "Enabled". 
#
# Windows 10 includes duplicate policies for this setting. It can also be configured under Computer
# Configuration >> Administrative Templates >> Windows Components >> Windows Defender SmartScreen >> Microsoft
# Edge.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220840r569187_rule
# STIG ID: WN10-CC-000230
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220840 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\" -Name PreventOverride -ErrorAction Stop) -eq 1) {
        $V220840 = $true
    } else {
        $V220840 = $false
    }
} catch {
    $V220840 = $false
}

##
# V-220841
# Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for unverified files in
# Microsoft Edge.
#
##
# DISCUSSION: 
# The Windows Defender SmartScreen filter in Microsoft Edge provides warning messages and blocks potentially
# malicious websites and file downloads.  If users are allowed to ignore warnings from the Windows Defender
# SmartScreen filter they could still download potentially malicious files.
#
##
# CHECK: 
# This is applicable to unclassified systems, for other systems this is NA.
#
# Windows 10 LTSC\B versions do not include Microsoft Edge, this is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\
#
# Value Name: PreventOverrideAppRepUnknown
#
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Microsoft Edge >> "Prevent bypassing Windows Defender SmartScreen prompts for files" to "Enabled". 
#
# Windows 10 includes duplicate policies for this setting. It can also be configured under Computer
# Configuration >> Administrative Templates >> Windows Components >> Windows Defender SmartScreen >> Microsoft
# Edge.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220841r569187_rule
# STIG ID: WN10-CC-000235
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220841 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\" -Name PreventOverrideAppRepUnknown -ErrorAction Stop) -eq 1) {
        $V220841 = $true
    } else {
        $V220841 = $false
    }
} catch {
    $V220841 = $false
}

##
# V-220842
# Windows 10 must be configured to prevent certificate error overrides in Microsoft Edge.
#
##
# DISCUSSION: 
# Web security certificates provide an indication whether a site is legitimate. This policy setting prevents the
# user from ignoring Secure Sockets Layer/Transport Layer Security (SSL/TLS) certificate errors that interrupt
# browsing.
#
##
# CHECK: 
# This setting is applicable starting with v1809 of Windows 10; it is NA for prior versions.
#
# Windows 10 LTSC\B versions do not include Microsoft Edge; this is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings\
#
# Value Name: PreventCertErrorOverrides
#
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Microsoft Edge >> "Prevent certificate error overrides" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220842r569187_rule
# STIG ID: WN10-CC-000238
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220842 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings\" -Name PreventCertErrorOverrides -ErrorAction Stop) -eq 1) {
        $V220842 = $true
    } else {
        $V220842 = $false
    }
} catch {
    $V220842 = $false
}

##
# V-220843
# The password manager function in the Edge browser must be disabled.
#
##
# DISCUSSION: 
# Passwords save locally for re-use when browsing may be subject to compromise.  Disabling the Edge password
# manager will prevent this for the browser.
#
##
# CHECK: 
# Windows 10 LTSC\B versions do not include Microsoft Edge, this is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\
#
# Value Name: FormSuggest Passwords
#
# Type: REG_SZ
# Value: no
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Microsoft Edge >> "Configure Password Manager" to "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220843r569187_rule
# STIG ID: WN10-CC-000245
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220843 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main\" -Name FormSuggest Passwords -ErrorAction Stop) -eq "no") {
        $V220843 = $true
    } else {
        $V220843 = $false
    }
} catch {
    $V220843 = $false
}

##
# V-220844
# The Windows Defender SmartScreen filter for Microsoft Edge must be enabled.
#
##
# DISCUSSION: 
# The Windows Defender SmartScreen filter in Microsoft Edge provides warning messages and blocks potentially
# malicious websites.
#
##
# CHECK: 
# This is applicable to unclassified systems, for other systems this is NA.
#
# Windows 10 LTSC\B versions do not include Microsoft Edge, this is NA for those systems.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\
#
# Value Name: EnabledV9
#
# Type: REG_DWORD
# Value: 0x00000001 (1)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Microsoft Edge >> "Configure Windows Defender SmartScreen" to "Enabled". 
#
# Windows 10 includes duplicate policies for this setting. It can also be configured under Computer
# Configuration >> Administrative Templates >> Windows Components >> Windows Defender SmartScreen >> Microsoft
# Edge.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220844r569187_rule
# STIG ID: WN10-CC-000250
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsBuildNumber -in $LTSB) {
        $V220844 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter\" -Name EnabledV9 -ErrorAction Stop) -eq 1) {
        $V220844 = $true
    } else {
        $V220844 = $false
    }
} catch {
    $V220844 = $false
}

##
# V-220845
# Windows 10 must be configured to disable Windows Game Recording and Broadcasting.
#
##
# DISCUSSION: 
# Windows Game Recording and Broadcasting is intended for use with games, however it could potentially record
# screen shots of other applications and expose sensitive data.  Disabling the feature will prevent this from
# occurring.
#
##
# CHECK: 
# This is NA for Windows 10 LTSC\B versions 1507 and 1607.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows\GameDVR\
#
# Value Name: AllowGameDVR
#
# Type: REG_DWORD
# Value: 0x00000000 (0)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Windows Game Recording and Broadcasting >> "Enables or disables Windows Game Recording and Broadcasting" to
# "Disabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220845r569187_rule
# STIG ID: WN10-CC-000252
# REFERENCE: 
##
try {
    if ($ComputerInfo.OsBuildNumber -in @($v1507, $v1607)) {
        $V220845 = $true
    } elseif ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR\" -Name AllowGameDVR -ErrorAction Stop) -eq 0) {
        $V220845 = $true
    } else {
        $V220845 = $false
    }
} catch {
    $V220845 = $false
}

##
# V-220846
# The use of a hardware security device with Windows Hello for Business must be enabled.
#
##
# DISCUSSION: 
# The use of a Trusted Platform Module (TPM) to store keys for Windows Hello for Business provides additional
# security.  Keys stored in the TPM may only be used on that system while keys stored using software are more
# susceptible to compromise and could be used on other systems.
#
##
# CHECK: 
# Virtual desktop implementations currently may not support the use of TPMs. For virtual desktop implementations
# where the virtual desktop instance is deleted or refreshed upon logoff, this is NA.
#
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\PassportForWork\
#
# Value Name: RequireSecurityDevice
#
# Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Windows Hello for Business >> "Use a hardware security device" to "Enabled". 
#
# v1507 LTSB:
# The policy path is Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft
# Passport for Work.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220846r569187_rule
# STIG ID: WN10-CC-000255
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\" -Name RequireSecurityDevice -ErrorAction Stop) -eq 1) {
        $V220846 = $true
    } else {
        $V220846 = $false
    }
} catch {
    $V220846 = $false
}


##
# V-220847
# Windows 10 must be configured to require a minimum pin length of six characters or greater.
#
##
# DISCUSSION: 
# Windows allows the use of PINs as well as biometrics for authentication without sending a password to a
# network or website where it could be compromised.  Longer minimum PIN lengths increase the available
# combinations an attacker would have to attempt.  Shorter minimum length significantly reduces the strength.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding.
#
# Registry Hive:  HKEY_LOCAL_MACHINE
# Registry Path:  \SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\
#
# Value Name:  MinimumPINLength
#
# Type:  REG_DWORD
# Value:  6 (or greater)
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> System >> PIN Complexity
# >> "Minimum PIN length" to "6" or greater. 
#
# v1607 LTSB:
# The policy path is Computer Configuration >> Administrative Templates >> Windows Components >> Windows Hello
# for Business >> Pin Complexity.
#
# v1507 LTSB:
# The policy path is Computer Configuration >> Administrative Templates >> Windows Components >> Microsoft
# Passport for Work >> Pin Complexity.
#
##
# SEVERITY: CAT II
# RULE ID: SV-220847r569187_rule
# STIG ID: WN10-CC-000260
# REFERENCE: 
##
try {
    if ($MinimumPIN) {
        $pin = $MinimumPIN
    } else {
        $pin = 6
    }
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity\" -Name MinimumPINLength -ErrorAction Stop) -ge $pin) {
        $V220847 = $true
    } else {
        $V220847 = $false
    }
} catch {
    $V220847 = $false
}

##
# V-220848
# Passwords must not be saved in the Remote Desktop Client.
#
##
# DISCUSSION: 
# Saving passwords in the Remote Desktop Client could allow an unauthorized user to establish a remote desktop
# session to another system.  The system must be configured to prevent users from saving passwords in the Remote
# Desktop Client.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\
#
# Value Name: DisablePasswordSaving
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Remote Desktop Services >> Remote Desktop Connection Client >> "Do not allow passwords to be saved" to
# "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220848r851994_rule
# STIG ID: WN10-CC-000270
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name DisablePasswordSaving -ErrorAction Stop) -eq 1) {
        $V220848 = $true
    } else {
        $V220848 = $false
    }
} catch {
    $V220848 = $false
}


##
# V-220849
# Local drives must be prevented from sharing with Remote Desktop Session Hosts.
#
##
# DISCUSSION: 
# Preventing users from sharing the local drives on their client computers to Remote Session Hosts that they
# access helps reduce possible exposure of sensitive data.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\
#
# Value Name: fDisableCdm
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Remote Desktop Services >> Remote Desktop Session Host >> Device and Resource Redirection >> "Do not allow
# drive redirection" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220849r569187_rule
# STIG ID: WN10-CC-000275
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fDisableCdm -ErrorAction Stop) -eq 1) {
        $V220849 = $true
    } else {
        $V220849 = $false
    }
} catch {
    $V220849 = $false
}


##
# V-220850
# Remote Desktop Services must always prompt a client for passwords upon connection.
#
##
# DISCUSSION: 
# This setting controls the ability of users to supply passwords automatically as part of their remote desktop
# connection.  Disabling this setting would allow anyone to use the stored credentials in a connection item to
# connect to the terminal server.
#
##
# CHECK: 
# If the following registry value does not exist or is not configured as specified, this is a finding:
#
# Registry Hive: HKEY_LOCAL_MACHINE
# Registry Path: \SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\
#
# Value Name: fPromptForPassword
#
# Value Type: REG_DWORD
# Value: 1
#
##
# FIX: 
# Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >>
# Remote Desktop Services >> Remote Desktop Session Host >> Security >> "Always prompt for password upon
# connection" to "Enabled".
#
##
# SEVERITY: CAT II
# RULE ID: SV-220850r851995_rule
# STIG ID: WN10-CC-000280
# REFERENCE: 
##
try {
    if ((Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" -Name fPromptForPassword -ErrorAction Stop) -eq 1) {
        $V220850 = $true
    } else {
        $V220850 = $false
    }
} catch {
    $V220850 = $false
}


$hash = [ordered]@{
    'V-220774' = $V220774
    'V-220775' = $V220775
    'V-220776' = $V220776
    'V-220777' = $V220777
    'V-220778' = $V220778
    'V-220779' = $V220779
    'V-220780' = $V220780
    'V-220781' = $V220781
    'V-220782' = $V220782
    'V-220783' = $V220783
    'V-220784' = $V220784
    'V-220786' = $V220786
    'V-220787' = $V220787
    'V-220788' = $V220788
    'V-220789' = $V220789
    'V-220790' = $V220790
    'V-220791' = $V220791
    'V-220792' = $V220792
    'V-220793' = $V220793
    'V-220794' = $V220794
    'V-220795' = $V220795
    'V-220796' = $V220796
    'V-220799' = $V220799
    'V-220800' = $V220800
    'V-220801' = $V220801
    'V-220802' = $V220802
    'V-220803' = $V220803
    'V-220805' = $V220805
    'V-220806' = $V220806
    'V-220807' = $V220807
    'V-220808' = $V220808
    'V-220809' = $V220809
    'V-220810' = $V220810
    'V-220813' = $V220813
    'V-220814' = $V220814
    'V-220815' = $V220815
    'V-220816' = $V220816
    'V-220817' = $V220817
    'V-220818' = $V220818
    'V-220819' = $V220819
    'V-220820' = $V220820
    'V-220821' = $V220821
    'V-220822' = $V220822
    'V-220824' = $V220824
    'V-220830' = $V220830
    'V-220832' = $V220832
    'V-220833' = $V220833
    'V-220834' = $V220834
    'V-220836' = $V220836
    'V-220837' = $V220837
    'V-220839' = $V220839
    'V-220840' = $V220840
    'V-220841' = $V220841
    'V-220842' = $V220842
    'V-220843' = $V220843
    'V-220844' = $V220844
    'V-220845' = $V220845
    'V-220846' = $V220846
    'V-220847' = $V220847
    'V-220848' = $V220848
    'V-220849' = $V220849
    'V-220850' = $V220850
}

return $hash | ConvertTo-Json -Compress
