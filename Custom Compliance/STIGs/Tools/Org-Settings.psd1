@{
    # Settings imported in to Convert-xccdf.ps1 policy generator
    InputSTIGFile = "C:\stig.xccdf"
    InputChecksFile = "C:\checks.psd1"

    # Select which severity rules to generate policy for
    CAT1 = $true
    CAT2 = $false
    CAT3 = $false

    # JSON output to upload in to Intune Custom Compliance policy
    # Style:   verbose - Put STIG rule "Discussion" section in to Remediation Description
    #          mini - 
    #          debug - Change description to show rule evaluation values in Company Portal
    # NoCheck: include - Keep rules with no technical checks in compliance policy (append rule name w/NoChk)
    #          exclude - Remove rules with no technical checks from compliance policy
    #
    OutputJSONFile = "C:\stig.json"
    JSONFileStyle = "debug"
    JSONFileInfoURL = "https://contoso.com"
    JSONFileNoCheckRules = "include"

    # PowerShell output to upload as script in Intune Custom Compliance
    # Style:   verbose - Add all of the STIG rule comments (Discussion, Check, Fix)
    #          mini - 
    #          zen - Only include STIG rule title
    OutputPSFile = "C:\stig.ps1"
    PSFileStyle = ""

    # List all accounts that should not be evaluated in STIG rule checks
    LocalAdminAccounts = "root"
    LocalBackupOperatorAccounts = ""
    LocalHyperVAdminAccounts = ""

    # Overrides - Settings here will override respective STIG rule values
    #             Rules with overrides will be indicated with trailing -OVR
    'V-220706' = @{
        LatestServicingLevel = "23H2"
    }
    
    AllNodes = @(
        @{
            NodeName = 'DSC-01'
        }
        @{
            NodeName = 'DSC-02'
        }
    )
}
