@{
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
    
    OutputPSFile = "C:\stig.ps1"
    PSFileStyle = ""

    # List all accounts that should not be evaluated in STIG rule checks
    LocalAdminAccounts = "root"
    LocalBackupOperatorAccounts = ""
    LocalHyperVAdminAccounts = ""
    
    AllNodes = @(
        @{
            NodeName = 'DSC-01'
        }
        @{
            NodeName = 'DSC-02'
        }
    )
}
