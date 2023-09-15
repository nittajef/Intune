$OrgSettings = Import-PowerShellDataFile "Org-Settings.psd1"
$RuleChecks = Import-PowerShellDataFile $OrgSettings.input.Checks
[xml]$stig = Get-Content -Path $OrgSettings.input.STIG -Encoding UTF8

$checks = @()
$results = [ordered]@{}

$header = @(
    "# " + $stig.Benchmark.title
    "# Version: " + $stig.Benchmark.version + ", " + $stig.Benchmark.'plain-text'.'#text'[0]+ "`r`n`r`n"
)

$checks += $header

function Generate-CCPolicy() {
    $rules = @()

    foreach ($rule in $stig.Benchmark.Group.Rule) {
        # Continue if rule is in a CAT category specified above
        if (($OrgSettings.severity.CAT1 -and $rule.severity -eq "high") -or
            ($OrgSettings.severity.CAT2 -and $rule.severity -eq "medium") -or
            ($OrgSettings.severity.CAT3 -and $rule.severity -eq "low")) {
        } else {
            continue
        }

        $settingName = $rule.id.Substring(1,8)

        if ($OrgSettings.nocode -contains $settingName) {
            if ($OrgSettings.output.JSONNoCheckRules -eq "exclude") {
                continue
            } else {
                $settingName = $settingName + "-NoChk"
            }
        }

        # Fill out reference section of entry, which is not used by Intune CC
        $reference = [ordered]@{}
        $reference.Add('Severity', $rule.severity)
        $reference.Add('Rule_ID', $rule.id)
        $reference.Add('STIG_ID', $rule.version)

        $cciId = @()
        $legacyId = @() 

        foreach ($ident in $rule.ident) {
            if ($ident.system -eq 'http://cyber.mil/cci') {
                $cciId += $ident.'#text'
            } elseif ($ident.system -eq 'http://cyber.mil/legacy') {
                $legacyId += $ident.'#text'
            }
        }
        if ($cciId.Count -gt 0) {$reference.Add('CCI', $cciId -join ',')}
        if ($legacyId.Count -gt 0) {$reference.Add('Legacy_IDs', $legacyId -join ',')}

        $description = switch ($OrgSettings.output.JSONStyle) {
                           "description" { [regex]::Matches($rule.description,'<VulnDiscussion>([\s\S]*)</VulnDiscussion>').Groups[1].Value }
                           "fix"    { $rule.fixtext.'#text' }
                           "debug"   { "Rule check return value: {ActualValue}" } # Need to adjust PS check returns to make this useful
                       }
        $setting = [ordered]@{
                        SettingName = $settingName
                        Operator = "IsEquals"
                        DataType = "Boolean"
                        Operand = $true
                        MoreInfoUrl = $OrgSettings.output.JSONInfoURL
                        RemediationStrings = @(([ordered]@{
                            Language = "en_US"
                            Title = $settingName + " - " + $rule.title
                            Description = $description
                        }))
                        Reference = $reference
                    }
        $rules += $setting
    }

    @{"Rules" = $rules}
}

function Format-Text ($input_txt) {
    # Replace non-Latin characters that Intune doesn't like
    $input_txt = $input_txt -replace ('â€œ|â€', '"')
    $input_txt = $input_txt -replace ('â€¦', '...')
    $input_txt = $input_txt -replace ('â„¢', '')
    $input_txt = $input_txt -replace ('â€“', '-')

    foreach ($sub_txt in $input_txt) {
        if ($sub_txt -eq "`n") {
            # Add the blank lines back in for spacing
            $formatted_text += "#`r`n"
        } else {
            $sub_txt = [regex]::Matches($sub_txt,'(?<=\s|^)(.{1,110})(?=\s|$)')
            foreach ($snip in $sub_txt) {
                $formatted_text += "# " + $snip.Groups[1].Value + "`r`n"
            }
        }
        $formatted_text += "#`r`n"
    }

    # Remove last extra blank line
    $formatted_text = $formatted_text.TrimEnd("`r`n")

    $formatted_text
}

if ($RuleChecks.gather_info) {
    $checks += $RuleChecks.gather_info + "`r`n"
}

$EmptyRules = 0

# Iterate through all rules in the STIG document
foreach ($rule in $stig.Benchmark.Group.Rule) {
    # Continue if rule is in a CAT category specified above
    if (($OrgSettings.severity.CAT1 -and $rule.severity -eq "high") -or
        ($OrgSettings.severity.CAT2 -and $rule.severity -eq "medium") -or
        ($OrgSettings.severity.CAT3 -and $rule.severity -eq "low")) {
    } else {
        continue
    }

    $ruleId = $rule.id.Substring(1,8)

    if ($OrgSettings.nocode -contains $ruleId) {
        if ($OrgSettings.output.JSONNoCheckRules -eq "exclude") {
            continue
        }
    }

    # Create rule comments (title, description, check, fix, ids)
    # Split description/check/fix fields by blank lines to preserver spacing
    $formatted_title = Format-Text($rule.title)
    # Match text in VulnDiscussion section, but remove the VulnDiscussion tags
    $desc_txt = [regex]::Matches($rule.description,'<VulnDiscussion>([\s\S]*)</VulnDiscussion>').Groups[1].Value
    $formatted_description = Format-Text($desc_txt -split "(?:\r?\n){2,}")
    $formatted_check = Format-Text($rule.check.'check-content' -split "(?:\r?\n){2,}")
    $formatted_fix = Format-Text($rule.fixtext.'#text' -split "(?:\r?\n){2,}")
    # Convert severity to CAT I/II/III
    $severity = switch ($rule.severity) {
                    "low" {"CAT III"}
                    "medium" {"CAT II"}
                    "high" {"CAT I"}
                }

    # Try to auto create checks for rules with registry values
    # $regchecks holds a collection of individual registry checks, some rules have multiple
    $regChecks = [System.Collections.ArrayList]@()
    $regCheck = @()
    foreach ($line in $rule.check.'check-content'.Split("`n")) {
        if ($line.Contains("Registry Hive")) {
            $hive = switch -regex ($line) {
                'Registry Hive:\s+HKEY_LOCAL_MACHINE' { "HKLM:" }
                'Registry Hive:\s+HKEY_CURRENT_USER' { "HKCU:" }
                default { $null }
            }
        } elseif ($line.Contains("Registry Path:")) {
            $regPath = $line -replace 'Registry Path:\s+', "".Trim()
        } elseif ($line.Contains("Value Name:")) {
            $regName = $line -replace 'Value Name:\s+', "".Trim()
        } elseif ($line.Contains("Value:")) {
            # Match these: Value: 0x00000001 (1) (Enabled with UEFI lock)
            #              Value: 1
            if ($line.TrimEnd() -match '0x.{8}\s+\((\d+)\)') {
                $regValue = $Matches[1]
            } elseif ($line.TrimEnd() -match "(?m)Value:\s+(\d+)$") {
                $regValue = $Matches[1]
            }
            $regCheck = $hive, $regPath, $regName, $regValue
            $regChecks.Add($regCheck) | Out-Null
        }
    }

    # Create check rule logic template
    $ruleVarName = $ruleId -replace "-"

    # Load custom check logic if exists from .psd1 file
    # Create simple registry check logic if created above
    # Or create blank try/catch template to be filled in manually
    if ($RuleChecks.$ruleId) {
        $check_template = $RuleChecks.$ruleId
    }
    elseif ($regchecks) {
        # Template for the PowerShell registry check for the rule
        $psRegChecks = "    if ("
        foreach ($regCheck in $regChecks) {
            $psRegChecks += "(Get-ItemPropertyValue -Path `""+ $regCheck[0] + $regCheck[1] + "`" -Name " + $regCheck[2] + " -ErrorAction Stop) -eq " + $regCheck[3] + " -and`r`n        "
        }
        # Replace last entries "-and" and close the "if" conditional
        $psRegChecks = $psRegChecks.TrimEnd(" -and`r`n")
        $psRegChecks += ") {"

        $check_template = @(
            "try {"
                $psRegChecks
            "        $" + $ruleVarName + ' = $true'
            "    } else {"
            "        $" + $ruleVarName + ' = $false'
            "    }"
            "} catch {"
            "    $" + $ruleVarName + ' = $false'
            "}`r`n"
        ) -join "`r`n"
    } elseif ($OrgSettings.nocode -contains $ruleId) {
        $ruleId = $ruleId + "-NoChk"
        $check_template = @(
            "$" + $ruleVarName + ' = $true'
        ) -join "`r`n"
    } else {
        $check_template = @(
            "try {"
            "    "
            "    #$" + $ruleVarName + ' = $true'
            "} catch {"
            "    $" + $ruleVarName + ' = $false'
            "}`r`n`r`n"
        ) -join "`r`n"
        $i++
    }

    # Output full check/logic test text for each rule
    $check = "##`r`n"
    $check += "# " + $ruleId + "`r`n"
    $check += $formatted_title + "`r`n"
    if ($OrgSettings.output.PSStyle -eq 'verbose') {
        $check += "##`r`n"
        $check += "# DISCUSSION: `r`n"
        $check += $formatted_description + "`r`n"
    }
    if ($OrgSettings.output.PSStyle -eq 'verbose') {
        $check += "##`r`n"
        $check += "# CHECK: `r`n"
        $check += $formatted_check + "`r`n"
    }
    if ($OrgSettings.output.PSStyle -eq 'verbose') {
        $check += "##`r`n"
        $check += "# FIX: `r`n"
        $check += $formatted_fix + "`r`n"
    }
    if ($OrgSettings.output.PSStyle -ne 'zen') {
        $check += "##`r`n"
        $check += "# SEVERITY: " + $severity + "`r`n"
        $check += "# RULE ID: " + $rule.id + "`r`n"
        $check += "# STIG ID: " + $rule.version + "`r`n"
        $check += "# REFERENCE: `r`n"
    }
    $check += "##`r`n"
    $check += $check_template + "`r`n"

    $checks += $check
    $results.Add($ruleId, "$" + $ruleVarName)
}

# Create the return hash of check values
$ret_hash = '$hash = [ordered]@{' + "`r`n"
foreach ($key in $results.Keys) {
    $ret_hash += "    '" + $key + "' = " + $($results[$key]) + "`r`n"
}
$ret_hash += "}`r`n`r`n"
$ret_hash += 'return $hash | ConvertTo-Json -Compress'
$checks += $ret_hash  

Generate-CCPolicy | ConvertTo-Json -Depth 4 | Out-File $OrgSettings.output.JSON
$checks | Out-File -FilePath $OrgSettings.output.PS
Write-Host("$EmptyRules empty rule checks")
