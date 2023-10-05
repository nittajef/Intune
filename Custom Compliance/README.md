# Intune Custom Compliance (WIP)

Custom Compliance PowerShell & JSON files for Windows STIGs are located in the [STIGs subfolders](https://github.com/nittajef/Intune/tree/main/Custom%20Compliance/STIGs).

*All generated policy files are a work in progress and are not guaranteed to definitively confirm that a system is compliant with a particular STIG. There are addtional checks that need to be manually verified (denoted in the Custom Compliance policy with "-NoChk" appended to the rule name).*

Checks for CAT I and CAT III are complete. There are 2 CAT II checks, V-220709, and V-220724 left to complete, or switch to a non-checked rule.

The [Tools](https://github.com/nittajef/Intune/tree/main/Custom%20Compliance/STIGs/Tools) folder contains PowerShell scripts to help generate org-customize Intune compatible files for Custom Compliance via the STIG xccdf files.

<h1>Generator files</h1>

<h4>Convert-xccdf.ps1</h4> The main script, which will ingest the STIG file and generate matching PS and JSON files.

<h4>Org-Settings.psd1</h4> Needed to specify some file paths as well as other configuration options such as which CAT severity rules to output, as well as to specify rules that should be exempted or overrriden. For instance, you may not actually work with the DOD and not need the DOD Certificate Roots to be installed on your clients. If so, add the rules V-220903-V220906 to the "exemptions" array (one per line) in the Org-Settings file and they will be skipped.

<h4>Checks.psd1</h4> Where all of the custom PowerShell code to do the checks is stored. Most simple registry based checks are generated automatically, but any others need to be completed and stored in the Checks.psd1 file manually.

<h4>W10-W11-rule-map.csv</h4> Needed to generate Custom Compliance files for Windows 11, re-using the check logic from the Windows 10 rules. Comparing the two latest STIG releases for W10 and W11, W11 has 2 new rules (1 addtional audit rule, and an w32tm rule), and has dropped 6 rules (Edge and Explorer preview pane rules) from the W10 set.

<h1>Output files</h1>

<h2>Ready to use policy files</h2>
Policy files as close to the STIG standard for Windows 10 can be found here: [Windows 10](https://github.com/nittajef/Intune/tree/main/Custom%20Compliance/STIGs/Windows%2010)
[Windows 11](https://github.com/nittajef/Intune/tree/main/Custom%20Compliance/STIGs/Windows%2011)
<br>
They are generated with the settings set in the Org-Settings-W10.psd1 file in the same directory. Rule sets are separated by CAT severity, and the CAT II severity is broken up further because there is a current limit of 100 rules per Custom Compliance Policy. 


<h2>How to create your Custom Compliance Policy / Policy file components</h2>
<h3>PowerShell discovery script</h3>
https://learn.microsoft.com/en-us/mem/intune/protect/compliance-custom-script
<br><br>
This will be uploaded in the "Scripts" section under "Compliance policies":
<br>
<img width="405" alt="image" src="https://github.com/nittajef/Intune/assets/77274708/9c5b0d1b-68c1-4526-b976-0cb4c89f8d5d">
<br>
It contains all of the logic checks to determine if the machine meets each STIG rule. Because Custom Compliance doesn't allow for flexible matching in the JSON file, all multi-part or ranged results are evaluated within the discovery script and return a boolean true/false for whether the rule is met or not.

If you are trying to upload a discovery script and nothing seems to happen when you click the "Review + Save" button, it may because of non-Latin characters in the text. You can verify by viewing the browser's console for errors on the page.


<h3>JSON file</h3>
https://learn.microsoft.com/en-us/mem/intune/protect/compliance-custom-json
<br><br>
This file is uploaded in the Compliance policy (after uploading your script):
<br>
<img width="320" alt="image" src="https://github.com/nittajef/Intune/assets/77274708/cb3ef613-42b5-4ba4-bc03-b2392afa0d5d">
<br>
The JSON is created using only boolean checks for now, for consistency, since each Intune policy setting can only compare the return value to one "correct" value. There is a loss in being able to see the raw values returned to Intune because of this, and maybe STIG rules will be broken in to multiple sub-settings in the future (V-252903A, V-252903B, etc).
<br><br>
As of 2023-09-29 I believe these are the actual limits for Custom Compliance JSON, which don't match what MS docs say:

- Script size of 1MB (documented, doesn't seem to be true)
- Rule limit of 100 
- Script character limit of 102400/size limit of 100KB


<h2>Intune Policy</h2>
Once the two policies files are generated, you can create a new Custom Compliance policy and see results similar to the screenshots below.

If you'd like to just see how your clients stack up against the STIG rules, you can change the delay to mark devices as non-compliant to 365 (which is the max) so that you can still see which tests pass/fail, without affecting the devices compliance status.
<br>
<img width="254" alt="image" src="https://github.com/nittajef/Intune/assets/77274708/479d7102-6923-4523-825c-b35fdf954a9a">
<br>

Device policy view:

<img width="341" alt="image" src="https://github.com/nittajef/Intune/assets/77274708/ca4b73fa-e416-4727-a30e-3c0087609394">

Per setting view from the policy configuration:

<img width="347" alt="image" src="https://github.com/nittajef/Intune/assets/77274708/d17e6974-a7a3-46a8-a7c6-5025c767c159">


<h2>Change Log</h2>

2023-10-05

- Uploaded generated default policy files with rule/setting names instead of just the STIG ID as name

2023-09-29

- Fixed CAT I rule V-220963, which had $true/$false values switched

2023-09-28

- Added rule mapping for Windows 10 to Windows 11 ID names
- First pass at generating rules for [Windows 11](https://github.com/nittajef/Intune/tree/main/Custom%20Compliance/STIGs/Windows%2011), CAT I and CAT III are posted

2023-09-26

- Fixed CAT III checks V-220977, V-220973, V-220965, V-220956, and CAT I check V-220958, which were checking for empty set of privilege assignment by empty string "", but needed to check against $null value.
- Fixed CAT II check V-220749, wrong value was being set when registry key didn't exist
- Modified unfinished CAT II checks V-220709 and V-220724 to return $true for now so they don't return $null and error out the PS script in Intune

2023-09-25

- Added flag to exclude "Reference" data in output JSON (to reduce file size with current 100KB limit)
- Completed CAT II checks: 
  - V-220903 - Override added to verify other/non-DOD roots
  - V-220904
  - V-220905
  - V-220906
  - V-220717 (extra verification welcome)
  - V-220723 - searches only local drives with drive letters (extra verification welcome)
  - V-220957
- Fixed CAT I checks:
  - V-220958 - check was switched from CAT II check V-220957
