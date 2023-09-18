# Intune Custom Compliance

Custom Compliance PowerShell & JSON files for Windows STIGs are located in the subfolders.

The Tools folder contains PowerShell scripts to help generate Intune compatible files for Custom Compliance via the STIG xccdf filess.

You'll need 3 files to run the generator:

<h4>Convert-xccdf.ps1</h4> The main script, which will ingest the STIG file and generate matching PS and JSON files.

<h4>Org-Settings.psd1</h4> Needed to specify some file paths as well as other configuration options such as which CAT severity rules to outupt,
as well as to specify rules that should be skipped or overrriden.

<h4>Checks.psd1</h4> Where all of the custom PowerShell code to do the checks is stored. Most simple registry based checks are generated automatically,
but any others need to be completed and stored in the Checks.psd1 file manually.

Once the two policies files are generated, you can create a new Custom Compliance policy and see results similar to this:

Device policy view:

<img width="491" alt="image" src="https://github.com/nittajef/Intune/assets/77274708/45710655-5432-4b58-b182-86fbb637e104">

Per setting view from the policy configuration:

<img width="489" alt="image" src="https://github.com/nittajef/Intune/assets/77274708/423a7153-5b04-421c-9a1e-f50df7aee02e">
