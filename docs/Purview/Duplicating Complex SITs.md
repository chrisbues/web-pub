---
title: UntitledDuplicating Complex SITs
tags:
  - Purview
publish: true
---
In the Purview portal, entity SITs that have a large volume of patterns cannot be copied via the UI. EU National Identification Number is a good example.

To duplicate these SITs, you'll need to use PowerShell.







[System.IO.File]::WriteAllBytes('C:\custompath\exportedRules.xml', $ruleCollections.SerializedClassificationRuleCollection)


``` powershell
$rules = Get-DlpSensitiveInformationTypeRulePackage -Identity 'Microsoft Rule Package'
[System.IO.File]::WriteAllBytes('.\exportedRules.xml', $rules.SerializedClassificationRuleCollection)
```