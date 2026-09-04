$group = ""

$groupName   = Get-ADGroup $group | Select-Object Name
$description = Get-ADGroup $group -Properties Description | Select-Object Description

$members = Get-ADGroupMember $group -Recursive |
    Where-Object {$_.objectClass -eq "user"} |
    Get-ADUser -Properties DisplayName |
    Select-Object DisplayName |
    Sort-Object DisplayName

Write-Host ($groupName.Name) "---" ($description.Description)
Write-Output ""
Write-Output ($members.DisplayName)
