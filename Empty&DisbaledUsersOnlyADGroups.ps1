param (
    [Parameter(Mandatory = $true)]
    [string]$SearchBase,  # e.g. "OU=Security Groups,DC=domain,DC=com"

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\AD_Empty_DisabledGroups.csv"
)

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "Discovering AD groups in $SearchBase..." -ForegroundColor Cyan

$groups = Get-ADGroup -Filter * -SearchBase $SearchBase -Properties Description, DistinguishedName

$result = @()

foreach ($group in $groups) {

    $groupName = $group.Name
    $description = $group.Description
    $dn = $group.DistinguishedName

    # Extract OU Path
    $ouPath = ($dn -split ',', 2)[1]

    try {
        $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction Stop
    }
    catch {
        continue
    }

    # Case 1: Empty group
    if (-not $members) {
        $result += [PSCustomObject]@{
            Name         = $groupName
            Description  = $description
            OUPath       = $ouPath
            DisabledOnly = $false
            Status       = "Empty"
        }
        continue
    }

    # Only user members
    $userMembers = $members | Where-Object { $_.objectClass -eq "user" }

    if (-not $userMembers) {
        continue
    }

    $enabledUsers = 0
    $disabledUsers = 0

    foreach ($user in $userMembers) {
        try {
            $u = Get-ADUser -Identity $user.SamAccountName -Properties Enabled
            if ($u.Enabled) {
                $enabledUsers++
            } else {
                $disabledUsers++
            }
        }
        catch {
            continue
        }
    }

    # Case 2: Disabled-only group
    if ($enabledUsers -eq 0 -and $disabledUsers -gt 0) {
        $result += [PSCustomObject]@{
            Name         = $groupName
            Description  = $description
            OUPath       = $ouPath
            DisabledOnly = $true
            Status       = "Disabled-Only"
        }
    }
}

Write-Host "Exporting results to CSV..." -ForegroundColor Green

$result | Sort-Object Status, Name |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Done. Output saved to $OutputPath" -ForegroundColor Green