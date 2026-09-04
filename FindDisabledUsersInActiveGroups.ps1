param (
    [Parameter(Mandatory = $true)]
    [string]$SearchBase,  # e.g. "DC=domain,DC=com"

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\DisabledUsers_InActiveGroups.csv"
)

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "Collecting disabled users..." -ForegroundColor Cyan

# Get all disabled users
$disabledUsers = Get-ADUser -Filter { Enabled -eq $false } `
    -SearchBase $SearchBase `
    -Properties MemberOf, DistinguishedName

$result = @()

foreach ($user in $disabledUsers) {

    $userName = $user.SamAccountName
    $userDN   = $user.DistinguishedName

    # Skip users with no group memberships
    if (-not $user.MemberOf) {
        continue
    }

    foreach ($groupDN in $user.MemberOf) {

        try {
            $group = Get-ADGroup -Identity $groupDN -Properties Description, DistinguishedName
        }
        catch {
            continue
        }

        # Check if group has members (i.e., is "active")
        try {
            $members = Get-ADGroupMember -Identity $groupDN -ErrorAction Stop
        }
        catch {
            continue
        }

        if (-not $members) {
            # Skip empty groups
            continue
        }

        # Extract OU path
        $ouPath = ($group.DistinguishedName -split ',', 2)[1]

        $result += [PSCustomObject]@{
            UserName        = $userName
            UserDN          = $userDN
            GroupName       = $group.Name
            GroupDescription= $group.Description
            GroupOUPath     = $ouPath
        }
    }
}

Write-Host "Exporting results to CSV..." -ForegroundColor Green

$result | Sort-Object UserName, GroupName |
    Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8

Write-Host "Done. Output saved to $OutputPath" -ForegroundColor Green