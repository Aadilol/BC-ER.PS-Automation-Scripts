#requires -Version 5.1
#requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Read-only Active Directory security-group cleanup and auditing.

.DESCRIPTION
    Performs a read-only audit of Active Directory security groups.

    The script does NOT modify Active Directory.

    Audit areas:
      - Empty security groups
      - Group metadata/naming issues
      - Nested security groups
      - Excessive nesting depth
      - Circular nesting
      - Duplicate direct members
      - Redundant access paths
      - Disabled/inactive direct user members
      - Exact duplicate group memberships
      - Near-duplicate group memberships
      - Effective membership similarity
      - Traversal safety limits
      - Query failures

    Designed for Windows PowerShell 5.1 and the Microsoft ActiveDirectory module.

.NOTES
    Read-only with respect to Active Directory.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [AllowEmptyString()]
    [string]$SearchBase = '',

    [Parameter(Mandatory = $false)]
    [AllowEmptyString()]
    [string]$Server = '',

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = 'C:\Temp\ADSecurityGroupAudit',

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100)]
    [int]$DeepNestingThreshold = 5,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 3650)]
    [int]$InactiveUserDays = 120,

    [Parameter(Mandatory = $false)]
    [ValidateRange(0.50, 1.00)]
    [double]$NearDuplicateThreshold = 0.90,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 1000000)]
    [int]$TraversalStateLimit = 50000,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 1000)]
    [int]$MaxPathsPerUserGroup = 20,

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100000)]
    [int]$DuplicateCandidateLimit = 100,

    [Parameter(Mandatory = $false)]
    [switch]$IncludeEffectiveMembershipComparison
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# COLLECTION INITIALIZATION
# ---------------------------------------------------------------------------

$emptyFindings = [System.Collections.Generic.List[object]]::new()
$redundantGroupFindings = [System.Collections.Generic.List[object]]::new()
$nestedFindings = [System.Collections.Generic.List[object]]::new()
$depthFindings = [System.Collections.Generic.List[object]]::new()
$cycleFindings = [System.Collections.Generic.List[object]]::new()
$redundantAccessFindings = [System.Collections.Generic.List[object]]::new()
$accountFindings = [System.Collections.Generic.List[object]]::new()
$namingFindings = [System.Collections.Generic.List[object]]::new()
$duplicateFindings = [System.Collections.Generic.List[object]]::new()
$queryErrorFindings = [System.Collections.Generic.List[object]]::new()
$traversalLimitFindings = [System.Collections.Generic.List[object]]::new()

$auditErrors = [System.Collections.Generic.List[string]]::new()

# ---------------------------------------------------------------------------
# GLOBAL STATE
# ---------------------------------------------------------------------------

$groupByDn = @{}
$groupInfoByDn = @{}
$directMembersByGroup = @{}
$directMemberInfoByGroup = @{}
$userCache = @{}
$effectiveMembershipCache = @{}

$script:AuditStart = Get-Date
$script:DomainName = ''
$script:DomainDN = ''
$script:GroupEnumerationSucceeded = $false

# ---------------------------------------------------------------------------
# FUNCTIONS
# ---------------------------------------------------------------------------

function Add-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$List,

        [Parameter(Mandatory = $true)]
        [hashtable]$Data
    )

    if ($null -eq $List) {
        throw 'Add-Finding received a null collection.'
    }

    $List.Add([pscustomobject]$Data) | Out-Null
}

function Add-AuditError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Stage,

        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [System.Exception]$Exception
    )

    $timestamp = (Get-Date).ToString('s')

    $message = '{0} | Stage={1} | Identity={2} | Error={3}' -f `
        $timestamp,
        $Stage,
        $Identity,
        $Exception.Message

    $auditErrors.Add($message) | Out-Null

    Add-Finding -List $queryErrorFindings -Data @{
        Timestamp = $timestamp
        Stage     = $Stage
        Identity  = $Identity
        Error     = $Exception.Message
        Exception = $Exception.GetType().FullName
    }
}

function Get-SafeProperty {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    if ($null -eq $Object) {
        return $null
    }

    try {
        $property = $Object.PSObject.Properties[$PropertyName]

        if ($null -eq $property) {
            return $null
        }

        return $property.Value
    }
    catch {
        return $null
    }
}

function Get-SafeString {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return ''
    }

    try {
        return [string]$Value
    }
    catch {
        return ''
    }
}

function Get-DNKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Object
    )

    $dn = Get-SafeProperty -Object $Object -PropertyName 'DistinguishedName'

    if ($null -eq $dn) {
        return ''
    }

    return (Get-SafeString $dn).Trim().ToLowerInvariant()
}

function Get-ObjectName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Object
    )

    $name = Get-SafeProperty -Object $Object -PropertyName 'Name'

    if ($null -ne $name) {
        return (Get-SafeString $name)
    }

    $dn = Get-DNKey -Object $Object

    if ($dn -ne '') {
        $firstPart = ($dn -split ',', 2)[0]

        if ($firstPart -match '^CN=(.*)$') {
            return $matches[1]
        }

        if ($firstPart -match '^OU=(.*)$') {
            return $matches[1]
        }
    }

    return ''
}

function Normalize-Name {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return ''
    }

    $normalized = $Name.ToLowerInvariant()

    $normalized = $normalized -replace '[^a-z0-9]+', ' '
    $normalized = $normalized -replace '\s+', ' '
    $normalized = $normalized.Trim()

    return $normalized
}

function Get-NameTokens {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Name
    )

    $normalized = Normalize-Name -Name $Name

    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return @()
    }

    return @(
        $normalized -split '\s+' |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            } |
            Select-Object -Unique
    )
}

function Get-JaccardSimilarity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [object[]]$SetA,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [object[]]$SetB
    )

    $arrayA = @($SetA)
    $arrayB = @($SetB)

    $countA = @($arrayA).Count
    $countB = @($arrayB).Count

    if ($countA -eq 0 -and $countB -eq 0) {
        return 1.0
    }

    if ($countA -eq 0 -or $countB -eq 0) {
        return 0.0
    }

    $hashA = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    $hashB = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($item in $arrayA) {
        if ($null -ne $item) {
            [void]$hashA.Add((Get-SafeString $item))
        }
    }

    foreach ($item in $arrayB) {
        if ($null -ne $item) {
            [void]$hashB.Add((Get-SafeString $item))
        }
    }

    $intersectionCount = 0

    foreach ($item in $hashA) {
        if ($hashB.Contains($item)) {
            $intersectionCount++
        }
    }

    $unionCount = $hashA.Count + $hashB.Count - $intersectionCount

    if ($unionCount -eq 0) {
        return 1.0
    }

    return [double]$intersectionCount / [double]$unionCount
}

function Get-MembershipSignature {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [object[]]$MemberDNs
    )

    $members = @(
        $MemberDNs |
            ForEach-Object {
                if ($null -ne $_) {
                    (Get-SafeString $_).Trim().ToLowerInvariant()
                }
            } |
            Where-Object {
                -not [string]::IsNullOrWhiteSpace($_)
            } |
            Sort-Object -Unique
    )

    if (@($members).Count -eq 0) {
        return '<EMPTY>'
    }

    return [string]::Join('|', $members)
}

function Get-DescriptionText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Object
    )

    $description = Get-SafeProperty -Object $Object -PropertyName 'Description'

    if ($null -eq $description) {
        return ''
    }

    if ($description -is [System.Array]) {
        return [string]::Join(' ', @($description))
    }

    return Get-SafeString $description
}

function Test-DescriptionContainsSignal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    $pattern = '\b(reserved|emergency|break[\s-]?glass|placeholder|future|deny|exclude|protected|dynamic|do not delete|dont delete|do not remove|system|default)\b'

    return ($Text -match $pattern)
}

function Test-ProtectedNamingPattern {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }

    $pattern = '(^|[-_ ]+)(admin|administrator|domain admins|enterprise admins|schema admins|builtin|system|default|protected|deny|exclude|breakglass|break-glass|emergency)([-_ ]+|$)'

    return ($Name -match $pattern)
}

function Test-UnusualGroupName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Name
    )

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }

    return ($Name -match '[^\x20-\x7E]')
}

function Get-OUOrContainer {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DistinguishedName
    )

    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) {
        return ''
    }

    $parts = $DistinguishedName -split ','

    if (@($parts).Count -le 1) {
        return ''
    }

    return [string]::Join(',', @($parts)[1..(@($parts).Count - 1)])
}

function Export-FindingCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if ($null -eq $InputObject) {
        throw 'Export-FindingCsv received a null collection.'
    }

    if ($InputObject.Count -gt 0) {
        @($InputObject) | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
    }
}

function Invoke-ADQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory = $true)]
        [string]$Stage,

        [Parameter(Mandatory = $true)]
        [string]$Identity
    )

    try {
        return @(& $ScriptBlock)
    }
    catch {
        Add-AuditError `
            -Stage $Stage `
            -Identity $Identity `
            -Exception $_.Exception

        return $null
    }
}

function Get-EffectiveUsersForGroup {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$RootDN
    )

    $rootKey = $RootDN.Trim().ToLowerInvariant()

    if ($effectiveMembershipCache.ContainsKey($rootKey)) {
        return $effectiveMembershipCache[$rootKey]
    }

    $users = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    $stack = [System.Collections.Generic.Stack[object]]::new()

    $initialPath = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    [void]$initialPath.Add($rootKey)

    $stack.Push(
        [pscustomobject]@{
            CurrentDN = $rootKey
            PathDNs   = @($rootKey)
            Visited   = $initialPath
        }
    )

    $states = 0

    while ($stack.Count -gt 0) {

        $state = $stack.Pop()

        if ($null -eq $state) {
            continue
        }

        $states++

        if ($states -ge $TraversalStateLimit) {
            break
        }

        $currentDN = Get-SafeString (
            Get-SafeProperty -Object $state -PropertyName 'CurrentDN'
        )

        if ([string]::IsNullOrWhiteSpace($currentDN)) {
            continue
        }

        $memberInfo = $null

        if ($directMemberInfoByGroup.ContainsKey($currentDN)) {
            $memberInfo = $directMemberInfoByGroup[$currentDN]
        }

        foreach ($member in @($memberInfo)) {

            if ($null -eq $member) {
                continue
            }

            $memberDN = Get-SafeString (
                Get-SafeProperty -Object $member -PropertyName 'DistinguishedName'
            )

            if ([string]::IsNullOrWhiteSpace($memberDN)) {
                continue
            }

            $memberKey = $memberDN.Trim().ToLowerInvariant()

            $isGroup = $false

            if ($groupByDn.ContainsKey($memberKey)) {
                $isGroup = $true
            }

            if ($isGroup) {

                $visited = Get-SafeProperty `
                    -Object $state `
                    -PropertyName 'Visited'

                if ($null -eq $visited) {
                    continue
                }

                if ($visited.Contains($memberKey)) {
                    continue
                }

                $nextVisited = [System.Collections.Generic.HashSet[string]]::new(
                    [System.StringComparer]::OrdinalIgnoreCase
                )

                foreach ($visitedDN in @($visited)) {
                    [void]$nextVisited.Add((Get-SafeString $visitedDN))
                }

                [void]$nextVisited.Add($memberKey)

                $currentPath = @(
                    Get-SafeProperty -Object $state -PropertyName 'PathDNs'
                )

                $nextPath = @(
                    $currentPath + $memberKey
                )

                $stack.Push(
                    [pscustomobject]@{
                        CurrentDN = $memberKey
                        PathDNs   = $nextPath
                        Visited   = $nextVisited
                    }
                )
            }
            else {
                [void]$users.Add($memberKey)
            }
        }
    }

    $effectiveMembershipCache[$rootKey] = $users

    return $users
}

# ---------------------------------------------------------------------------
# OUTPUT DIRECTORY
# ---------------------------------------------------------------------------

try {
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
}
catch {
    throw "Could not create output directory '$OutputPath'. Error: $($_.Exception.Message)"
}

$auditErrorLogPath = Join-Path $OutputPath 'AuditErrors.log'

# ---------------------------------------------------------------------------
# DOMAIN INFORMATION
# ---------------------------------------------------------------------------

try {
    if ([string]::IsNullOrWhiteSpace($Server)) {
        $domain = Get-ADDomain -ErrorAction Stop
    }
    else {
        $domain = Get-ADDomain -Server $Server -ErrorAction Stop
    }

    $script:DomainName = Get-SafeString (
        Get-SafeProperty -Object $domain -PropertyName 'DNSRoot'
    )

    $script:DomainDN = Get-SafeString (
        Get-SafeProperty -Object $domain -PropertyName 'DistinguishedName'
    )
}
catch {
    throw "Unable to query Active Directory domain information. Verify the ActiveDirectory module, domain connectivity, domain controller, and read permissions. Error: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# STAGE 1 - GROUP ENUMERATION
# ---------------------------------------------------------------------------

Write-Host 'Discovering Active Directory security groups...' -ForegroundColor Cyan

$groups = @()

try {
    $groupParams = @{
        Filter      = 'GroupCategory -eq "Security"'
        Properties  = @(
            'Description',
            'ManagedBy',
            'adminCount',
            'isCriticalSystemObject',
            'GroupScope',
            'GroupCategory',
            'whenCreated',
            'whenChanged'
        )
        ErrorAction = 'Stop'
    }

    if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
        $groupParams['SearchBase'] = $SearchBase
    }

    if (-not [string]::IsNullOrWhiteSpace($Server)) {
        $groupParams['Server'] = $Server
    }

    $groups = @(Get-ADGroup @groupParams)

    $script:GroupEnumerationSucceeded = $true
}
catch {
    throw @"
Initial security-group enumeration failed.

Verify:
  - SearchBase: $SearchBase
  - Domain naming context: $script:DomainDN
  - Domain controller / Server: $Server
  - Microsoft ActiveDirectory PowerShell module
  - Read permissions

Error: $($_.Exception.Message)
"@
}

Write-Host ('Total groups: {0}' -f @($groups).Count) -ForegroundColor Gray

# ---------------------------------------------------------------------------
# BUILD GROUP INDEX
# ---------------------------------------------------------------------------

$groupIndex = 0

foreach ($group in @($groups)) {

    $groupIndex++

    if (($groupIndex % 100) -eq 0) {
        Write-Progress `
            -Activity 'Indexing security groups' `
            -Status ('{0} / {1}' -f $groupIndex, @($groups).Count) `
            -PercentComplete ([int](($groupIndex / [double]([math]::Max(1, @($groups).Count))) * 100))
    }

    if ($null -eq $group) {
        continue
    }

    $dn = Get-DNKey -Object $group
    $name = Get-ObjectName -Object $group

    if ([string]::IsNullOrWhiteSpace($dn)) {
        Add-AuditError `
            -Stage 'Group Enumeration' `
            -Identity $name `
            -Exception ([System.Exception]::new('Group has no DistinguishedName property.'))

        continue
    }

    $groupByDn[$dn] = $group

    $groupInfoByDn[$dn] = [pscustomobject]@{
        DistinguishedName     = $dn
        Name                  = $name
        Description           = Get-DescriptionText -Object $group
        ManagedBy             = Get-SafeString (
            Get-SafeProperty -Object $group -PropertyName 'ManagedBy'
        )
        AdminCount            = Get-SafeProperty -Object $group -PropertyName 'adminCount'
        IsCriticalSystemObject = Get-SafeProperty -Object $group -PropertyName 'isCriticalSystemObject'
        GroupScope            = Get-SafeString (
            Get-SafeProperty -Object $group -PropertyName 'GroupScope'
        )
        GroupCategory         = Get-SafeString (
            Get-SafeProperty -Object $group -PropertyName 'GroupCategory'
        )
        OU                    = Get-OUOrContainer -DistinguishedName $dn
    }
}

Write-Progress -Activity 'Indexing security groups' -Completed

# ---------------------------------------------------------------------------
# STAGE 2 - DIRECT MEMBERSHIP ENUMERATION
# ---------------------------------------------------------------------------

Write-Host 'Checking empty groups and metadata...' -ForegroundColor Cyan

$groupCounter = 0

foreach ($group in @($groups)) {

    $groupCounter++

    $dn = Get-DNKey -Object $group

    if ([string]::IsNullOrWhiteSpace($dn)) {
        continue
    }

    $name = Get-ObjectName -Object $group

    if (($groupCounter % 50) -eq 0) {
        Write-Progress `
            -Activity 'Checking direct group membership' `
            -Status ('{0} / {1}: {2}' -f $groupCounter, @($groups).Count, $name) `
            -PercentComplete ([int](($groupCounter / [double]([math]::Max(1, @($groups).Count))) * 100))
    }

    $members = $null
    $querySucceeded = $false

    try {

        $memberParams = @{
            Identity    = $dn
            ErrorAction = 'Stop'
        }

        if (-not [string]::IsNullOrWhiteSpace($Server)) {
            $memberParams['Server'] = $Server
        }

        $members = @(Get-ADGroupMember @memberParams)

        $querySucceeded = $true
    }
    catch {
        Add-AuditError `
            -Stage 'Get-ADGroupMember' `
            -Identity $dn `
            -Exception $_.Exception

        continue
    }

    if (-not $querySucceeded) {
        continue
    }

    $memberDNs = [System.Collections.Generic.List[string]]::new()
    $memberObjects = [System.Collections.Generic.List[object]]::new()

    foreach ($member in @($members)) {

        if ($null -eq $member) {
            continue
        }

        $memberDN = Get-SafeString (
            Get-SafeProperty -Object $member -PropertyName 'DistinguishedName'
        )

        if ([string]::IsNullOrWhiteSpace($memberDN)) {
            continue
        }

        $memberKey = $memberDN.Trim().ToLowerInvariant()

        $memberDNs.Add($memberKey) | Out-Null

        $memberName = Get-ObjectName -Object $member

        if ([string]::IsNullOrWhiteSpace($memberName)) {
            $memberName = $memberKey
        }

        $memberObjects.Add(
            [pscustomobject]@{
                DistinguishedName = $memberKey
                Name              = $memberName
                ObjectClass       = Get-SafeProperty -Object $member -PropertyName 'objectClass'
            }
        ) | Out-Null
    }

    $directMembersByGroup[$dn] = @($memberDNs)
    $directMemberInfoByGroup[$dn] = @($memberObjects)

    # ---------------------------------------------------------------
    # EMPTY GROUP
    # ---------------------------------------------------------------

    if (@($memberDNs).Count -eq 0) {

        $description = Get-DescriptionText -Object $group

        $managedBy = Get-SafeString (
            Get-SafeProperty -Object $group -PropertyName 'ManagedBy'
        )

        $adminCount = Get-SafeProperty `
            -Object $group `
            -PropertyName 'adminCount'

        $critical = Get-SafeProperty `
            -Object $group `
            -PropertyName 'isCriticalSystemObject'

        $intentionalSignals = [System.Collections.Generic.List[string]]::new()

        if ($critical -eq $true) {
            $intentionalSignals.Add('isCriticalSystemObject=True') | Out-Null
        }

        if ($null -ne $adminCount -and (Get-SafeString $adminCount) -eq '1') {
            $intentionalSignals.Add('adminCount=1') | Out-Null
        }

        if (-not [string]::IsNullOrWhiteSpace($managedBy)) {
            $intentionalSignals.Add('managedBy is populated') | Out-Null
        }

        if (Test-DescriptionContainsSignal -Text $description) {
            $intentionalSignals.Add('description contains a potentially intentional-use keyword') | Out-Null
        }

        if (Test-ProtectedNamingPattern -Name $name) {
            $intentionalSignals.Add('name resembles a protected/system/emergency group') | Out-Null
        }

        $reason = 'No direct members were returned by a successful membership query. Human review required.'

        if ($intentionalSignals.Count -gt 0) {
            $reason = 'Empty group has signals that it may be intentionally maintained: ' +
                ([string]::Join('; ', @($intentionalSignals)))
        }

        Add-Finding -List $emptyFindings -Data @{
            Name                  = $name
            DistinguishedName     = $dn
            OU                    = Get-OUOrContainer -DistinguishedName $dn
            ManagedBy             = $managedBy
            AdminCount            = Get-SafeString $adminCount
            IsCriticalSystemObject = Get-SafeString $critical
            Description           = $description
            IntentionalUseSignals = [string]::Join('; ', @($intentionalSignals))
            ReasonForFlagging     = $reason
            Recommendation        = 'Review manually. Do not automatically delete.'
        }
    }

    # ---------------------------------------------------------------
    # METADATA / NAMING
    # ---------------------------------------------------------------

    $description = Get-DescriptionText -Object $group

    $managedBy = Get-SafeString (
        Get-SafeProperty -Object $group -PropertyName 'ManagedBy'
    )

    $issues = [System.Collections.Generic.List[string]]::new()

    if ([string]::IsNullOrWhiteSpace($description)) {
        $issues.Add('Missing description') | Out-Null
    }

    if ([string]::IsNullOrWhiteSpace($managedBy)) {
        $issues.Add('Missing managedBy owner') | Out-Null
    }

    if ($name -ne $name.Trim()) {
        $issues.Add('Leading or trailing spaces') | Out-Null
    }

    if ($name -match '\s{2,}') {
        $issues.Add('Repeated spaces') | Out-Null
    }

    if (Test-UnusualGroupName -Name $name) {
        $issues.Add('Unusual/non-ASCII characters') | Out-Null
    }

    if ($name.Length -gt 64) {
        $issues.Add('Excessively long group name') | Out-Null
    }

    if ($issues.Count -gt 0) {

        Add-Finding -List $namingFindings -Data @{
            Name              = $name
            DistinguishedName = $dn
            OU                = Get-OUOrContainer -DistinguishedName $dn
            Issues            = [string]::Join('; ', @($issues))
            Description       = $description
            ManagedBy         = $managedBy
            Recommendation    = 'Review naming and metadata manually.'
        }
    }
}

Write-Progress -Activity 'Checking direct group membership' -Completed

# ---------------------------------------------------------------------------
# IDENTICAL NORMALIZED DESCRIPTIONS / NAMES
# ---------------------------------------------------------------------------

Write-Host 'Checking normalized names and descriptions...' -ForegroundColor Cyan

$nameBuckets = @{}
$descriptionBuckets = @{}

foreach ($group in @($groups)) {

    if ($null -eq $group) {
        continue
    }

    $dn = Get-DNKey -Object $group

    if (-not $groupInfoByDn.ContainsKey($dn)) {
        continue
    }

    $info = $groupInfoByDn[$dn]

    $normalizedName = Normalize-Name -Name (
        Get-SafeString (
            Get-SafeProperty -Object $info -PropertyName 'Name'
        )
    )

    if (-not [string]::IsNullOrWhiteSpace($normalizedName)) {

        if (-not $nameBuckets.ContainsKey($normalizedName)) {
            $nameBuckets[$normalizedName] = [System.Collections.Generic.List[string]]::new()
        }

        $nameBuckets[$normalizedName].Add($dn) | Out-Null
    }

    $description = Get-SafeString (
        Get-SafeProperty -Object $info -PropertyName 'Description'
    )

    $normalizedDescription = Normalize-Name -Name $description

    if (-not [string]::IsNullOrWhiteSpace($normalizedDescription)) {

        if (-not $descriptionBuckets.ContainsKey($normalizedDescription)) {
            $descriptionBuckets[$normalizedDescription] = [System.Collections.Generic.List[string]]::new()
        }

        $descriptionBuckets[$normalizedDescription].Add($dn) | Out-Null
    }
}

foreach ($bucketKey in @($nameBuckets.Keys)) {

    $bucket = @($nameBuckets[$bucketKey])

    if (@($bucket).Count -lt 2) {
        continue
    }

    for ($i = 0; $i -lt @($bucket).Count; $i++) {

        for ($j = $i + 1; $j -lt @($bucket).Count; $j++) {

            $a = $bucket[$i]
            $b = $bucket[$j]

            $infoA = $groupInfoByDn[$a]
            $infoB = $groupInfoByDn[$b]

            Add-Finding -List $namingFindings -Data @{
                Name              = Get-SafeString (Get-SafeProperty $infoA 'Name')
                DistinguishedName = $a
                OU                = Get-SafeString (Get-SafeProperty $infoA 'OU')
                Issues            = 'Identical normalized group name with another group'
                RelatedGroup      = Get-SafeString (Get-SafeProperty $infoB 'Name')
                RelatedDN         = $b
                Description       = Get-SafeString (Get-SafeProperty $infoA 'Description')
                ManagedBy         = Get-SafeString (Get-SafeProperty $infoA 'ManagedBy')
                Recommendation    = 'Review whether the similarly named groups serve distinct purposes.'
            }
        }
    }
}

foreach ($bucketKey in @($descriptionBuckets.Keys)) {

    $bucket = @($descriptionBuckets[$bucketKey])

    if (@($bucket).Count -lt 2) {
        continue
    }

    for ($i = 0; $i -lt @($bucket).Count; $i++) {

        for ($j = $i + 1; $j -lt @($bucket).Count; $j++) {

            $a = $bucket[$i]
            $b = $bucket[$j]

            $infoA = $groupInfoByDn[$a]
            $infoB = $groupInfoByDn[$b]

            Add-Finding -List $namingFindings -Data @{
                Name              = Get-SafeString (Get-SafeProperty $infoA 'Name')
                DistinguishedName = $a
                OU                = Get-SafeString (Get-SafeProperty $infoA 'OU')
                Issues            = 'Identical normalized description with another group'
                RelatedGroup      = Get-SafeString (Get-SafeProperty $infoB 'Name')
                RelatedDN         = $b
                Description       = Get-SafeString (Get-SafeProperty $infoA 'Description')
                ManagedBy         = Get-SafeString (Get-SafeProperty $infoA 'ManagedBy')
                Recommendation    = 'Review whether the groups have overlapping purpose.'
            }
        }
    }
}

# ---------------------------------------------------------------------------
# STAGE 3 - NESTING / CYCLES
# ---------------------------------------------------------------------------

Write-Host 'Traversing nested group relationships...' -ForegroundColor Cyan

$rootCounter = 0

foreach ($rootGroup in @($groups)) {

    $rootCounter++

    $rootDN = Get-DNKey -Object $rootGroup

    if ([string]::IsNullOrWhiteSpace($rootDN)) {
        continue
    }

    $rootName = Get-ObjectName -Object $rootGroup

    if (($rootCounter % 25) -eq 0) {
        Write-Progress `
            -Activity 'Traversing nested group relationships' `
            -Status ('{0} / {1}: {2}' -f $rootCounter, @($groups).Count, $rootName) `
            -PercentComplete ([int](($rootCounter / [double]([math]::Max(1, @($groups).Count))) * 100))
    }

    $stack = [System.Collections.Generic.Stack[object]]::new()

    $rootState = [pscustomobject]@{
        CurrentDN = $rootDN
        PathDNs   = @($rootDN)
        PathNames = @($rootName)
        Depth     = 0
    }

    $stack.Push($rootState)

    $stateCount = 0
    $maxDepth = 0
    $limitReached = $false

    while ($stack.Count -gt 0) {

        $state = $stack.Pop()

        if ($null -eq $state) {
            continue
        }

        $stateCount++

        if ($stateCount -ge $TraversalStateLimit) {
            $limitReached = $true
            break
        }

        $currentDN = Get-SafeString (
            Get-SafeProperty -Object $state -PropertyName 'CurrentDN'
        )

        $pathDNs = @(
            Get-SafeProperty -Object $state -PropertyName 'PathDNs'
        )

        $pathNames = @(
            Get-SafeProperty -Object $state -PropertyName 'PathNames'
        )

        $depthValue = Get-SafeProperty `
            -Object $state `
            -PropertyName 'Depth'

        $depth = 0

        if ($null -ne $depthValue) {
            try {
                $depth = [int]$depthValue
            }
            catch {
                $depth = 0
            }
        }

        if ($depth -gt $maxDepth) {
            $maxDepth = $depth
        }

        $children = @()

        if ($directMemberInfoByGroup.ContainsKey($currentDN)) {
            $children = @(
                $directMemberInfoByGroup[$currentDN] |
                    Where-Object {
                        $memberDN = Get-SafeString (
                            Get-SafeProperty $_ 'DistinguishedName'
                        )

                        $memberKey = $memberDN.Trim().ToLowerInvariant()

                        $groupByDn.ContainsKey($memberKey)
                    }
            )
        }

        foreach ($child in @($children)) {

            $childDN = Get-SafeString (
                Get-SafeProperty $child 'DistinguishedName'
            )

            if ([string]::IsNullOrWhiteSpace($childDN)) {
                continue
            }

            $childKey = $childDN.Trim().ToLowerInvariant()

            $childName = Get-ObjectName -Object $child

            if ([string]::IsNullOrWhiteSpace($childName)) {
                if ($groupByDn.ContainsKey($childKey)) {
                    $childName = Get-ObjectName -Object $groupByDn[$childKey]
                }
            }

            $nextDepth = [int]$depth + 1

            # -----------------------------------------------------------
            # DIRECT NESTED RELATIONSHIP
            # -----------------------------------------------------------

            Add-Finding -List $nestedFindings -Data @{
                ParentGroup           = $rootName
                ParentDistinguishedName = $rootDN
                ChildGroup            = $childName
                ChildDistinguishedName = $childKey
                DirectRelationship    = $true
                ParentOU              = Get-OUOrContainer $rootDN
                ChildOU               = Get-OUOrContainer $childKey
                DepthFromRoot         = $nextDepth
                Path                  = [string]::Join(
                    ' -> ',
                    @($pathNames + $childName)
                )
            }

            # -----------------------------------------------------------
            # CYCLE DETECTION
            # -----------------------------------------------------------

            $cycleIndex = -1

            for ($pathIndex = 0; $pathIndex -lt @($pathDNs).Count; $pathIndex++) {

                $existingDN = Get-SafeString $pathDNs[$pathIndex]

                if ($existingDN -eq $childKey) {
                    $cycleIndex = $pathIndex
                    break
                }
            }

            if ($cycleIndex -ge 0) {

                $cycleNames = @()

                for ($cyclePathIndex = $cycleIndex; `
                     $cyclePathIndex -lt @($pathNames).Count; `
                     $cyclePathIndex++) {

                    $cycleNames += $pathNames[$cyclePathIndex]
                }

                $cycleNames += $childName

                Add-Finding -List $cycleFindings -Data @{
                    RootGroup           = $rootName
                    RootDistinguishedName = $rootDN
                    CyclePath           = [string]::Join(
                        ' -> ',
                        @($cycleNames)
                    )
                    CycleDistinguishedNames = [string]::Join(
                        ' -> ',
                        @($pathDNs[$cycleIndex..(@($pathDNs).Count - 1)] + $childKey)
                    )
                    DepthDetected       = $nextDepth
                    Recommendation      = 'Review circular nesting immediately.'
                }

                continue
            }

            # -----------------------------------------------------------
            # EXCESSIVE DEPTH
            # -----------------------------------------------------------

            if ($nextDepth -ge $DeepNestingThreshold) {

                Add-Finding -List $depthFindings -Data @{
                    RootGroup             = $rootName
                    RootDistinguishedName = $rootDN
                    Depth                 = $nextDepth
                    Path                  = [string]::Join(
                        ' -> ',
                        @($pathNames + $childName)
                    )
                    Recommendation        = 'Review whether the nesting depth is necessary.'
                }
            }

            # -----------------------------------------------------------
            # CONTINUE TRAVERSAL
            # -----------------------------------------------------------

            $nextPathDNs = @($pathDNs + $childKey)
            $nextPathNames = @($pathNames + $childName)

            $stack.Push(
                [pscustomobject]@{
                    CurrentDN = $childKey
                    PathDNs   = $nextPathDNs
                    PathNames = $nextPathNames
                    Depth     = $nextDepth
                }
            )
        }
    }

    if ($limitReached) {

        Add-Finding -List $traversalLimitFindings -Data @{
            RootGroup             = $rootName
            RootDistinguishedName = $rootDN
            TraversalStateLimit   = $TraversalStateLimit
            StatesProcessed       = $stateCount
            MaximumDepthObserved  = $maxDepth
            Reason                = 'Traversal state limit reached. Results for this root may be incomplete.'
            Recommendation        = 'Review group nesting complexity and rerun with a higher limit if appropriate.'
        }
    }

    # ---------------------------------------------------------------
    # ROOT DEPTH SUMMARY
    # ---------------------------------------------------------------

    if ($maxDepth -ge $DeepNestingThreshold) {

        Add-Finding -List $depthFindings -Data @{
            RootGroup             = $rootName
            RootDistinguishedName = $rootDN
            Depth                 = $maxDepth
            Path                  = '(maximum depth observed for root)'
            Recommendation        = 'Review whether the nesting depth is necessary.'
        }
    }
}

Write-Progress -Activity 'Traversing nested group relationships' -Completed

# ---------------------------------------------------------------------------
# STAGE 4 - DIRECT USER / ACCOUNT AUDIT
# ---------------------------------------------------------------------------

Write-Host 'Checking inactive users...' -ForegroundColor Cyan

$inactiveCutoff = (Get-Date).AddDays(-1 * $InactiveUserDays)

$userCounter = 0

foreach ($group in @($groups)) {

    $userCounter++

    $groupDN = Get-DNKey -Object $group

    if ([string]::IsNullOrWhiteSpace($groupDN)) {
        continue
    }

    $groupName = Get-ObjectName -Object $group

    $memberInfo = @()

    if ($directMemberInfoByGroup.ContainsKey($groupDN)) {
        $memberInfo = @($directMemberInfoByGroup[$groupDN])
    }

    foreach ($member in @($memberInfo)) {

        if ($null -eq $member) {
            continue
        }

        $memberDN = Get-SafeString (
            Get-SafeProperty $member 'DistinguishedName'
        )

        if ([string]::IsNullOrWhiteSpace($memberDN)) {
            continue
        }

        $memberKey = $memberDN.Trim().ToLowerInvariant()

        # Groups are handled elsewhere.
        if ($groupByDn.ContainsKey($memberKey)) {
            continue
        }

        if ($userCache.ContainsKey($memberKey)) {
            $userInfo = $userCache[$memberKey]
        }
        else {

            $userInfo = $null

            try {

                $userParams = @{
                    Identity    = $memberKey
                    Properties  = @(
                        'Enabled',
                        'lastLogonTimestamp',
                        'DisplayName',
                        'SamAccountName',
                        'UserPrincipalName'
                    )
                    ErrorAction = 'Stop'
                }

                if (-not [string]::IsNullOrWhiteSpace($Server)) {
                    $userParams['Server'] = $Server
                }

                $user = Get-ADUser @userParams

                if ($null -ne $user) {

                    $enabledValue = Get-SafeProperty $user 'Enabled'

                    $lastLogonRaw = Get-SafeProperty `
                        $user `
                        'lastLogonTimestamp'

                    $lastLogon = $null

                    if ($null -ne $lastLogonRaw) {

                        try {

                            if ($lastLogonRaw -is [System.Array]) {
                                $lastLogonRaw = @($lastLogonRaw)[0]
                            }

                            $lastLogonInt64 = [int64]$lastLogonRaw

                            if ($lastLogonInt64 -gt 0) {
                                $lastLogon = [DateTime]::FromFileTimeUtc(
                                    $lastLogonInt64
                                ).ToLocalTime()
                            }
                        }
                        catch {
                            $lastLogon = $null
                        }
                    }

                    $userInfo = [pscustomobject]@{
                        Found             = $true
                        DistinguishedName = $memberKey
                        Name              = Get-ObjectName $user
                        SamAccountName    = Get-SafeString (
                            Get-SafeProperty $user 'SamAccountName'
                        )
                        DisplayName       = Get-SafeString (
                            Get-SafeProperty $user 'DisplayName'
                        )
                        UserPrincipalName = Get-SafeString (
                            Get-SafeProperty $user 'UserPrincipalName'
                        )
                        Enabled           = $enabledValue
                        LastLogon         = $lastLogon
                    }
                }
            }
            catch {
                Add-AuditError `
                    -Stage 'Get-ADUser' `
                    -Identity $memberKey `
                    -Exception $_.Exception

                $userInfo = [pscustomobject]@{
                    Found             = $false
                    DistinguishedName = $memberKey
                    Name              = Get-ObjectName $member
                    SamAccountName    = ''
                    DisplayName       = ''
                    UserPrincipalName = ''
                    Enabled           = $null
                    LastLogon         = $null
                }
            }

            $userCache[$memberKey] = $userInfo
        }

        if ($null -eq $userInfo) {
            continue
        }

        $found = Get-SafeProperty $userInfo 'Found'

        if ($found -ne $true) {
            continue
        }

        $enabled = Get-SafeProperty $userInfo 'Enabled'
        $lastLogon = Get-SafeProperty $userInfo 'LastLogon'

        $reasons = [System.Collections.Generic.List[string]]::new()

        if ($enabled -eq $false) {
            $reasons.Add('Disabled account') | Out-Null
        }

        if ($null -eq $lastLogon) {
            $reasons.Add('Missing/invalid replicated lastLogonTimestamp') | Out-Null
        }
        elseif ($lastLogon -lt $inactiveCutoff) {
            $reasons.Add(
                ('lastLogonTimestamp older than {0} days' -f $InactiveUserDays)
            ) | Out-Null
        }

        if ($reasons.Count -gt 0) {

            Add-Finding -List $accountFindings -Data @{
                UserName             = Get-SafeString (Get-SafeProperty $userInfo 'Name')
                SamAccountName       = Get-SafeString (Get-SafeProperty $userInfo 'SamAccountName')
                UserPrincipalName    = Get-SafeString (Get-SafeProperty $userInfo 'UserPrincipalName')
                UserDistinguishedName = $memberKey
                ParentGroup          = $groupName
                ParentGroupDN        = $groupDN
                Enabled              = Get-SafeString $enabled
                LastLogonTimestamp   = if ($null -eq $lastLogon) { '' } else { $lastLogon.ToString('s') }
                InactivityThreshold  = $InactiveUserDays
                Reasons              = [string]::Join('; ', @($reasons))
                Recommendation       = 'Investigate manually. lastLogonTimestamp is replicated and is not definitive proof of account inactivity.'
            }
        }
    }

    if (($userCounter % 50) -eq 0) {

        Write-Progress `
            -Activity 'Checking inactive direct user members' `
            -Status ('{0} / {1}: {2}' -f $userCounter, @($groups).Count, $groupName) `
            -PercentComplete ([int](($userCounter / [double]([math]::Max(1, @($groups).Count))) * 100))
    }
}

Write-Progress -Activity 'Checking inactive direct user members' -Completed

# ---------------------------------------------------------------------------
# STAGE 5 - DUPLICATE DIRECT MEMBER DETECTION
# ---------------------------------------------------------------------------

Write-Host 'Comparing memberships...' -ForegroundColor Cyan

$membershipSignatureBuckets = @{}

foreach ($groupDN in @($directMembersByGroup.Keys)) {

    $memberDNs = @($directMembersByGroup[$groupDN])

    $signature = Get-MembershipSignature -MemberDNs $memberDNs

    if (-not $membershipSignatureBuckets.ContainsKey($signature)) {
        $membershipSignatureBuckets[$signature] = [System.Collections.Generic.List[string]]::new()
    }

    $membershipSignatureBuckets[$signature].Add($groupDN) | Out-Null
}

# Exact duplicate membership detection.
foreach ($signature in @($membershipSignatureBuckets.Keys)) {

    $bucket = @($membershipSignatureBuckets[$signature])

    if (@($bucket).Count -lt 2) {
        continue
    }

    # Important:
    # Do not treat multiple empty groups as duplicate groups.
    if ($signature -eq '<EMPTY>') {
        continue
    }

    for ($i = 0; $i -lt @($bucket).Count; $i++) {

        for ($j = $i + 1; $j -lt @($bucket).Count; $j++) {

            $groupADN = $bucket[$i]
            $groupBDN = $bucket[$j]

            $groupAInfo = $groupInfoByDn[$groupADN]
            $groupBInfo = $groupInfoByDn[$groupBDN]

            $membersA = @($directMembersByGroup[$groupADN])
            $membersB = @($directMembersByGroup[$groupBDN])

            Add-Finding -List $redundantGroupFindings -Data @{
                GroupA               = Get-SafeString (Get-SafeProperty $groupAInfo 'Name')
                GroupADistinguishedName = $groupADN
                GroupB               = Get-SafeString (Get-SafeProperty $groupBInfo 'Name')
                GroupBDistinguishedName = $groupBDN
                MembershipType       = 'Identical direct membership'
                GroupAMemberCount    = @($membersA).Count
                GroupBMemberCount    = @($membersB).Count
                MembershipSimilarity = 1.0
                NameSimilarity       = Get-JaccardSimilarity `
                    -SetA (Get-NameTokens (Get-SafeString (Get-SafeProperty $groupAInfo 'Name'))) `
                    -SetB (Get-NameTokens (Get-SafeString (Get-SafeProperty $groupBInfo 'Name')))
                DescriptionSimilarity = Get-JaccardSimilarity `
                    -SetA (Get-NameTokens (Get-SafeString (Get-SafeProperty $groupAInfo 'Description'))) `
                    -SetB (Get-NameTokens (Get-SafeString (Get-SafeProperty $groupBInfo 'Description')))
                WhyFlagged           = 'Both groups have the same direct member DN set.'
                Recommendation       = 'Review whether one group is redundant before considering any administrative action.'
            }
        }
    }
}

# ---------------------------------------------------------------------------
# NEAR DUPLICATE CANDIDATE BUCKETING
# ---------------------------------------------------------------------------

Write-Host 'Comparing direct memberships (optimized)...' -ForegroundColor Cyan
Write-Host ('Total groups: {0}' -f @($groups).Count) -ForegroundColor Gray

$candidateBuckets = @{}

foreach ($groupDN in @($directMembersByGroup.Keys)) {

    $info = $groupInfoByDn[$groupDN]

    $name = Get-SafeString (Get-SafeProperty $info 'Name')
    $tokens = @(Get-NameTokens -Name $name)

    $memberCount = @(
        $directMembersByGroup[$groupDN]
    ).Count

    # A group can be compared against similarly-sized groups.
    # The normalized name token provides a useful candidate bucket.
    $bucketKeys = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    foreach ($token in @($tokens)) {
        [void]$bucketKeys.Add(
            ('TOKEN:{0}' -f $token)
        )
    }

    # Also bucket by membership size so groups with wildly different
    # membership counts are not needlessly compared.
    $sizeBucket = [int][math]::Floor($memberCount / 10)

    [void]$bucketKeys.Add(
        ('SIZE:{0}' -f $sizeBucket)
    )

    foreach ($bucketKey in @($bucketKeys)) {

        if (-not $candidateBuckets.ContainsKey($bucketKey)) {
            $candidateBuckets[$bucketKey] = [System.Collections.Generic.List[string]]::new()
        }

        $candidateBuckets[$bucketKey].Add($groupDN) | Out-Null
    }
}

$comparedPairs = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)

$duplicateComparisonCounter = 0

foreach ($bucketKey in @($candidateBuckets.Keys)) {

    $candidateGroups = @(
        $candidateBuckets[$bucketKey]
    )

    if (@($candidateGroups).Count -lt 2) {
        continue
    }

    # Prevent pathological buckets from exploding.
    if (@($candidateGroups).Count -gt $DuplicateCandidateLimit) {
        $candidateGroups = @(
            $candidateGroups |
                Select-Object -First $DuplicateCandidateLimit
        )
    }

    for ($i = 0; $i -lt @($candidateGroups).Count; $i++) {

        for ($j = $i + 1; $j -lt @($candidateGroups).Count; $j++) {

            $groupADN = Get-SafeString $candidateGroups[$i]
            $groupBDN = Get-SafeString $candidateGroups[$j]

            if ($groupADN -eq $groupBDN) {
                continue
            }

            $pairKeyParts = @(
                $groupADN
                $groupBDN
            ) | Sort-Object

            $pairKey = [string]::Join('|', @($pairKeyParts))

            if ($comparedPairs.Contains($pairKey)) {
                continue
            }

            [void]$comparedPairs.Add($pairKey)

            $duplicateComparisonCounter++

            if (($duplicateComparisonCounter % 1000) -eq 0) {
                Write-Progress `
                    -Activity 'Comparing potential duplicate groups' `
                    -Status ('Pairs evaluated: {0}' -f $duplicateComparisonCounter)
            }

            $membersA = @($directMembersByGroup[$groupADN])
            $membersB = @($directMembersByGroup[$groupBDN])

            $memberCountA = @($membersA).Count
            $memberCountB = @($membersB).Count

            if ($memberCountA -eq 0 -and $memberCountB -eq 0) {
                continue
            }

            $maximumSize = [math]::Max(
                $memberCountA,
                $memberCountB
            )

            $sizeDifference = [math]::Abs(
                $memberCountA - $memberCountB
            )

            if ($maximumSize -gt 0) {

                $sizeDifferenceRatio = (
                    [double]$sizeDifference /
                    [double]$maximumSize
                )

                # If the membership counts differ dramatically,
                # Jaccard similarity cannot realistically be high.
                if ($sizeDifferenceRatio -gt (1.0 - $NearDuplicateThreshold)) {
                    continue
                }
            }

            $membershipSimilarity = Get-JaccardSimilarity `
                -SetA $membersA `
                -SetB $membersB

            if ($membershipSimilarity -lt $NearDuplicateThreshold) {
                continue
            }

            $infoA = $groupInfoByDn[$groupADN]
            $infoB = $groupInfoByDn[$groupBDN]

            $nameSimilarity = Get-JaccardSimilarity `
                -SetA (Get-NameTokens (Get-SafeString (Get-SafeProperty $infoA 'Name'))) `
                -SetB (Get-NameTokens (Get-SafeString (Get-SafeProperty $infoB 'Name')))

            $descriptionSimilarity = Get-JaccardSimilarity `
                -SetA (Get-NameTokens (Get-SafeString (Get-SafeProperty $infoA 'Description'))) `
                -SetB (Get-NameTokens (Get-SafeString (Get-SafeProperty $infoB 'Description')))

            $why = 'Direct membership similarity meets the configured threshold.'

            if ($nameSimilarity -ge 0.50) {
                $why += ' Normalized names are also similar.'
            }

            if ($descriptionSimilarity -ge 0.50) {
                $why += ' Descriptions are also similar.'
            }

            Add-Finding -List $redundantGroupFindings -Data @{
                GroupA                  = Get-SafeString (Get-SafeProperty $infoA 'Name')
                GroupADistinguishedName = $groupADN
                GroupB                  = Get-SafeString (Get-SafeProperty $infoB 'Name')
                GroupBDistinguishedName = $groupBDN
                MembershipType          = 'Near-duplicate direct membership'
                GroupAMemberCount       = $memberCountA
                GroupBMemberCount       = $memberCountB
                MembershipSimilarity    = [math]::Round($membershipSimilarity, 4)
                NameSimilarity          = [math]::Round($nameSimilarity, 4)
                DescriptionSimilarity   = [math]::Round($descriptionSimilarity, 4)
                WhyFlagged              = $why
                Recommendation          = 'Review group purpose, owners, permissions, and business usage before considering consolidation.'
            }
        }
    }
}

Write-Progress -Activity 'Comparing potential duplicate groups' -Completed

# ---------------------------------------------------------------------------
# DUPLICATE DIRECT MEMBERS WITHIN SAME GROUP
# ---------------------------------------------------------------------------

foreach ($groupDN in @($directMembersByGroup.Keys)) {

    $members = @($directMembersByGroup[$groupDN])

    if (@($members).Count -eq 0) {
        continue
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    $duplicates = [System.Collections.Generic.List[string]]::new()

    foreach ($memberDN in @($members)) {

        if (-not $seen.Add((Get-SafeString $memberDN))) {
            $duplicates.Add((Get-SafeString $memberDN)) | Out-Null
        }
    }

    if ($duplicates.Count -gt 0) {

        $groupInfo = $groupInfoByDn[$groupDN]

        Add-Finding -List $duplicateFindings -Data @{
            GroupName         = Get-SafeString (Get-SafeProperty $groupInfo 'Name')
            GroupDN           = $groupDN
            DuplicateCount    = $duplicates.Count
            DuplicateMembers  = [string]::Join('; ', @($duplicates))
            Recommendation    = 'Investigate the directory membership anomaly.'
        }
    }
}

# ---------------------------------------------------------------------------
# REDUNDANT ACCESS PATHS
# ---------------------------------------------------------------------------

Write-Host 'Analyzing redundant access paths...' -ForegroundColor Cyan

$redundantPathCounter = 0

foreach ($parentGroupDN in @($groups | ForEach-Object { Get-DNKey $_ })) {

    if ([string]::IsNullOrWhiteSpace($parentGroupDN)) {
        continue
    }

    if (-not $directMemberInfoByGroup.ContainsKey($parentGroupDN)) {
        continue
    }

    $parentName = Get-SafeString (
        Get-SafeProperty $groupInfoByDn[$parentGroupDN] 'Name'
    )

    # -------------------------------------------------------------------
    # First find all user paths from the parent.
    # -------------------------------------------------------------------

    $pathStack = [System.Collections.Generic.Stack[object]]::new()

    $pathStack.Push(
        [pscustomobject]@{
            CurrentDN = $parentGroupDN
            PathDNs   = @($parentGroupDN)
            PathNames = @($parentName)
        }
    )

    $userPaths = @{}

    $pathStateCount = 0

    while ($pathStack.Count -gt 0) {

        $state = $pathStack.Pop()

        if ($null -eq $state) {
            continue
        }

        $pathStateCount++

        if ($pathStateCount -ge $TraversalStateLimit) {
            break
        }

        $currentDN = Get-SafeString (
            Get-SafeProperty $state 'CurrentDN'
        )

        $pathDNs = @(
            Get-SafeProperty $state 'PathDNs'
        )

        $pathNames = @(
            Get-SafeProperty $state 'PathNames'
        )

        $memberInfo = @()

        if ($directMemberInfoByGroup.ContainsKey($currentDN)) {
            $memberInfo = @(
                $directMemberInfoByGroup[$currentDN]
            )
        }

        foreach ($member in @($memberInfo)) {

            if ($null -eq $member) {
                continue
            }

            $memberDN = Get-SafeString (
                Get-SafeProperty $member 'DistinguishedName'
            )

            if ([string]::IsNullOrWhiteSpace($memberDN)) {
                continue
            }

            $memberKey = $memberDN.Trim().ToLowerInvariant()

            $memberName = Get-ObjectName $member

            if ([string]::IsNullOrWhiteSpace($memberName)) {
                $memberName = $memberKey
            }

            if ($groupByDn.ContainsKey($memberKey)) {

                $alreadyVisited = $false

                foreach ($existingDN in @($pathDNs)) {
                    if ((Get-SafeString $existingDN) -eq $memberKey) {
                        $alreadyVisited = $true
                        break
                    }
                }

                if ($alreadyVisited) {
                    continue
                }

                $pathStack.Push(
                    [pscustomobject]@{
                        CurrentDN = $memberKey
                        PathDNs   = @($pathDNs + $memberKey)
                        PathNames = @($pathNames + $memberName)
                    }
                )
            }
            else {

                if (-not $userPaths.ContainsKey($memberKey)) {
                    $userPaths[$memberKey] = [System.Collections.Generic.List[object]]::new()
                }

                $pathText = [string]::Join(
                    ' -> ',
                    @($pathNames + $memberName)
                )

                $userPaths[$memberKey].Add(
                    [pscustomobject]@{
                        PathDNs   = @($pathDNs + $memberKey)
                        PathNames = @($pathNames + $memberName)
                        PathText  = $pathText
                    }
                ) | Out-Null
            }
        }
    }

    # -------------------------------------------------------------------
    # Analyze path counts.
    # -------------------------------------------------------------------

    foreach ($userDN in @($userPaths.Keys)) {

        $paths = @($userPaths[$userDN])

        if (@($paths).Count -lt 2) {
            continue
        }

        # Limit reported paths.
        $pathsToReport = @(
            $paths |
                Select-Object -First $MaxPathsPerUserGroup
        )

        $hasDirect = $false
        $indirectCount = 0

        foreach ($path in @($pathsToReport)) {

            $pathDNArray = @(
                Get-SafeProperty $path 'PathDNs'
            )

            if (@($pathDNArray).Count -eq 2) {
                $hasDirect = $true
            }
            else {
                $indirectCount++
            }
        }

        $findingType = ''

        if ($hasDirect -and $indirectCount -gt 0) {
            $findingType = 'Direct plus indirect redundant access'
        }
        elseif ($indirectCount -gt 1) {
            $findingType = 'Multiple indirect access paths'
        }
        else {
            continue
        }

        $pathTexts = @(
            $pathsToReport |
                ForEach-Object {
                    Get-SafeString (
                        Get-SafeProperty $_ 'PathText'
                    )
                }
        )

        $redundantPathCounter++

        Add-Finding -List $redundantAccessFindings -Data @{
            ParentGroup          = $parentName
            ParentGroupDN        = $parentGroupDN
            UserDN               = $userDN
            FindingType          = $findingType
            TotalDiscoveredPaths = @($paths).Count
            PathsReported        = @($pathsToReport).Count
            Paths               = [string]::Join(
                ' || ',
                @($pathTexts)
            )
            Recommendation       = 'Review whether direct membership or multiple nested paths are necessary.'
        }
    }
}

# ---------------------------------------------------------------------------
# EFFECTIVE MEMBERSHIP COMPARISON
# ---------------------------------------------------------------------------

if ($IncludeEffectiveMembershipComparison) {

    Write-Host 'Comparing effective user memberships...' -ForegroundColor Cyan

    $effectiveCounter = 0

    foreach ($groupDN in @($groups | ForEach-Object { Get-DNKey $_ })) {

        $effectiveCounter++

        if ([string]::IsNullOrWhiteSpace($groupDN)) {
            continue
        }

        if (($effectiveCounter % 25) -eq 0) {

            Write-Progress `
                -Activity 'Building effective user memberships' `
                -Status ('{0} / {1}' -f $effectiveCounter, @($groups).Count) `
                -PercentComplete ([int](($effectiveCounter / [double]([math]::Max(1, @($groups).Count))) * 100))
        }

        try {
            $effectiveUsers = Get-EffectiveUsersForGroup -RootDN $groupDN

            if ($null -eq $effectiveUsers) {
                $effectiveMembershipCache[$groupDN] =
                    [System.Collections.Generic.HashSet[string]]::new(
                        [System.StringComparer]::OrdinalIgnoreCase
                    )
            }
        }
        catch {
            Add-AuditError `
                -Stage 'Effective Membership Calculation' `
                -Identity $groupDN `
                -Exception $_.Exception
        }
    }

    Write-Progress -Activity 'Building effective user memberships' -Completed

    # Candidate effective-membership comparison.
    $effectiveBuckets = @{}

    foreach ($groupDN in @($effectiveMembershipCache.Keys)) {

        $effectiveSet = $effectiveMembershipCache[$groupDN]

        $count = 0

        if ($null -ne $effectiveSet) {
            $count = $effectiveSet.Count
        }

        $sizeBucket = [int][math]::Floor($count / 10)

        $bucketKey = 'EFFECTIVE_SIZE:{0}' -f $sizeBucket

        if (-not $effectiveBuckets.ContainsKey($bucketKey)) {
            $effectiveBuckets[$bucketKey] = [System.Collections.Generic.List[string]]::new()
        }

        $effectiveBuckets[$bucketKey].Add($groupDN) | Out-Null

        $info = $groupInfoByDn[$groupDN]

        $tokens = @(Get-NameTokens (
            Get-SafeString (Get-SafeProperty $info 'Name')
        ))

        foreach ($token in @($tokens)) {

            $tokenKey = 'EFFECTIVE_TOKEN:{0}' -f $token

            if (-not $effectiveBuckets.ContainsKey($tokenKey)) {
                $effectiveBuckets[$tokenKey] = [System.Collections.Generic.List[string]]::new()
            }

            $effectiveBuckets[$tokenKey].Add($groupDN) | Out-Null
        }
    }

    $effectiveComparedPairs = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )

    $effectivePairCounter = 0

    foreach ($bucketKey in @($effectiveBuckets.Keys)) {

        $candidateGroups = @(
            $effectiveBuckets[$bucketKey]
        )

        if (@($candidateGroups).Count -lt 2) {
            continue
        }

        if (@($candidateGroups).Count -gt $DuplicateCandidateLimit) {
            $candidateGroups = @(
                $candidateGroups |
                    Select-Object -First $DuplicateCandidateLimit
            )
        }

        for ($i = 0; $i -lt @($candidateGroups).Count; $i++) {

            for ($j = $i + 1; $j -lt @($candidateGroups).Count; $j++) {

                $groupADN = Get-SafeString $candidateGroups[$i]
                $groupBDN = Get-SafeString $candidateGroups[$j]

                if ($groupADN -eq $groupBDN) {
                    continue
                }

                $pairParts = @(
                    $groupADN
                    $groupBDN
                ) | Sort-Object

                $pairKey = [string]::Join('|', @($pairParts))

                if ($effectiveComparedPairs.Contains($pairKey)) {
                    continue
                }

                [void]$effectiveComparedPairs.Add($pairKey)

                $effectivePairCounter++

                $effectiveA = $effectiveMembershipCache[$groupADN]
                $effectiveB = $effectiveMembershipCache[$groupBDN]

                if ($null -eq $effectiveA -or $null -eq $effectiveB) {
                    continue
                }

                $effectiveCountA = 0
                $effectiveCountB = 0

                if ($null -ne $effectiveA) {
                    $effectiveCountA = $effectiveA.Count
                }

                if ($null -ne $effectiveB) {
                    $effectiveCountB = $effectiveB.Count
                }

                if ($effectiveCountA -eq 0 -and $effectiveCountB -eq 0) {
                    continue
                }

                $maximumSize = [math]::Max(
                    $effectiveCountA,
                    $effectiveCountB
                )

                $sizeDifference = [math]::Abs(
                    $effectiveCountA - $effectiveCountB
                )

                if ($maximumSize -gt 0) {

                    $sizeDifferenceRatio =
                        [double]$sizeDifference /
                        [double]$maximumSize

                    if ($sizeDifferenceRatio -gt (1.0 - $NearDuplicateThreshold)) {
                        continue
                    }
                }

                $effectiveArrayA = @($effectiveA)
                $effectiveArrayB = @($effectiveB)

                $effectiveSimilarity = Get-JaccardSimilarity `
                    -SetA $effectiveArrayA `
                    -SetB $effectiveArrayB

                if ($effectiveSimilarity -lt $NearDuplicateThreshold) {
                    continue
                }

                $infoA = $groupInfoByDn[$groupADN]
                $infoB = $groupInfoByDn[$groupBDN]

                $nameSimilarity = Get-JaccardSimilarity `
                    -SetA (Get-NameTokens (
                        Get-SafeString (
                            Get-SafeProperty $infoA 'Name'
                        )
                    )) `
                    -SetB (Get-NameTokens (
                        Get-SafeString (
                            Get-SafeProperty $infoB 'Name'
                        )
                    ))

                $descriptionSimilarity = Get-JaccardSimilarity `
                    -SetA (Get-NameTokens (
                        Get-SafeString (
                            Get-SafeProperty $infoA 'Description'
                        )
                    )) `
                    -SetB (Get-NameTokens (
                        Get-SafeString (
                            Get-SafeProperty $infoB 'Description'
                        )
                    ))

                Add-Finding -List $redundantGroupFindings -Data @{
                    GroupA                    = Get-SafeString (Get-SafeProperty $infoA 'Name')
                    GroupADistinguishedName   = $groupADN
                    GroupB                    = Get-SafeString (Get-SafeProperty $infoB 'Name')
                    GroupBDistinguishedName   = $groupBDN
                    MembershipType            = 'Near-duplicate effective user membership'
                    GroupAEffectiveUserCount  = $effectiveCountA
                    GroupBEffectiveUserCount  = $effectiveCountB
                    MembershipSimilarity      = [math]::Round($effectiveSimilarity, 4)
                    NameSimilarity            = [math]::Round($nameSimilarity, 4)
                    DescriptionSimilarity     = [math]::Round($descriptionSimilarity, 4)
                    WhyFlagged                = 'Effective user membership similarity meets the configured threshold.'
                    Recommendation            = 'Review nested group structure and group purpose before considering consolidation.'
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------

Write-Host 'Exporting reports...' -ForegroundColor Cyan

$duration = (Get-Date) - $script:AuditStart

$summary = [ordered]@{
    AuditStart                         = $script:AuditStart.ToString('s')
    AuditEnd                           = (Get-Date).ToString('s')
    DurationSeconds                    = [math]::Round($duration.TotalSeconds, 2)

    DomainName                         = $script:DomainName
    DomainDistinguishedName            = $script:DomainDN
    SearchBase                         = $SearchBase
    Server                             = $Server

    SecurityGroups                     = @($groups).Count

    EmptyGroups                        = @($emptyFindings).Count
    PotentiallyRedundantGroups         = @($redundantGroupFindings).Count
    NestedGroupRelationships           = @($nestedFindings).Count
    DeepNestingFindings                = @($depthFindings).Count
    CircularNestingFindings            = @($cycleFindings).Count
    RedundantAccessPathFindings        = @($redundantAccessFindings).Count
    DisabledInactiveAccountFindings    = @($accountFindings).Count
    NamingFindings                     = @($namingFindings).Count
    DuplicateDirectMemberFindings      = @($duplicateFindings).Count
    TraversalLimitFindings             = @($traversalLimitFindings).Count
    QueryErrors                        = @($queryErrorFindings).Count

    InactiveUserDays                   = $InactiveUserDays
    DeepNestingThreshold               = $DeepNestingThreshold
    NearDuplicateThreshold             = $NearDuplicateThreshold
    TraversalStateLimit                = $TraversalStateLimit
    MaxPathsPerUserGroup               = $MaxPathsPerUserGroup
    DuplicateCandidateLimit            = $DuplicateCandidateLimit
    EffectiveMembershipComparison      = [bool]$IncludeEffectiveMembershipComparison

    ReadOnlyAudit                       = $true

    ImportantNote1                     = 'No Active Directory objects are modified by this script.'
    ImportantNote2                     = 'Empty groups are findings for human review, not automatic deletion recommendations.'
    ImportantNote3                     = 'lastLogonTimestamp is replicated and should not be treated as definitive proof that an account is unused.'
    ImportantNote4                     = 'Query failures are not treated as empty groups.'
}

# ---------------------------------------------------------------------------
# SUMMARY CSV
# ---------------------------------------------------------------------------

$summaryCsvPath = Join-Path $OutputPath 'Summary.csv'

$summaryRows = @(
    [pscustomobject]$summary
)

$summaryRows | Export-Csv `
    -Path $summaryCsvPath `
    -NoTypeInformation `
    -Encoding UTF8

# ---------------------------------------------------------------------------
# SUMMARY JSON
# ---------------------------------------------------------------------------

$summaryJsonPath = Join-Path $OutputPath 'Summary.json'

$summary |
    ConvertTo-Json -Depth 5 |
    Set-Content -Path $summaryJsonPath -Encoding UTF8

# ---------------------------------------------------------------------------
# FOCUSED CSV EXPORTS
# ---------------------------------------------------------------------------

if ($emptyFindings.Count -gt 0) {
    Export-FindingCsv `
        -InputObject $emptyFindings `
        -Path (Join-Path $OutputPath 'Empty Groups.csv')
}

if ($redundantGroupFindings.Count -gt 0) {
    Export-FindingCsv `
        -InputObject $redundantGroupFindings `
        -Path (Join-Path $OutputPath 'Potentially Redundant Groups.csv')
}

if ($nestedFindings.Count -gt 0) {
    Export-FindingCsv `
        -InputObject $nestedFindings `
        -Path (Join-Path $OutputPath 'Nested Groups.csv')
}

if ($depthFindings.Count -gt 0) {
    Export-FindingCsv `
        -InputObject $depthFindings `
        -Path (Join-Path $OutputPath 'Deep Nesting.csv')
}

if ($cycleFindings.Count -gt 0) {
    Export-FindingCsv `
        -InputObject $cycleFindings `
        -Path (Join-Path $OutputPath 'Circular Nesting.csv')
}

if ($redundantAccessFindings.Count -gt 0) {
    Export-FindingCsv `
        -InputObject $redundantAccessFindings `
        -Path (Join-Path $OutputPath 'Redundant Access Paths.csv')
}

if ($accountFindings.Count -gt 0) {
    Export-FindingCsv `
        -InputObject $accountFindings `
        -Path (Join-Path $OutputPath 'Disabled or Inactive Accounts.csv')
}

if ($namingFindings.Count -gt 0) {
    Export-FindingCsv `
        -InputObject $namingFindings `
        -Path (Join-Path $OutputPath 'Naming Issues.csv')
}

if ($duplicateFindings.Count -gt 0) {
    Export-FindingCsv `
        -InputObject $duplicateFindings `
        -Path (Join-Path $OutputPath 'Duplicate Direct Members.csv')
}

if ($traversalLimitFindings.Count -gt 0) {
    Export-FindingCsv `
        -InputObject $traversalLimitFindings `
        -Path (Join-Path $OutputPath 'Traversal Limits.csv')
}

if ($queryErrorFindings.Count -gt 0) {
    Export-FindingCsv `
        -InputObject $queryErrorFindings `
        -Path (Join-Path $OutputPath 'Query Errors.csv')
}

# ---------------------------------------------------------------------------
# AUDIT ERROR LOG
# ---------------------------------------------------------------------------

if ($auditErrors.Count -gt 0) {

    $auditErrors |
        Set-Content `
            -Path $auditErrorLogPath `
            -Encoding UTF8
}
else {

    @(
        'No query or processing errors were recorded.'
        ('Audit completed: {0}' -f (Get-Date).ToString('s'))
    ) |
        Set-Content `
            -Path $auditErrorLogPath `
            -Encoding UTF8
}

# ---------------------------------------------------------------------------
# FINAL CONSOLE OUTPUT
# ---------------------------------------------------------------------------

Write-Host ''
Write-Host '============================================================' -ForegroundColor Cyan
Write-Host 'Active Directory Security Group Audit Complete' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan

Write-Host ('Security groups:              {0}' -f @($groups).Count)
Write-Host ('Empty groups:                 {0}' -f @($emptyFindings).Count)
Write-Host ('Potential duplicates:         {0}' -f @($redundantGroupFindings).Count)
Write-Host ('Nested relationships:         {0}' -f @($nestedFindings).Count)
Write-Host ('Deep nesting findings:        {0}' -f @($depthFindings).Count)
Write-Host ('Circular nesting:             {0}' -f @($cycleFindings).Count)
Write-Host ('Redundant access paths:       {0}' -f @($redundantAccessFindings).Count)
Write-Host ('Disabled/inactive accounts:   {0}' -f @($accountFindings).Count)
Write-Host ('Naming/metadata findings:     {0}' -f @($namingFindings).Count)
Write-Host ('Duplicate direct members:     {0}' -f @($duplicateFindings).Count)
Write-Host ('Traversal limits reached:     {0}' -f @($traversalLimitFindings).Count)
Write-Host ('Query errors:                 {0}' -f @($queryErrorFindings).Count)

Write-Host ''
Write-Host ('Reports written to: {0}' -f $OutputPath) -ForegroundColor Green

if ($IncludeEffectiveMembershipComparison) {
    Write-Host 'Effective membership comparison: ENABLED' -ForegroundColor Yellow
}
else {
    Write-Host 'Effective membership comparison: DISABLED' -ForegroundColor Gray
}

Write-Host ''
Write-Host 'This was a READ-ONLY Active Directory audit.' -ForegroundColor Green
Write-Host 'No Active Directory objects were modified.' -ForegroundColor Green