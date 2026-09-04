All of the files are self-explanatory from the file names but here the description for FullADGroupsAuditCleanUp.ps1 

# AD Security Group Cleanup & Audit Script

## Overview
`Invoke-ADSecurityGroupCleanupAudit.ps1` is a **read-only PowerShell 5.1 script** for auditing Active Directory security groups.  
It identifies cleanup opportunities, risks, and inconsistencies—**without making any changes to AD**.

---

## Features
- **Empty Groups** – Flags groups with no members (with context for intentional use)
- **Duplicate Groups** – Detects identical or near-identical groups (membership + naming)
- **Redundant Access** – Finds users with duplicate access paths (direct + nested)
- **Nested Groups** – Maps relationships, detects deep nesting & circular loops
- **Inactive Accounts** – Identifies disabled or stale users in groups
- **Naming Issues** – Highlights missing descriptions, owners, or poor naming

---

## Safety
- Fully **read-only**
- Uses only `Get-AD*` cmdlets
- No `Set/Add/Remove/New-AD*` operations
- Built-in error handling and logging

---

## Output
Creates a report folder with:

**Always:**
- `Summary.csv`
- `Summary.json`

**If findings exist:**
- Empty Groups  
- Redundant Groups  
- Nested / Deep / Circular Groups  
- Redundant Access Paths  
- Inactive Accounts  
- Naming Issues  
- Query Errors  

**Logs:**
- `AuditErrors.log`

---

## Usage
```powershell
.\Invoke-ADSecurityGroupCleanupAudit.ps1 `
    -SearchBase "OU=,DC=,DC=local" `
    -OutputPath "C:\Temp\ADSecurityGroupAudit" `
    -DeepNestingThreshold 5 `
    -InactiveUserDays 120 `
    -NearDuplicateThreshold 0.90 `
    -IncludeEffectiveMembershipComparison
