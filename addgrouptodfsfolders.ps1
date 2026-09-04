# --- CONFIG ---
$Group      = "BCOGC.local\Records File Audit"
$FolderList = @(
    "folder names here",
)


# --- SETTINGS ---
$Rights      = [System.Security.AccessControl.FileSystemRights]"Modify"
$Inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
$Propagation = [System.Security.AccessControl.PropagationFlags]::None
$Type        = [System.Security.AccessControl.AccessControlType]::Allow

# --- PROCESS ---
foreach ($Folder in $FolderList) {

    if (Test-Path $Folder) {

        try {
            $acl = Get-Acl $Folder

            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $Group,
                $Rights,
                $Inheritance,
                $Propagation,
                $Type
            )

            # Replace existing rule for group (cleaner than duplicate entries)
            $acl.SetAccessRule($rule)

            Set-Acl -Path $Folder -AclObject $acl

            Write-Host "✅ Updated ACL on $Folder" -ForegroundColor Green
        }
        catch {
            Write-Warning "❌ Failed on ${Folder}: $_"
        }
    }
    else {
        Write-Warning "❌ Path not found: $Folder"
    }
}
