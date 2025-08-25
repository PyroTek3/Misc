# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2025-08-25
# Script provided as-is

$GroupArray = @('Account Operators','Backup Operators','Cert Publishers','DNSAdmins','Enterprise Key Admins','Event Log Readers','IIS_IUSRS',`
 'Print Operators','Server Operators','Schema Admins')

$PrivilegedGroupMemberArray = @()
ForEach ($GroupArrayItem in $GroupArray)
 {
    $ADGroupMemberArray = Get-ADGroupMember $GroupArrayItem -Recursive
    $ADGroupMemberString = $ADGroupMemberArray.name -join ","
    $PrivilegedGroupMemberItem = New-Object PSObject
    $PrivilegedGroupMemberItem | Add-Member -MemberType NoteProperty -Name GroupName -Value $GroupArrayItem -Force
    $PrivilegedGroupMemberItem | Add-Member -MemberType NoteProperty -Name MemberCount -Value $ADGroupMemberArray.Count -Force 
    $PrivilegedGroupMemberItem | Add-Member -MemberType NoteProperty -Name Members -Value $ADGroupMemberString -Force 
    $PrivilegedGroupMemberItem | Add-Member -MemberType NoteProperty -Name MemberArray -Value $ADGroupMemberArray -Force 
    [array]$PrivilegedGroupMemberArray += $PrivilegedGroupMemberItem

    IF ($ADGroupMemberArray.Count -gt 0)
     { 
       SWITCH ($GroupArrayItem)
        {
            'Account Operators' { Write-Warning "The $GroupArrayItem group should be empty, but contains $($ADGroupMemberArray.Count) members" }
            'Print Operators' { Write-Warning "The $GroupArrayItem group should be empty, but contains $($ADGroupMemberArray.Count) members" }
            'Schema Admins' { Write-Warning "The $GroupArrayItem group should be empty, but contains $($ADGroupMemberArray.Count) members" }
        }
     }

    IF ( ($GroupArrayItem -eq 'Backup Operators') -AND ($ADGroupMemberArray.Count -ge 5) )
     { Write-Warning "The $GroupArrayItem group should typically have less than ~5 members, but contains $($ADGroupMemberArray.Count) members" }
    IF ( ($GroupArrayItem -eq 'Cert Publishers') -AND ($ADGroupMemberArray.Count -ge 5) )
     { Write-Warning "The $GroupArrayItem group should typically have less than ~5 members, but contains $($ADGroupMemberArray.Count) members" }
    IF ( ($GroupArrayItem -eq 'Event Log Readers') -AND ($ADGroupMemberArray.Count -ge 2) )
     { Write-Warning "The $GroupArrayItem group should typically have less than ~3 members, but contains $($ADGroupMemberArray.Count) members" }
    IF ( ($GroupArrayItem -eq 'IIS_IUSRS') -AND ($ADGroupMemberArray.Count -ge 2) )
     { Write-Warning "The $GroupArrayItem group should typically have ~1 member, but contains $($ADGroupMemberArray.Count) members" }
 }

$PrivilegedGroupMemberArray | Select GroupName,MemberCount,Members | Format-Table -Auto

