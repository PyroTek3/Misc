# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2025-08-25
# Updated 2025-10-08
# Script provided as-is

Param
 (
    $Domain = $env:userdnsdomain
 )

$DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
$DomainInfo = Get-ADDomain -Server $DomainDC

# $GroupArray = @('Account Operators','Backup Operators','Cert Publishers','DNSAdmins','Enterprise Key Admins','Event Log Readers','Group Policy Creator Owners','Print Operators','Server Operators','Schema Admins')
$GroupArray =  @('S-1-5-32-548','S-1-5-32-551','-517','-1101','-527','S-1-5-32-573','-520','S-1-5-32-550','S-1-5-32-549','-518')

$PrivilegedGroupMemberArray = @()
ForEach ($GroupArrayItem in $GroupArray)
 {
    IF ($GroupArrayItem -like 'S-1-*')
     { $GroupArrayItemSID = $GroupArrayItem }    
    ELSE
     { $GroupArrayItemSID = $($DomainInfo.DomainSID.Value) + $GroupArrayItem }

     $GroupInfo = @()
     $GroupInfo = Get-ADGroup $GroupArrayItemSID -Server $DomainDC

    $ADGroupMemberArray = @()
    $ADGroupMemberArray = Get-ADGroupMember $GroupInfo.SID.Value -Recursive -Server $DomainDC
    $ADGroupMemberString = $ADGroupMemberArray.name -join ","
    $PrivilegedGroupMemberItem = New-Object PSObject
    $PrivilegedGroupMemberItem | Add-Member -MemberType NoteProperty -Name GroupName -Value $GroupInfo.Name -Force
    $PrivilegedGroupMemberItem | Add-Member -MemberType NoteProperty -Name MemberCount -Value $ADGroupMemberArray.Count -Force 
    $PrivilegedGroupMemberItem | Add-Member -MemberType NoteProperty -Name Members -Value $ADGroupMemberString -Force 
    $PrivilegedGroupMemberItem | Add-Member -MemberType NoteProperty -Name MemberArray -Value $ADGroupMemberArray -Force 
    [array]$PrivilegedGroupMemberArray += $PrivilegedGroupMemberItem

    IF ($ADGroupMemberArray.Count -gt 0)
     { 
       SWITCH ($GroupArrayItem)
        {
            'S-1-5-32-548' { Write-Warning "The $($GroupInfo.Name) group should be empty, but contains $($ADGroupMemberArray.Count) members" }
            '-520' { Write-Warning "The $($GroupInfo.Name) group should be empty, but contains $($ADGroupMemberArray.Count) members" }
            'S-1-5-32-550' { Write-Warning "The $($GroupInfo.Name) group should be empty, but contains $($ADGroupMemberArray.Count) members" }
            '-518' { Write-Warning "The $($GroupInfo.Name) group should be empty, but contains $($ADGroupMemberArray.Count) members" }
        }
     }

    IF ( ($GroupArrayItem -eq 'S-1-5-32-551') -AND ($ADGroupMemberArray.Count -ge 5) )
     { Write-Warning "The $($GroupInfo.Name) should typically have less than ~5 members, but contains $($ADGroupMemberArray.Count) members" }
    IF ( ($GroupArrayItem -eq 'Cert Publishers') -AND ($ADGroupMemberArray.Count -ge 5) )
     { Write-Warning "The $($GroupInfo.Name) group should typically have ~5 members, but contains $($ADGroupMemberArray.Count) members" }
    IF ( ($GroupArrayItem -eq 'S-1-5-32-573') -AND ($ADGroupMemberArray.Count -ge 2) )
     { Write-Warning "The $($GroupInfo.Name) group should typically have less than ~3 members, but contains $($ADGroupMemberArray.Count) members" }
 }

$PrivilegedGroupMemberArray | Sort SamAccountName | Select GroupName,MemberCount,Members | Format-Table -Auto
