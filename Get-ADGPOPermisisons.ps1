# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2025-09-03
# Script provided as-is
Param
 (
    $Domain = $env:userdnsdomain
 )

[Array]$DomainGPOArray = Get-GPO -All -Domain $Domain 
$DomainGPOOwnerArray = @()
ForEach ($DomainGPOItem in $DomainGPOArray)
 {
    $DomainGPOItem | Add-Member -MemberType NoteProperty -Name Default -Value $False -Force 
    IF ( ($DomainGPOItem.Owner -like '*Domain Admins') -OR ($DomainGPOItem.Owner -like '*Enterprise Admins') )
     { $DomainGPOItem | Add-Member -MemberType NoteProperty -Name Default -Value $True -Force }
    ELSE
     { $DomainGPOItem | Add-Member -MemberType NoteProperty -Name Default -Value $False -Force }
     [array]$DomainGPOOwnerArray += $DomainGPOItem
 }

$DomainGPOOwnerArray | Select DisplayName,Owner,id,Default | Format-Table -AutoSize


[Array]$DomainGPOArray = Get-GPO -All -Domain $Domain
$GPOPermissionArray = @()
ForEach ($DomainGPOArrayItem in $DomainGPOArray)
 {
    $GPPermissionArray = @()
    $GPPermissionArray = Get-GPPermissions -Guid $DomainGPOArrayItem.Id -All | Where {$_.Trustee.SidType.ToString() -ne "WellKnownGroup"}
    ForEach ($GPPermissionArrayItem in $GPPermissionArray)
     {
        $GPOPermissionArrayRecord = New-Object PSObject
        $GPOPermissionArrayRecord | Add-Member -MemberType NoteProperty -Name GPOName -Value $DomainGPOArrayItem.DisplayName -Force
        $GPOPermissionArrayRecord | Add-Member -MemberType NoteProperty -Name AccountName -Value $GPPermissionArrayItem.Trustee.Name -Force
        $GPOPermissionArrayRecord | Add-Member -MemberType NoteProperty -Name AccountType -Value $GPPermissionArrayItem.Trustee.SidType.ToString() -Force
        $GPOPermissionArrayRecord | Add-Member -MemberType NoteProperty -Name Permissions -Value $GPPermissionArrayItem.Permission -Force
        IF ( ($GPPermissionArrayItem.Trustee.Name -eq 'Domain Admins') -OR ($GPPermissionArrayItem.Trustee.Name -eq 'Enterprise Admins') )
         { $GPOPermissionArrayRecord | Add-Member -MemberType NoteProperty -Name Default -Value $True -Force }
        ELSE
         { $GPOPermissionArrayRecord | Add-Member -MemberType NoteProperty -Name Default -Value $False -Force }
        $GPOPermissionArray += $GPOPermissionArrayRecord
     }
 }
$GPOPermissionArray | Format-Table -AutoSize