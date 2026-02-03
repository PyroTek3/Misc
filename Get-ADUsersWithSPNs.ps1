# PowerShell script authored by Sean Metcalf (@PyroTek3)
# Created: 2026-02-03
# Last Update: 2026-02-03 
# Script provided as-is

Param
 (
    $Domain = $env:userdnsdomain
 )

$DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
$DomainInfo = Get-ADDomain -Server $DomainDC

[array]$AccountsWithSPNsArray = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Server $DomainDC -Prop SamAccountName,ObjectClass,PasswordLastSet,LastLogonDate,Enabled,DoesNotRequirePreAuth,UseDESKeyOnly,PasswordNeverExpires,ServicePrincipalName,description,MemberOf 

Write-Host "All Accounts with SPNs:" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
$AccountsWithSPNsArray | Sort SamAccountName | Select SamAccountName,ObjectClass,PasswordLastSet,LastLogonDate,Enabled,PasswordNeverExpires,ServicePrincipalName,description | Format-Table -AutoSize


[array]$ADAdminAccountsWithSPNsArray = $AccountsWithSPNsArray | Where { ($_.MemberOf -match 'Administrators') -OR ($_.MemberOf -match 'Domain Admins') -OR ($_.MemberOf -match 'Enterprise Admins') }

Write-Host "AD Admin Accounts with SPNs:" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan
$ADAdminAccountsWithSPNsArray | Sort SamAccountName | Select SamAccountName,ObjectClass,PasswordLastSet,LastLogonDate,Enabled,PasswordNeverExpires,ServicePrincipalName,description | Format-Table -AutoSize

