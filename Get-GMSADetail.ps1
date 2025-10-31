# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2025-10-31
# Updated
# Script provided as-is

Param
 (
    $Domain = $env:userdnsdomain
 )

$DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
$DomainInfo = Get-ADDomain -Server $DomainDC

[array]$DomainGMSAArray = Get-ADServiceAccount -filter * -prop * -Server $DomainDC | Sort Name

$DomainGMSADetailArray = @()
ForEach ($DomainGMSAArrayItem in $DomainGMSAArray)
 {
    $PasswordAccesPrincipalArray = @()
    ForEach ($PasswordAccessPrincipalArrayItem in $DomainGMSAArrayItem.PrincipalsAllowedtoRetrieveManagedPassword)
     {
        $PasswordAccessPrincipalArray = Get-ADObject $PasswordAccessPrincipalArrayItem -Server $DomainDC
        Switch($PasswordAccessPrincipalArray.ObjectClass)
         {
            Group { $PasswordAccesPrincipalArray += Get-ADGroupMember $PasswordAccessPrincipalArray.DistinguishedName -Server $DomainDC }
            User  { $PasswordAccesPrincipalArray += Get-ADUser $PasswordAccessPrincipalArray.DistinguishedName -Server $DomainDC }
         } 
     }
     [string]$PasswordAccesPrincipalString = $PasswordAccesPrincipalArray.Name -join ","
     $DomainGMSAArrayItem | Add-Member -MemberType NoteProperty -Name PasswordAccesPrincipalArray -Value $PasswordAccesPrincipalArray -Force
     $DomainGMSAArrayItem | Add-Member -MemberType NoteProperty -Name PasswordAccesPrincipalString -Value $PasswordAccesPrincipalString -Force
     $DomainGMSADetailArray += $DomainGMSAArrayItem
 }

$DomainGMSADetailArray | Select Name,DNSHostName,MemberOf,Created,LastLogonDate,PasswordLastSet,msDS-ManagedPasswordInterval,`
 PrincipalsallowedtoDelegateToAccount,PrincipalsAllowedtoRetrieveManagedPassword,PasswordAccesPrincipalString,msDS-ManagedPassword,ServicePrincipalName | Sort Name


