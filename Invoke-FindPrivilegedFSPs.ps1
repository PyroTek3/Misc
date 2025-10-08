# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2025-10-08
# Script provided as-is

Param
 (
    $Domain = $env:userdnsdomain
 )

$DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
$DomainInfo = Get-ADDomain -Server $DomainDC
$DomainEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($DomainInfo.DistinguishedName)")

#$GroupArray = @('Administrators','Account Operators','Backup Operators','Cert Publishers','DNSAdmins','Domain Admins','Enterprise Admins','Print Operators','Remote Desktop Users','Server Operators')
$GroupArray = @('S-1-5-32-544','S-1-5-32-548','S-1-5-32-551',"-517",'-1101','-512','-519','S-1-5-32-550','S-1-5-32-555','S-1-5-32-549')

ForEach ($GroupArrayItem in $GroupArray)
 {
    IF ($GroupArrayItem -like 'S-1-*')
     { $GroupArrayItemSID = $GroupArrayItem }    
    ELSE
     { $GroupArrayItemSID = $($DomainInfo.DomainSID.Value) + $GroupArrayItem }
    $GroupInfo = (Get-ADGroup -Identity $GroupArrayItemSID -Server $DomainDC)
    $GroupInfoDN = $GroupInfo.DistinguishedName
    Write-Host "Scanning $($GroupInfo.Name) for FSPs..."
    $GroupEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$GroupInfoDN")
    $MemberArray = @()
    [array]$MemberArray = $groupEntry.Properties["member"]
    $FSPMemberArray = @()
    $FSPMemberArray = $MemberArray | Select-String -Pattern 'ForeignSecurityPrincipals' -CaseSensitive
    IF ($FSPMemberArray)
     { 
         Write-Host ""
         Write-Host "$($GroupInfo.Name) FSP Members:" 
        $FSPMemberArray
         Write-Host ""
     }  
 }