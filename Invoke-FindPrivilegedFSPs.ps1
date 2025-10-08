# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2025-10-07
# Script provided as-is

Param
 (
    $Domain = $env:userdnsdomain
 )

$DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
$DomainInfo = Get-ADDomain -Server $DomainDC
$DomainEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($DomainInfo.DistinguishedName)")

$GroupArray = @('Administrators','Account Operators','Backup Operators','Cert Publishers','DNSAdmins','Domain Admins','Enterprise Admins','Print Operators','Remote Desktop Users','Server Operators')

ForEach ($GroupArrayItem in $GroupArray)
 {
    Write-Host "Scanning $GroupArrayItem for FSPs..."
    $GroupInfoDN = (Get-ADGroup -Identity $GroupArrayItem -Server $DomainDC).DistinguishedName
    $GroupEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$GroupInfoDN")
    $MemberArray = @()
    [array]$MemberArray = $groupEntry.Properties["member"]
    $FSPMemberArray = @()
    $FSPMemberArray = $MemberArray | Select-String -Pattern 'ForeignSecurityPrincipals' -CaseSensitive -SimpleMatch 
    IF ($FSPMemberArray)
     { 
         Write-Host ""
         Write-Host "$GroupArrayItem FSP Members:" 
        $FSPMemberArray
         Write-Host ""
     }  
 }