# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2025-09-12
# Script provided as-is

Param
 (
    $Domain = $env:userdnsdomain
 )

$DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
$DomainInfo = Get-ADDomain -Server $DomainDC

[array]$ADAdminArray = Get-ADGroupMember -Identity 'Administrators' -Recursive -Server $DomainDC

$ADAdminPropertyArray = @()
ForEach($ADAdminArrayItem in $ADAdminArray)
 { 
    SWITCH ($ADAdminArrayItem.objectClass)
    {
        'User' { [array]$ADAdminPropertyArray += Get-ADUser $ADAdminArrayItem.DistinguishedName -Prop *  -Server $DomainDC }
        'Computer' { [array]$ADAdminPropertyArray += Get-ADComputer $ADAdminArrayItem.DistinguishedName -Prop *   -Server $DomainDC }
        'msDS-GroupManagedServiceAccount' { [array]$ADAdminPropertyArray += Get-ADServiceAccount $ADAdminArrayItem.DistinguishedName -Prop *   -Server $DomainDC }
    }
 }

$ADAdminPropertyArray | Sort SamAccountName | Select SamAccountName,ObjectClass,PasswordLastSet,LastLogonDate,Enabled,DoesNotRequirePreAuth,UseDESKeyOnly,PasswordNeverExpires,ServicePrincipalName,info,description | Format-Table -AutoSize
