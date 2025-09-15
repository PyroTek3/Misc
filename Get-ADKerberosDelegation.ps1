# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2025-09-15
# Script provided as-is

Param
 (
    $Domain = $env:userdnsdomain
 )

$DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
$DomainInfo = Get-ADDomain -Server $DomainDC

$ADProperties = @("Name","ObjectClass","PrimaryGroupID","UserAccountControl","ServicePrincipalName","msDS-AllowedToDelegateTo","msDS-AllowedToActOnBehalfOfOtherIdentity")

$KerberosDelegationArray = @()
[array]$KerberosDelegationObjects = Get-ADObject -filter {((UserAccountControl -BAND 0x0080000) -OR (UserAccountControl -BAND 0x1000000) -OR (msDS-AllowedToDelegateTo -like '*') -OR (msDS-AllowedToActOnBehalfOfOtherIdentity -like '*')) -AND (PrimaryGroupID -ne '516') -AND (PrimaryGroupID -ne '521') }  -Properties $ADProperties -SearchBase $((Get-ADDomain -Server $DomainDC).DistinguishedName) -Server $DomainDC

ForEach ($KerberosDelegationObjectItem in $KerberosDelegationObjects) 
 {
    IF ($KerberosDelegationObjectItem.UserAccountControl -BAND 0x0080000) 
     { 
        $KerberosDelegationServices = 'All Services'
        $KerberosType = 'Unconstrained' 
     } 
    ELSE 
     { 
        $KerberosDelegationServices = 'Specific Services'
        $KerberosType = 'Constrained' 
     } 

    IF ($KerberosDelegationObjectItem.UserAccountControl -BAND 0x1000000) 
     { 
        $KerberosDelegationAllowedProtocols = 'Any (Protocol Transition)'
        $KerberosType = 'Constrained with Protocol Transition'
     } 
    ELSE 
     { 
        $KerberosDelegationAllowedProtocols = 'Kerberos'
     }

    IF ($KerberosDelegationObjectItem.'msDS-AllowedToActOnBehalfOfOtherIdentity') 
     { 
        $KerberosType = 'Resource-Based Constrained Delegation'
     } 

    $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name Domain -Value $DomainName -Force
    $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name KerberosDelegationServices -Value $KerberosDelegationServices -Force
    $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name DelegationType -Value $KerberosType -Force
    $KerberosDelegationObjectItem | Add-Member -MemberType NoteProperty -Name KerberosDelegationAllowedProtocols -Value $KerberosDelegationAllowedProtocols -Force

    [array]$KerberosDelegationArray += $KerberosDelegationObjectItem
 }

$KerberosDelegationArray | Sort DelegationType | Select DistinguishedName,DelegationType,Name,ServicePrincipalName | Format-Table -AutoSize

