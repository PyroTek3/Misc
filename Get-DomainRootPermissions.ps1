# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2025-11-04
# Updated
# Script provided as-is

Param
 (
    $Domain = $env:userdnsdomain
 )

$DomainDC = (Get-ADDomainController -Discover -DomainName $Domain).Name
$DomainInfo = Get-ADDomain -Server $DomainDC

function Get-NameForGUID{
    # From http://blog.wobl.it/2016/04/active-directory-guid-to-friendly-name-using-just-powershell/
    [CmdletBinding()]
    Param(
        [guid]$guid,
        [string]$ForestDNSName
    )
    Begin{
        if (!$ForestDNSName) { 
            $ForestDNSName = (Get-ADForest $ForestDNSName).Name 
        }

        if ($ForestDNSName -notlike "*=*") { 
            $ForestDNSNameDN = "DC=$($ForestDNSName.replace(".", ",DC="))" 
        }

        $ExtendedRightGUIDs = "LDAP://cn=Extended-Rights,cn=configuration,$ForestDNSNameDN"
        $PropertyGUIDs = "LDAP://cn=schema,cn=configuration,$ForestDNSNameDN"
    }
    Process{
        if ($guid -eq "00000000-0000-0000-0000-000000000000"){
            Return "All"
        } else {
            $rightsGuid = $guid
            $property = "cn"
            $SearchAdsi = ([ADSISEARCHER]"(rightsGuid=$rightsGuid)")
            $SearchAdsi.SearchRoot = $ExtendedRightGUIDs
            $SearchAdsi.SearchScope = "OneLevel"
            $SearchAdsiRes = $SearchAdsi.FindOne()
            if ($SearchAdsiRes){
                Return $SearchAdsiRes.Properties[$property]
            } else {
                $SchemaGuid = $guid
                $SchemaByteString = "\" + ((([guid]$SchemaGuid).ToByteArray() | %{$_.ToString("x2")}) -Join "\")
                $property = "ldapDisplayName"
                $SearchAdsi = ([ADSISEARCHER]"(schemaIDGUID=$SchemaByteString)")
                $SearchAdsi.SearchRoot = $PropertyGUIDs
                $SearchAdsi.SearchScope = "OneLevel"
                $SearchAdsiRes = $SearchAdsi.FindOne()
                if ($SearchAdsiRes){
                    Return $SearchAdsiRes.Properties[$property]
                } else {
                    Write-Host -f Yellow $guid
                    Return $guid.ToString()
                }
            }
        }
    }
}

$ForestDomainObjectData = Get-ADObject $DomainInfo.DistinguishedName -Properties * -Server $DomainDC
$ForestDomainObjectSecurityData = $ForestDomainObjectData.nTSecurityDescriptor.Access
    
$ForestDomainObjectPermissionArray = @()
ForEach ($ForestDomainObjectSecurityDataItem in $ForestDomainObjectSecurityData) {
    $ObjectTypeName = Get-NameForGUID $ForestDomainObjectSecurityDataItem.ObjectType -ForestDNSName $DomainInfo.Forest
    $InheritedObjectTypeName = Get-NameForGUID $ForestDomainObjectSecurityDataItem.InheritedObjectType -ForestDNSName $DomainInfo.Forest

    $ForestDomainObjectSecurityDataItem | Add-Member -MemberType NoteProperty -Name Domain -Value $Domain -Force
    $ForestDomainObjectSecurityDataItem | Add-Member -MemberType NoteProperty -Name ObjectTypeName -Value $ObjectTypeName -Force
    $ForestDomainObjectSecurityDataItem | Add-Member -MemberType NoteProperty -Name InheritedObjectTypeName -Value $InheritedObjectTypeName -Force

    [array]$ForestDomainObjectPermissionArray += $ForestDomainObjectSecurityDataItem
}

$DomainRootPermissionHashtable = @{}
ForEach ($ForestDomainObjectPermissionArrayItem in $ForestDomainObjectPermissionArray)
 {
    $ForestDomainObjectPermissionRecordItem = $ForestDomainObjectPermissionArrayItem.InheritedObjectTypeName + ':' + $ForestDomainObjectPermissionArrayItem.ActiveDirectoryRights + ':' + $ForestDomainObjectPermissionArrayItem.ObjectTypeName + ':' + $ForestDomainObjectPermissionArrayItem.AccessControlType
    $ForestDomainObjectPermissionRecordExistingItem = $NULL
    $ForestDomainObjectPermissionRecordExistingItem = $DomainRootPermissionHashtable.Get_Item($ForestDomainObjectPermissionArrayItem.IdentityReference.Value)

    IF ($ForestDomainObjectPermissionRecordExistingItem)
     {
        $ForestDomainObjectPermissionRecordExistingItemPlus = $NULL
        $ForestDomainObjectPermissionRecordExistingItemPlus = $ForestDomainObjectPermissionRecordExistingItem + '; ' + $ForestDomainObjectPermissionRecordItem
        $DomainRootPermissionHashtable.Set_Item($ForestDomainObjectPermissionArrayItem.IdentityReference.Value,$ForestDomainObjectPermissionRecordExistingItemPlus)
     }
    ELSE
     { $DomainRootPermissionHashtable.Set_Item($ForestDomainObjectPermissionArrayItem.IdentityReference.Value,$ForestDomainObjectPermissionRecordItem) }
 }

# $DomainRootPermissionHashtable.GetEnumerator() | Format-Table -AutoSize


# Directory Changes & Directory Changes All
Write-Host "Security Principals with DS-Replication-Get-Changes & DS-Replication-Get-Changes-All (DCSync rights)" -ForegroundColor Cyan
$DomainRootPermissionHashtable.GetEnumerator() | where { ($_.value -like "*All:ExtendedRight:DS-Replication-Get-Changes:Allow*") -AND ($_.value -like "*All:ExtendedRight:DS-Replication-Get-Changes-All:Allow*") } | Format-Table -AutoSize

# Change Owner on domain root
Write-Host "Security Principals with Modify Rights on the domain root which (Owners can change permissions)" -ForegroundColor Cyan
$DomainRootPermissionHashtable.GetEnumerator() | where { ($_.value -like "*WriteOwner:All:Allow*") }  | Format-Table -AutoSize

# Change Permission on domain root
Write-Host "Security Principals with Change Permission Rights on the domain root" -ForegroundColor Cyan
$DomainRootPermissionHashtable.GetEnumerator() | where { ($_.value -like "*WriteDacl:All:Allow*") }  | Format-Table -AutoSize

# Full Control on all
Write-Host "Security Principals with Full Control on all objects in the domain" -ForegroundColor Cyan
$DomainRootPermissionHashtable.GetEnumerator() | where { ($_.value -like "*All:GenericAll:All:Allow*") }  | Format-Table -AutoSize

# Full Control on Users & Computers
Write-Host "Security Principals with Full Control on user & computer objects in the domain" -ForegroundColor Cyan
$DomainRootPermissionHashtable.GetEnumerator() | where { ($_.value -like "*user:GenericAll:All:Allow*") -AND ($_.value -like "*computer:GenericAll:All:Allow*") }  | Format-Table -AutoSize

# Full Control on Users
Write-Host "Security Principals with Full Control on user objects in the domain" -ForegroundColor Cyan
$DomainRootPermissionHashtable.GetEnumerator() | where { ($_.value -like "*user:GenericAll:All:Allow*") }  | Format-Table -AutoSize

# Full Control on Computers
Write-Host "Security Principals with Full Control on computer objects in the domain" -ForegroundColor Cyan
$DomainRootPermissionHashtable.GetEnumerator() | where { ($_.value -like "*computer:GenericAll:All:Allow*") }  | Format-Table -AutoSize
