# PowerShell script authored by Sean Metcalf (@PyroTek3)
# 2025-09-03
# Script provided as-is

$ForestDCArray = @()
ForEach ($ForestDomainItem in $((Get-ADForest).Domains) )
 {
   $DomainDC = Get-ADDomainController -Discover -DomainName $ForestDomainItem
   $DomainInfo = Get-ADDomain -Server $($DomainDC.HostName)
   ForEach ($DomainControllerItem in $($DomainInfo.ReplicaDirectoryServers) )
    { [array]$ForestDCArray += Get-ADDomainController $DomainControllerItem -Server $DomainDC }
 }

$Forest2025DCArray = $ForestDCArray | Where {$_.OperatingSystem -like "*2025*"}
Write-Host "The following DCs are running Windows Server 2025:"
$Forest2025DCArray | Select Domain,Name,OperatingSystem,Site | format-table -AutoSize

$KDSRootKeyArray = Get-KdsRootKey 

IF ($KDSRootKeyArray)
 {
    $KDSRootKeyDomainArray = @()
    ForEach ($KDSRootKeyArrayItem in $KDSRootKeyArray)
     {
        $DC1 = $KDSRootKeyArrayItem.DomainController -Replace('CN=',"") 
        $DC2 = $DC1 -Replace (',OU=Domain Controllers',"")
        $DomainDC = $DC2 -Replace (',DC=',".")
        $KDSDomainArray = Get-ADDomain -Server $DomainDC
        $KDSDomainArray | Add-Member -MemberType NoteProperty -Name KDSCreationTime -Value $KDSRootKeyArrayItem.CreationTime -Force
        [array]$KDSRootKeyDomainArray += $KDSDomainArray
     }
 }
 Write-Host "The following domains have had the KDS Root Key created:"
 ForEach ($KDSRootKeyDomainArrayItem in $KDSRootKeyDomainArray)
  {
    Write-Host "  * $($KDSRootKeyDomainArrayItem.DNSRoot): KDS root key created on $($KDSRootKeyDomainArrayItem.KDSCreationTime)"
  }

$KDSKey2025DCDomainArray = @()
ForEach ($KDSRootKeyDomainArrayItem in $KDSRootKeyDomainArray)
  { 
    ForEach ($Forest2025DCArrayItem in $Forest2025DCArray)
     {
        IF ($KDSRootKeyDomainArrayItem.DNSRoot -eq $Forest2025DCArrayItem.Domain)
         { [array]$KDSKey2025DCDomainArray += $KDSRootKeyDomainArrayItem.DNSRoot }
     }
  }
$KDSKey2025DCDomainArray = $KDSKey2025DCDomainArray | Sort-Object -Unique
Write-Host " "
Write-Host "The following domains have a Windows Server 2025 Domain Controller and the KDS Root Key created:"
ForEach ($KDSKey2025DCDomainArrayItem in $KDSKey2025DCDomainArray)
 { Write-Host "  * $KDSKey2025DCDomainArrayItem" }

