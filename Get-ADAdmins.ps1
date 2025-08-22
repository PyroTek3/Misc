# Note this script is designed for a single domain environment

[array]$ADAdminArray = Get-ADGroupMember -Identity 'Administrators' -Recursive 

$ADAdminPropertyArray = @()
ForEach($ADAdminArrayItem in $ADAdminArray)
 { 
   SWITCH ($ADAdminArrayItem.objectClass)
    {
        'User' { [array]$ADAdminPropertyArray += Get-ADUser $ADAdminArrayItem.DistinguishedName -Prop * }
        'Computer' { [array]$ADAdminPropertyArray += Get-ADComputer $ADAdminArrayItem.DistinguishedName -Prop *  }
        'msDS-GroupManagedServiceAccount' { [array]$ADAdminPropertyArray += Get-ADServiceAccount $ADAdminArrayItem.DistinguishedName -Prop *  }
    }
 }

$ADAdminPropertyArray | Sort SamAccountName | Select SamAccountName,ObjectClass,PasswordLastSet,LastLogonDate,Enabled,DoesNotRequirePreAuth,UseDESKeyOnly,PasswordNeverExpires,info,description | Format-Table -AutoSize


