#####################
#
# Parses ACL and ACL Roles table exports and produces
# a CSV file containing Table, Role, and Operation
#
# Note:  CSV file will only contain table-level ACLs
#
# Usage:
#
#     1. Modify the values in the configuration file
#        (multiple entries in the checkRoles array are allowed)
#
#     2. Run the code in this file making sure the paths in the
#        configuration file are accessible
#
# NOTE:  back-slashes in configuration file must be escaped ("c:\files" becomes "c:\\files")
#
################
$configFilePath = 'aclrole.json'
 
$config = (Get-Content $configFilePath | ConvertFrom-Json)
 
$aclrole = [xml](Get-Content  "$($config.aclRoleFile)")
$validACLRoles = ($aclrole.unload.sys_security_acl_role | Where-Object { -not ($_.sys_security_acl.display_value -match '\.') -and ($_.sys_user_role.display_value -in $config.checkRoles)})
 
$aclOpCache = @{}
 
$acls = [xml](Get-Content "$($config.aclFile)")
 
$acls.unload.sys_security_acl | ForEach-Object {
    $aclOpCache[$_.sys_id] = $_.operation.display_value
}
 
$validACLRoles | ForEach-Object {
    $thisRoleName = $_.sys_user_role.name
    $thisAclSysId = $_.sys_security_acl.'#text'
    $validACLRoles | Where-Object { $_.sys_user_role.name -eq $thisRoleName } | ForEach-Object {
        [pscustomobject]@{
            "Table" = $_.sys_security_acl.display_value
            "Role" = $thisRoleName
            "Operation" = $aclOpCache[$thisAclSysId]
        }
    }
} | ConvertTo-Csv | Out-File "$($config.csvFile)"
