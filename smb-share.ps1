
function Add-Acl {
    $NewAcl = Get-Acl -Path $Path
    # Set properties
    $identity = $everyoneName
    $fileSystemRights = "FullControl"
    $type = "Allow"
    # Create new rule
    $fileSystemAccessRuleArgumentList = $identity, $fileSystemRights, 'ContainerInherit,ObjectInherit', 'None', $type
    $fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemAccessRuleArgumentList
    # Apply new rule
    $NewAcl.SetAccessRule($fileSystemAccessRule)
    Set-Acl -Path $Path -AclObject $NewAcl
}

function Set-ClientConfiguration {
    Set-SmbClientConfiguration -EnableInsecureGuestLogons $true -Force
    Set-SmbClientConfiguration -RequireSecuritySignature $false -Force
}

function Set-ServerConfiguration {
    Set-SmbServerConfiguration -RequireSecuritySignature $false -Force
    Set-SmbServerConfiguration -RejectUnencryptedAccess $false -force
    Set-SmbServerConfiguration -EncryptData $false -force
}

$Path = "C:\share_folder"
$everyoneSID = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$everyoneName = $everyoneSID.Translate([System.Security.Principal.NTAccount]).Value


New-Item -Path $Path -ItemType Directory -Force

New-SmbShare –Name "share" -Path $Path -FullAccess $everyoneName –EncryptData $true
Add-Acl
Set-ServerConfiguration

Enable-LocalUser -Name Guest

