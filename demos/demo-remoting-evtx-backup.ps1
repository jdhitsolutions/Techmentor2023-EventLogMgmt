return "This is a demo script file."

$sb = {
    param (
        [string]$Drive = 'Q',
        [string]$Path,
        [PSCredential]$Credential
    )

    $backupList = @(
        'Microsoft-Windows-WinRM/Operational',
        'Application',
        'System'
    )

    #mapping a drive with credentials to get around the 2nd hop problem
    $username = $Credential.Username
    $Password = $Credential.GetNetworkCredential.Password
    [void](New-PSDrive -name $Drive -psprovider FileSystem -root $Path -credential $Credential)

    $es = [System.Diagnostics.Eventing.Reader.EventLogSession]::new()
    foreach ($item in $backupList) {
        $fileName = "{0}-{1}_{2}.evtx" -f $env:computername,($item -replace "\/","-"),(Get-Date -Format "yyyyMMddhhmm")
        $backup = Join-Path -path "C:\" -childPath $FileName
        Write-Host "[$($env:COMPUTERNAME)] Backing up $item to $backup" -foreground yellow
        $es.ExportLog($item, 'logname', '*', $backup)
        if (Test-Path "$($drive):\") {
            #move to network location
            Get-ChildItem c:\*.evtx | Move-Item -Destination "$($drive):\" -force -passthru | Out-Host
        }
        else {
            Write-Warning "Failed to find $($drive):\"
        }
    }

}

$computername = 'SRV1', 'SRV2','DOM1','DOM2'

$BackPath = '\\SRV2\EventBackup'

$cred = Get-Credential company\artd
Invoke-Command $sb -ComputerName $computername -ArgumentList @('Q', $BackPath, $cred) -credential $cred

<#
#demo setup
invoke-Command { mkdir c:\EventBackup; New-SMBshare -Name EventBackup -Path c:\EventBackup -Description "company log backups" -FullAccess "Company\Domain Admins" } -ComputerName srv2

#>