Param
(
    [Parameter(Mandatory)]
    [string]$LogName,
    [Parameter(Mandatory)]
    [int[]]$ID,
    [int]$Max = 1000,
    [string]$Computername = $ENV:COMPUTERNAME,
    [PSCredential]$Credential
)
$splat = @{
    FilterHashTable = @{LogName = $LogName; ID = $ID }
    Computername    = $ComputerName
    MaxEvents       = $Max
}

If ($Credential.UserName) {
    $splat.Add('Credential', $Credential)
}

Get-WinEvent @splat |
Select-Object -Property LogName, TimeCreated, ID, Message,
@{Name = 'Computername'; Expression = { $Computername.ToUpper() }}