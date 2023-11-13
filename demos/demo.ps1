return 'This is a demo script file.'

<#
Learning Objective 1: Learn how to write efficient event log queries
Learning Objective 2: Learn how to effectively scale searching across the enterprise
Learning Objective 3: Learn how to use event subscribers
#>

#region basics

#list log
Get-WinEvent -ListLog *powershell*
Get-WinEvent -ListLog *
Get-WinEvent -ListLog * | Where-Object RecordCount -GT 0 |
Sort-Object RecordCount -Descending | Select-Object -First 20

#computer
Get-WinEvent -ListLog *active* -ComputerName dom1

#max events
Get-WinEvent 'Active Directory Web Services' -ComputerName dom1 -MaxEvents 10

#endregion

#region Basic filtering
help Get-WinEvent -Parameter FilterHashTable

#look at an object
Get-WinEvent System -max 1 | Select-Object *

#id
Get-WinEvent -FilterHashtable @{LogName = 'System'; ID = 6005, 6006 } -MaxEvents 10

#errors and warnings
Get-WinEvent -FilterHashtable @{LogName = 'System'; Level = 2 } -MaxEvents 10
Get-WinEvent -FilterHashtable @{LogName = 'System'; Level = 3 } -MaxEvents 10
Get-WinEvent -FilterHashtable @{LogName = 'System'; Level = 4 } -MaxEvents 10
Get-WinEvent -FilterHashtable @{LogName = 'System'; Level = 2, 3 } -MaxEvents 20

Get-WinEvent system -MaxEvents 1000 | Group-Object Level
Get-WinEvent system -MaxEvents 2000 | Group-Object -Property {
  Switch ($_.Level) {
    2 { 'Error' }
    3 { 'Warning' }
    4 { 'Information' }
    Default { $_.Level }
  }
} -NoElement

Get-WinEvent -FilterHashtable @{LogName = 'System'; Level = 2, 3; StartTime = (Get-Date).AddHours(-24) }

#endregion
#region Filtering with XPath

$xml = @'
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[Provider[@Name='Microsoft-Windows-Eventlog' or @Name='EventLog'] and TimeCreated[timediff(@SystemTime) &lt;= 2592000000]]]</Select>
  </Query>
</QueryList>
'@

Get-WinEvent -FilterXml $xml

<#
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">*[System[(EventID=6005 or EventID=6506) and TimeCreated[timediff(@SystemTime) &lt;= 2592000000]]]</Select>
  </Query>
</QueryList>
#>

#watch operators &lt; becomes <=
$xPath = '*[System[(EventID=6005 or EventID=6006) and TimeCreated[timediff(@SystemTime) <= 2592000000]]]'
Get-WinEvent -LogName System -FilterXPath $xpath

#region better event output
psedit .\Convert-EventLogRecord.ps1

. .\Convert-EventLogRecord.ps1

Get-WinEvent -LogName System -FilterXPath $xpath | Convert-EventLogRecord

#endregion

#endregion
#region Filtering at scale

# 6005 event log service started
# 6006 event log service stopped
# 6009 startup
$ID = @(1074, 6009, 6005, 6009)

$computers = 'dom1', 'dom2', 'srv1', 'srv2', 'dom1', 'dom2', 'srv1', 'srv2', 'dom1', 'dom2', 'srv1', 'srv2'
$splat = @{
  FilterHashTable = @{LogName = 'System'; ID = $ID }
  Computername    = $null
  MaxEvents       = 100
}
#not using MachineName property from the event log
#because it can change
$r = foreach ($c in $computers) {
  $splat['Computername'] = $c
  Get-WinEvent @splat |
  Select-Object -Property LogName, TimeCreated, ID, Message,
  @{Name = 'Computername'; Expression = { $c } }
}

#remoting
#there is overhead in setting up the PSSessions
$cred = Get-Credential company\artd

$sb = {
  Param([string]$LogName, [int[]]$ID, [int]$Max)
  $splat = @{
    FilterHashTable = @{LogName = $LogName; ID = $ID }
    MaxEvents       = $Max
  }
  Get-WinEvent @splat |
  Select-Object -Property LogName, TimeCreated, ID, Message,
  @{Name = 'Computername'; Expression = { $ENV:Computername } }
}

$icmSplat = @{
  ScriptBlock      = $sb
  Computername     = $computers
  Credential       = $cred
  HideComputerName = $True
  ArgumentList     = @('System', $ID, 100)
}

Invoke-Command @icmSplat | Select-Object -Property * -ExcludeProperty RunSpaceID

#jobs
psedit .\GetEventRecordByID.ps1
$r = $computers | ForEach-Object {
  Start-Job -FilePath .\GetEventRecordByID.ps1 -ArgumentList @('System', $ID, 100, $_, $cred)
} | Wait-Job | Receive-Job -Keep |
Select-Object -Property * -ExcludeProperty RunSpaceID

#threadjob
# Install-Module ThreadJobs
$q = $computers | ForEach-Object {
  Start-ThreadJob -FilePath .\GetEventRecordByID.ps1 -ArgumentList @('System', $ID, 100, $_, $cred)
} | Wait-Job | Receive-Job -Keep |
Select-Object -Property * -ExcludeProperty RunSpaceID

#foreach-parallel
$p = $computers | ForEach-Object -Parallel {
  $computer = $_
  $start = Get-Date
  Write-Host "[$((Get-Date).TimeOfDay)] Started querying $Computer" -ForegroundColor Green
  $ID = @(1074, 6009, 6005, 6009)
  $splat = @{
    FilterHashTable = @{LogName = $Using:LogName; ID = $ID }
    MaxEvents       = $Using:Max
    Computername    = $computer
    Credential      = $using:cred
  }
  Get-WinEvent @splat |
  Select-Object -Property LogName, TimeCreated, ID, Message,
  @{Name = 'Computername'; Expression = { $computer.toUpper() } }
  #I'm inserting a random delay to simulate a larger log collection
  Start-Sleep -Milliseconds (Get-Random -Minimum 1000 -Maximum 5000)
  Write-Host "[$((Get-Date).TimeOfDay)] Ended querying $Computer -> $(New-TimeSpan -Start $start -End (Get-Date))" -ForegroundColor Yellow
}

#endregion
#region Event log management

psedit .\get-eventlogusage.ps1
. .\get-eventlogusage.ps1

Get-EventLogUsage Application
Get-EventLogUsage -computer srv1, srv2 -EnabledOnly | Where-Object RecordCount -GT 0 | Out-GridView

#open event log viewer to see changes
Show-EventLog

#limit size
$l = Get-WinEvent -ListLog 'microsoft-windows-powershell/operational'
$l.MaximumSizeInBytes
# 15728640
$l.MaximumSizeInBytes = $l.MaximumSizeInBytes * 2
$l.SaveChanges()

#set logMode
Get-TypeMember System.Diagnostics.Eventing.Reader.EventLogMode
$l.LogMode = 'AutoBackup'
$l.SaveChanges()

#using EventLogSession
Get-TypeMember system.diagnostics.eventing.reader.EventlogSession
[System.Diagnostics.Eventing.Reader.EventLogSession]::new.OverloadDefinitions
$els = [System.Diagnostics.Eventing.Reader.EventLogSession]::new()
$els | Get-Member

#or use full filepath and FilePath
$els.GetLogInformation('microsoft-windows-powershell/operational', 'logName')

#backup
$els | Get-Member Export*
$els.ExportLog.OverloadDefinitions
#error if log already exists
$els.ExportLog('microsoft-windows-powershell/operational', 'logName', '*', 'c:\temp\psop-1.evtx')

#filtering needs XPath
Get-WinEvent -LogName 'microsoft-windows-powershell/operational' -FilterXPath '*[System[(EventID=4104)]]'
$els.ExportLog('microsoft-windows-powershell/operational', 'logName', '*[System[(EventID=4104)]]', 'c:\temp\psop-2.evtx')

$els.GetLogInformation('C:\temp\psop-1.evtx', 'FilePath')
$els.GetLogInformation('C:\temp\psop-2.evtx', 'FilePath')

#proof-of-concept
. .\demo-remoting-evtx-backup.ps1

#clear
$els.ClearLog.OverloadDefinitions
$els.ClearLog('microsoft-windows-powershell/operational', 'c:\temp\psop-all.evtx')
$els.GetLogInformation('C:\temp\psop-all.evtx', 'FilePath')
Get-WinEvent -LogName 'microsoft-windows-powershell/operational'

powershell -NoLogo -NoProfile -command '&{Get-Process p*}'
Get-WinEvent -LogName 'microsoft-windows-powershell/operational'

#region Event subscribers
psedit .\watch-EventLog.ps1

#endregion
