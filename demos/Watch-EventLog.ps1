return 'This is a demo script file.'

# System.Diagnostics.Eventing.Reader.EventLogRecord

<#
PS Substack:\eventing-1> [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new.OverloadDefinitions
System.Diagnostics.Eventing.Reader.EventLogWatcher new(string path)
System.Diagnostics.Eventing.Reader.EventLogWatcher new(System.Diagnostics.Eventing.Reader.EventLogQuery eventQuery)
System.Diagnostics.Eventing.Reader.EventLogWatcher new(System.Diagnostics.Eventing.Reader.EventLogQuery eventQuery, System.Diagnostics.Eventing.Reader.EventBookmark bookmark)
System.Diagnostics.Eventing.Reader.EventLogWatcher new(System.Diagnostics.Eventing.Reader.EventLogQuery eventQuery, System.Diagnostics.Eventing.Reader.EventBookmark bookmark, bool readExistingEvents)
#>

# https://learn.microsoft.com/dotnet/api/system.diagnostics.eventing.reader.eventlogwatcher
# https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventing.reader.eventlogwatcher.eventrecordwritten?view=dotnet-plat-ext-6.0
# https://learn.microsoft.com/en-us/previous-versions/bb671202(v=vs.90)

$elw = [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new('System')
$elw.Enabled = $true
Register-ObjectEvent -InputObject $elw -EventName 'EventRecordWritten' -MessageData 'There is a new System event log record' -SourceIdentifier 'WatchSystem'

Get-EventSubscriber
#wait for an event
Get-Event
#doesn't include the message
(Get-Event)[-1].SourceEventArgs.EventRecord | select *

<#
PS Substack:\eventing-1> (Get-Event)[-1].SourceEventArgs.EventRecord | select *

Id                   : 114
Version              : 0
Qualifiers           :
Level                : 4
Task                 : 5
Opcode               : 123
Keywords             : 4611686018427387968
RecordId             : 104469
ProviderName         : Microsoft-Windows-HttpService
ProviderId           : dd5ef90a-6398-47a4-ad34-4dcecdef795f
LogName              : System
ProcessId            : 16948
ThreadId             : 11984
MachineName          : ThinkX1-JH
UserId               : S-1-5-20
TimeCreated          : 10/14/2022 10:28:18 AM
ActivityId           :
RelatedActivityId    :
ContainerLog         : System
MatchedQueryIds      : {}
Bookmark             : System.Diagnostics.Eventing.Reader.EventBookmark
LevelDisplayName     : Information
OpcodeDisplayName    : RemUrl
TaskDisplayName      : HTTP Configuration Property Trace Task
KeywordsDisplayNames : {Flagged on all HTTP events triggered on a URL group}
Properties           : {System.Diagnostics.Eventing.Reader.EventProperty,
                       System.Diagnostics.Eventing.Reader.EventProperty,
                       System.Diagnostics.Eventing.Reader.EventProperty,
                       System.Diagnostics.Eventing.Reader.EventProperty…}


#>

#get the record
(Get-Event WatchSystem).SourceEventArgs.EventRecord | ForEach-Object {
  Get-WinEvent -LogName $_.LogName -FilterXPath "*[System[EventRecordID=$($_.recordID)]]" -ComputerName $_.Machinename
} | Select-Object TimeCreated, Message | Format-Table -Wrap

Unregister-Event -SourceIdentifier WatchSystem
Get-Event | Remove-Event
cls
<#
Microsoft-Windows-PowerShell/Operational
or
PowerShellCore/Operational

event id 40962 - new PS session

#>

$elw = [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new('PowerShellCore/Operational')

$elw.Enabled = $true
Register-ObjectEvent -InputObject $elw -EventName 'EventRecordWritten' -MessageData Hey -SourceIdentifier 'WatchPSOperational'

(get-event).SourceEventArgs.eventRecord | group ID

Get-EventSubscriber | Unregister-Event
Get-Event | Remove-Event
# query for specific event
<#
[System.Diagnostics.Eventing.Reader.EventLogQuery]::new.OverloadDefinitions
System.Diagnostics.Eventing.Reader.EventLogQuery new(string path, System.Diagnostics.Eventing.Reader.PathType pathType)
System.Diagnostics.Eventing.Reader.EventLogQuery new(string path, System.Diagnostics.Eventing.Reader.PathType pathType, string query)

PathType is FilePath or LogName
Level 2 = Error
Level 3 = Warning
Level 4 = Information
#>

# *[System[(EventID=40961)]]

# $eventingQuery = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(" PowerShellCore/Operational","LogName","*[System[Level=4)]]")
# $eventingQuery = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(" PowerShellCore/Operational","LogName","*[System/Level=4]")

#need a valid XPath query
# $q= "*[System/Level=4]"
$q = '*[System[EventID=40962]]'
#test the query
Get-WinEvent -FilterXPath $q -LogName 'PowerShellCore/Operational' -MaxEvents 1

$eventingQuery = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new('PowerShellCore/Operational', 'LogName', $q)
$elw = [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new($EventingQuery)
$elw.Enabled = $true
Register-ObjectEvent -InputObject $elw -MessageData 'PS Ready' -SourceIdentifier NewPSCore -EventName EventRecordWritten

#Open a new PWSH session
pwsh.exe -nologo -noprofile -command "&{Get-Service bits}"
Get-Event
Function Get-WinEventRecord {
  [cmdletbinding()]
  Param(
    [Parameter(Position = 0, Mandatory, ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [int]$RecordID,
    [Parameter(Position = 1, Mandatory, ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [string]$LogName,
    [Parameter(ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [alias('MachineName')]
    [string]$Computername = $env:COMPUTERNAME
  )
  Begin {
    Write-Verbose "[$((Get-Date).TimeOfDay) BEGIN] Starting $($MyInvocation.MyCommand)"
  } #begin
  Process {
    Write-Verbose "[$((Get-Date).TimeOfDay) PROCESS] Getting record $RecordID from $LogName"
    Get-WinEvent -LogName $LogName -FilterXPath "*[System[EventRecordID=$($_.recordID)]]" -ComputerName $Computername
  } #process
  End {
    Write-Verbose "[$((Get-Date).TimeOfDay) END    ] Ending $($MyInvocation.MyCommand)"
  } #end
}

(Get-Event NewPSCore).SourceEventArgs.EventRecord | Get-WinEventRecord
(Get-Event NewPSCore).SourceEventArgs.EventRecord | Get-WinEventRecord |
Select-Object TimeCreated, ID, UserID

(Get-Event NewPSCore).SourceEventArgs.EventRecord | Get-WinEventRecord |
Select-Object TimeCreated, ID, Message,
@{Name = 'User'; Expression = { $_.UserId.Translate('System.Security.principal.NTAccount').value } }

# $r.UserId.Translate("System.Security.principal.NTAccount").value
$x = @'
<QueryList>
  <Query Id="0" Path="PowerShellCore/Operational">
    <Select Path="PowerShellCore/Operational">*[System[(EventID=40962)]]</Select>
  </Query>
</QueryList>
'@

Get-WinEvent -FilterXml $x -MaxEvents 5 -ComputerName win10

Get-WinEvent -FilterXPath $q

# Microsoft-Windows-PowerShell/Operational
# 53504  Windows PowerShell has started an IPC listening thread

#test filter
$q = '*[System[EventID=53504]]'
Get-WinEvent -FilterXPath $q -LogName 'Microsoft-Windows-PowerShell/Operational' -max 1 -ComputerName srv1

$eventingQuery = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new('Microsoft-Windows-PowerShell/Operational', 'LogName', $q)
$elw = [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new($EventingQuery)
$elw.Enabled = $true
Register-ObjectEvent -InputObject $elw -MessageData 'PS Listening' -SourceIdentifier NewPS -EventName EventRecordWritten

$q = '*[System[EventID=53504]]'
$eventingQuery = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new('Microsoft-Windows-PowerShell/Operational', 'LogName', $q)

#Connect to a remote computer
<#
[System.Diagnostics.Eventing.Reader.EventLogSession]::new.OverloadDefinitions
System.Diagnostics.Eventing.Reader.EventLogSession new()
System.Diagnostics.Eventing.Reader.EventLogSession new(string server)
System.Diagnostics.Eventing.Reader.EventLogSession new(string server, string domain, string user, securestring password, System.Diagnostics.Eventing.Reader.SessionAuthentication logOnType)
Logon type: Default, Kerberos,NTLM,Negotiate
#>

$eventingQuery.session = [System.Diagnostics.Eventing.Reader.EventLogSession]::new('SRV1')
$elw = [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new($EventingQuery)
$elw.Enabled = $true
Register-ObjectEvent -InputObject $elw -MessageData 'PS Listening' -SourceIdentifier NewPS -EventName EventRecordWritten

Get-Event -SourceIdentifier newps

Invoke-command { gsv m* } -ComputerName srv1

(Get-Event -SourceIdentifier NewPS).SourceEventArgs.EventRecord | select *

(Get-Event -SourceIdentifier NewPS).SourceEventArgs.EventRecord |
Get-WinEventRecord | Select-Object TimeCreated, ID, Message,
@{Name = 'User'; Expression = { $_.UserId.Translate('System.Security.principal.NTAccount').value } },
MachineName

<# $x = @"
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-PowerShell/Operational">
    <Select Path="Microsoft-Windows-PowerShell/Operational">*[System[(EventID=53504)]]</Select>
  </Query>
</QueryList>
"@

Get-WinEvent -FilterXml $x -MaxEvents 5 -ComputerName SRV1 #>

#demo with credentials
Get-WinEvent -FilterHashtable @{LogName = 'security'; id = 4738 } -computer dom1 -MaxEvents 5
$q = '*[System[EventID=4738]]'
$eventingQuery = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new('Security', 'LogName', $q)

$cred = Get-Credential company\administrator
$dom, $user = $cred.UserName.split('\')
<#
 System.Diagnostics.Eventing.Reader.EventLogSession new(
  string server,
  string domain,
  string user,
  securestring password,
  System.Diagnostics.Eventing.Reader.SessionAuthentication logOnType
  )
#>
#this works best from a domain member
$eventingQuery.session = [System.Diagnostics.Eventing.Reader.EventLogSession]::new('DOM1', $dom, $user, $cred.Password, 'default')
$elw = [System.Diagnostics.Eventing.Reader.EventLogWatcher]::new($EventingQuery)
$elw.Enabled = $true
Register-ObjectEvent -InputObject $elw -MessageData 'An account was changed' -SourceIdentifier ADChange -EventName EventRecordWritten

$p = ConvertTo-SecureString -AsPlainText -Force -String "P@sswOrdMonkey"
Get-ADUser kmoshos -server DOM1 | Set-ADAccountPassword -NewPassword $p -Server DOM1.company.pri

Get-Event
<#
PS C:\> (get-event).sourceeventargs.eventrecord | fl *


Id                   : 4738
Version              : 0
Qualifiers           :
Level                : 0
Task                 : 13824
Opcode               : 0
Keywords             : -9214364837600034816
RecordId             : 637037
ProviderName         : Microsoft-Windows-Security-Auditing
ProviderId           : 54849625-5478-4994-a5ba-3e3b0328c30d
LogName              : Security
ProcessId            : 572
ThreadId             : 1732
MachineName          : DOM1.Company.Pri
UserId               :
TimeCreated          : 10/18/2022 7:41:01 AM
ActivityId           :
RelatedActivityId    :
ContainerLog         : Security
MatchedQueryIds      : {}
Bookmark             : System.Diagnostics.Eventing.Reader.EventBookmark
LevelDisplayName     : Information
OpcodeDisplayName    : Info
TaskDisplayName      : User Account Management
KeywordsDisplayNames : {Audit Success}
Properties           : {System.Diagnostics.Eventing.Reader.EventProperty,
                       System.Diagnostics.Eventing.Reader.EventProperty,
                       System.Diagnostics.Eventing.Reader.EventProperty,
                       System.Diagnostics.Eventing.Reader.EventProperty...}

The event is not exactly the same as the event log

 PS C:\> (get-event).sourceeventargs.eventrecord.properties.value | where {$_ -ne "-"}
D.Hamsher
COMPANY

BinaryLength AccountDomainSid                        Value
------------ ----------------                        -----
          28 S-1-5-21-3554402041-35902484-4286231435 S-1-5-21-3554402041-35902484-4286231435-1144
          28 S-1-5-21-3554402041-35902484-4286231435 S-1-5-21-3554402041-35902484-4286231435-1105
ArtD
COMPANY
151546039
10/18/2022 7:41:01 AM

#>

#FUNCTION TO PARSE SOURCEEVENTARGS

Function Get-EventRecord {
  [cmdletbinding()]
  Param(
    [Parameter(Position = 0, Mandatory, ValueFromPipeline)]
    [ValidateNotNullOrEmpty()]
    [System.Management.Automation.PSEventArgs]$InputObject
  )
  Begin {
    Write-Verbose "[$((Get-Date).TimeOfDay) BEGIN] Starting $($MyInvocation.MyCommand)"
  } #begin
  Process {
    Write-Verbose "[$((Get-Date).TimeOfDay) PROCESS] Processing"
    $InputObject.SourceEventArgs.EventRecord
  } #process
  End {
    Write-Verbose "[$((Get-Date).TimeOfDay) END    ] Ending $($MyInvocation.MyCommand)"
  } #end
}

Get-Event ADChange | Get-EventRecord | Sort-Object TimeCreated -Descending |
Select-Object TimeCreated, ID, TaskDisplayName,
@{Name = 'UserAccount'; Expression = { $_.properties.value[1] } },
@{Name = 'Administrator'; Expression = { $_.properties.value[5] } },
RecordID | Format-Table

#xpath is case-sensitive
Get-WinEvent -LogName Security -FilterXPath '*[System[EventRecordID=637037]]' -ComputerName dom1

[xml]$e = (Get-WinEvent -LogName Security -FilterXPath '*[System[EventRecordID=637037]]' -ComputerName dom1).toxml()
<#
PS C:\> $e.event.eventdata.data

Name                #text
----                -----
Dummy               -
TargetUserName      D.Hamsher
TargetDomainName    COMPANY
TargetSid           S-1-5-21-3554402041-35902484-4286231435-1144
SubjectUserSid      S-1-5-21-3554402041-35902484-4286231435-1105
SubjectUserName     ArtD
SubjectDomainName   COMPANY
SubjectLogonId      0x90868b7
PrivilegeList       -
SamAccountName      -
DisplayName         -
UserPrincipalName   -
HomeDirectory       -
HomePath            -
ScriptPath          -
ProfilePath         -
UserWorkstations    -
PasswordLastSet     10/18/2022 7:41:01 AM
AccountExpires      -
PrimaryGroupId      -
AllowedToDelegateTo -
OldUacValue         -
NewUacValue         -
UserAccountControl  -
UserParameters      -
SidHistory          -
LogonHours          -

#>
