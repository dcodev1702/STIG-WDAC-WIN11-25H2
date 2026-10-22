Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id        = 3077
    StartTime = (Get-Date).AddMinutes(-15)
} -MaxEvents 10 | Select-Object TimeCreated, Id, Message | Format-List
