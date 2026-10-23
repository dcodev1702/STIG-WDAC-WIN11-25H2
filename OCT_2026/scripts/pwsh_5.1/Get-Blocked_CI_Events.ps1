# Windows PowerShell 5.1 edition - run in an elevated "Windows PowerShell" console or ISE.
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-CodeIntegrity/Operational'
    Id        = 3077
    StartTime = (Get-Date).AddMinutes(-15)
} -MaxEvents 10 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, Message | Format-List
