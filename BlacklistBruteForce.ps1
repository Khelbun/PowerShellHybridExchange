<#
Author: Eric Sobkowicz
Created: May 12, 2018
Last Updated By: Eric Sobkowicz
Last Updated: October 4,2018

Purpose: 
    Retrieves all the 411 events from the event log, converts the retrieved objects to XML, then parses the XML.  
    Takes the results and looks for any Source IPs outside the specified whitelist with bad password attempts over the specified threshold.
    Connects to O365 and adds all the IPs that meet the above conditions to the specified Client Access rule as bad IPs.
    Outputs the following log files:
        - "BlacklistLog_Timestamp.txt" - The general log file with the actions taken for the script run.
        - "RawFiles\IPBlacklistRulePreChanges_Timestamp.xml" - An XML of the current IP Blacklist rule before changes.
        - "RawFiles\IPBlacklistRulePostChanges_Timestamp.xml" - An XML of the IP Blacklist rule after any changes, is not created if no changes were made.
        - "RawFiles\IPBlacklistEvents_Timestamp.csv" - The full event data used for all caluclations.
        - "RawFiles\IPBlacklistIPCount_Timestamp.csv" - The full count of how often each IP shows up in the IPBlacklistEvents file.
        - "RawFiles\IPBlacklistNewBadIPsFound_Timestamp.csv" - The list of new IPs found not on the whitelist or currently blacklisted that exceeded the Threshold
            for  bad logins.  Is not created if there are no IPs that meet the criteria.

Requirements:
    This must be ran with administrator permissions on the ADFS server.
    The RawFiles folder must exist under the Output directory.
    The Client Access rule needs to already exist and be setup to block access to the desired services etc.
    Needs a credential object exported to XML using the Export-Clixml command on the system and under the user who will be running the script.
    Best used by setting a scheduled task to automate the running of the script, needs to be run with highest permissions, and as the user used to export the credential object.

Variables:
    $Output - The path to store the log files in, e.g. C:\BlacklistLogs.
    $Whitelist - Array of IPs that are to be ignored if over the specified threshold, enter multiple iPs in the format @("IP","IP","IP").
    $Threshold - Number of bad attempts for a specific IP before it gets actioned.
    $CredentialLocation - The location of the credential xml object to use when connecting to O365.  NOTE: this object needs to be created on the computer that will be running
        the script using the credentials it will be running as.
    $BlacklistRuleName - The name of the IP blacklist client access rule in O365.
    $EmailTo - The email address(es) to send the email alert to if there are any changes made to the blacklist rule.  This can be a single address, or an array of addresses.
    $EmailFrom - What address to send the email alert from.
    $SMTPMailServer - The address of the SMTP mail server to use.
#>

# Set the error action to stop to allow handling of non-terminating errors.
$ErrorActionPreference = "Stop"

# Variables
$Output = "C:\Scripts\BlacklistLogs"
$Whitelist = @("IP","IP")
$Threshold = 25
$CredentialLocation = "C:\Scripts\Creds.xml"
$BlacklistRuleName = "IPBlacklist"
$EmailTo = "email@domain.com"
$EmailFrom = "IPBlacklistScript@domain.com"
$SMTPMailServer = "mailserver.domain.com"

function Main
{
# Create variables to track if various steps were successful or not and set the initial values.
$BlacklistRuleChangesMade = $false
$UpdateRuleSuccessful = $true
$ExportRuleXMLSuccessful = $true
$ExportEventsCSVSuccessful = $true
$ExportIPCountCSVSuccessful = $true
$ExportBadIPsCSVSuccessful = $true
$SendEmailSuccessful = $true

# Check the $Output variable for a trailing \ and adds it if it's missing
if ($Output.Substring($Output.Length-1) -ne "\") 
    {
    $Output = $Output + "\"
    }

# Creates the Timestamp to be used on all the logs and output files
$TimeStamp = Get-Date -Format o | ForEach-Object {$_ -replace ":", "."}
$TimeStamp = $TimeStamp.Substring(0,16)

# Create the variables for the outputs of all the log files.
$MainLog = $Output + "BlacklistLog_" + $TimeStamp + ".txt"
$RulePreChangesXML = $Output + "RawFiles\IPBlacklistRulePreChanges_" + $TimeStamp + ".XML"
$RulePostChangesXML = $Output + "RawFiles\IPBlacklistRulePostChanges_" + $TimeStamp + ".XML"
$EventsCSV = $Output + "RawFiles\IPBlacklistEvents_" + $TimeStamp + ".csv"
$IPCountCSV = $Output + "RawFiles\IPBlacklistIPCount_" + $TimeStamp + ".csv"
$BadIPsCSV = $Output + "RawFiles\IPBlacklistNewBadIPsFound_" + $TimeStamp + ".csv"

# Create the Main Logfile.
New-Item $MainLog -ItemType File

# Pulls the events in and creates the credential object.
try 
    {
    $Events = Get-WinEvent -FilterHashtable @{Logname='Security';Id=411}
    }
catch 
    {
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Log -Level FATAL -logfile $MainLog -Message "There was an error parsing the event logs, exiting script."
    Write-Log -Level FATAL -logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
    Write-Log -Level FATAL -logfile $MainLog -Message "Script terminated before changes were made to the Client Access Rule due to FATAL error"
    Send-MailMessage -From $EmailFrom -To $EmailTo -Subject "Error running Client Access Rule IP Blacklist Script." -Body "There was an error running the Client Access Rule IP Blacklist Script, please see the attached log file for details." -Attachments $MainLog -SmtpServer $SMTPMailServer
    Exit
    }
Write-Log -logfile $MainLog -Message "Successfully retrieved the event logs."

try 
    {
    $Cred = Import-Clixml $CredentialLocation
    }
catch 
    {
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Log -Level FATAL -logfile $MainLog -Message "There was an error retrieving the credentials to connect to O365."
    Write-Log -Level FATAL -logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
    Write-Log -Level FATAL -logfile $MainLog -Message "Script terminated before changes were made to the Client Access Rule due to FATAL error"
    Send-MailMessage -From $EmailFrom -To $EmailTo -Subject "Error running Client Access Rule IP Blacklist Script." -Body "There was an error running the Client Access Rule IP Blacklist Script, please see the attached log file for details." -Attachments $MainLog -SmtpServer $SMTPMailServer
    Exit
    }
Write-Log -logfile $MainLog -Message "Successfully retrieved the O365 Credentials."

# Creates an empty variable length array to hold the results of parsing the Event logs.
[System.Collections.ArrayList]$EventResults = @([psobject])

# Convert each event to XML and parse out the desired data to a new PSObject.
foreach ($Event in $Events)
    {
    try 
        {
        $Temp1,$Temp2,$Temp3,$Temp4 = $null
        $XML = [xml]$Event.ToXml()
        $Temp1,$Temp2 = $XML.event.EventData.Data[4].split(',')
        $Temp3,$Temp4 = $XML.event.EventData.Data[2].split('-')
        $TempResults = New-Object psobject
        $TempResults | Add-Member -Type NoteProperty -Name ActivityID -Value $XML.event.EventData.Data[0]
        $TempResults | Add-Member -Type NoteProperty -Name EventTime -Value $XML.event.System.TimeCreated.SystemTime
        $TempResults | Add-Member -Type NoteProperty -Name SourceIP -Value $Temp1
        $TempResults | Add-Member -Type NoteProperty -Name ProxyIP -Value $Temp2
        $TempResults | Add-Member -Type NoteProperty -Name User -Value $Temp3
        $TempResults | Add-Member -Type NoteProperty -Name Error -Value $Temp4
        $EventResults+=$TempResults    
        }
    catch 
        {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Log -Level FATAL -logfile $MainLog -Message "There was an error while Parsing the event logs."
        Write-Log -Level FATAL -logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
        Write-Log -Level FATAL -logfile $MainLog -Message "Script terminated before changes were made to the Client Access Rule due to FATAL error"
        Send-MailMessage -From $EmailFrom -To $EmailTo -Subject "Error running Client Access Rule IP Blacklist Script." -Body "There was an error running the Client Access Rule IP Blacklist Script, please see the attached log file for details." -Attachments $MainLog -SmtpServer $SMTPMailServer
        Exit
        }

    }
Write-Log -logfile $MainLog -Message "Successfully Parsed the Event Logs."

# Remove the first line of the $Results array as it's always blank
$EventResults.RemoveAt(0)

# Perform a count of how often each IP has a bad password attempt and store it in a variable.
try 
    {
    $IPCount = $EventResults | Group-Object SourceIP | Sort-Object Count -Descending
    }
catch 
    {
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Log -Level FATAL -logfile $MainLog -Message "There was an error while getting the count of how many bad password attempts each IP had."
    Write-Log -Level FATAL -logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
    Write-Log -Level FATAL -logfile $MainLog -Message "Script terminated before changes were made to the Client Access Rule due to FATAL error"
    Send-MailMessage -From $EmailFrom -To $EmailTo -Subject "Error running Client Access Rule IP Blacklist Script." -Body "There was an error running the Client Access Rule IP Blacklist Script, please see the attached log file for details." -Attachments $MainLog -SmtpServer $SMTPMailServer
    Exit
    }
Write-Log -logfile $MainLog -Message "Successfully created the count of how many bad password attempts there were for each IP."

# Connect to O365
try{
    $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $Cred -Authentication Basic -AllowRedirection
    Import-PSSession $Session -AllowClobber
}
catch{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Log -Level FATAL -logfile $MainLog -Message "There was an error while connecting to O365."
    Write-Log -Level FATAL -logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
    Write-Log -Level FATAL -logfile $MainLog -Message "Script terminated before changes were made to the Client Access Rule due to FATAL error"
    Send-MailMessage -From $EmailFrom -To $EmailTo -Subject "Error running Client Access Rule IP Blacklist Script." -Body "There was an error running the Client Access Rule IP Blacklist Script, please see the attached log file for details." -Attachments $MainLog -SmtpServer $SMTPMailServer
    Exit
}

# Get the current list of bad and good IPs from the blacklist rule.
try 
    {
    $BlacklistRule = Get-ClientAccessRule $BlacklistRuleName
    $KnownBadIPs = $BlacklistRule.AnyOfClientIPAddressesOrRanges
    $KnownGoodIPs = $BlacklistRule.ExceptAnyOfClientIPAddressesOrRanges
    $BlacklistRule | Export-Clixml $RulePreChangesXML
    }
catch 
    {
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Log -Level FATAL -logfile $MainLog -Message "There was an error while getting the existing Blacklist rule from O365."
    Write-Log -Level FATAL -logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
    Write-Log -Level FATAL -logfile $MainLog -Message "Script terminated before changes were made to the Client Access Rule due to FATAL error"
    Send-MailMessage -From $EmailFrom -To $EmailTo -Subject "Error running Client Access Rule IP Blacklist Script." -Body "There was an error running the Client Access Rule IP Blacklist Script, please see the attached log file for details." -Attachments $MainLog -SmtpServer $SMTPMailServer
    Remove-PSSession $Session
    Exit
    }
Write-Log -logfile $MainLog -Message "Successfully retrieved the current Blacklist Client Access Rule from O365 and Backed up an XML of it to the RawFiles directory."

# Checks the IPCount for any IPs that are over the threshold and not on the whitelist and adds them to a logging variable.
$NewBadIPs = @()
$NewBadIPCount = 0
foreach ($IP in $IPCount)
    {
    if ($IP.count -ge $Threshold)
        {
        if (!($Whitelist.Contains($IP.Name)) -and !($KnownBadIPs.Contains($IP.Name)) -and !($KnownGoodIPs.Contains($IP.Name)))
            {
            $TempResults = New-Object psobject
            $TempResults | Add-Member -Type NoteProperty -Name IP -Value $IP.Name
            $TempResults | Add-Member -Type NoteProperty -Name Count -Value $IP.Count
            $NewBadIPs+=$TempResults
            Write-Log -logfile $MainLog -Message "New Bad IP $($IP.Name) found with bad login count of $($IP.Count)."
            $NewBadIPCount ++
            }
        }
    else 
        {
        break
        }
    }
Write-Log -logfile $MainLog -Message "Finished checking for New Bad IPs, Number of new BadIPs found: $NewBadIPCount"

# Adds the new Bad IPs to Blacklist Rule.
if ($NewBadIPs[0] -ne $null)
    {
    try 
        {
        $CombinedBadIPs = $KnownBadIPs += $NewBadIPs.IP
        Set-ClientAccessRule $BlacklistRuleName -AnyOfClientIPAddressesOrRanges $CombinedBadIPs -Confirm:$false
        }
    catch
        {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Log -Level ERROR -logfile $MainLog -Message "There was an error while adjusting the Blacklist Client Access Rule."
        Write-Log -Level ERROR -logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
        Send-MailMessage -From $EmailFrom -To $EmailTo -Subject "Error running Client Access Rule IP Blacklist Script." -Body "There was an error running the Client Access Rule IP Blacklist Script, please see the attached log file for details." -Attachments $MainLog -SmtpServer $SMTPMailServer
        $UpdateRuleSuccessful = $false
        }
    if ($UpdateRuleSuccessful)
        {
        Write-Log -logfile $MainLog -Message "Successfully updated the Blacklist Client Access Rule with the new Bad IPs."
        $BlacklistRuleChangesMade = $true
        }
    }

# Output the data files to the log location specified in the $Output Variable
if ($BlacklistRuleChangesMade)
    {
    try
        {
        Get-ClientAccessRule $BlacklistRuleName | Export-Clixml $RulePostChangesXML
        }
    catch
        {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Log -Level ERROR -logfile $MainLog -Message "There was an error while Exporting the updated Blacklist rule to XML."
        Write-Log -Level ERROR -logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
        Send-MailMessage -From $EmailFrom -To $EmailTo -Subject "Error running Client Access Rule IP Blacklist Script." -Body "There was an error running the Client Access Rule IP Blacklist Script, please see the attached log file for details." -Attachments $MainLog -SmtpServer $SMTPMailServer
        $ExportRuleXMLSuccessful = $false
        }
    if ($ExportRuleXMLSuccessful)
        {
        Write-Log -logfile $MainLog -Message "Successfully Exported the updated Blacklist rule to XML."
        }
    }

try
    {
    $EventResults | Select-Object ActivityID,EventTime,SourceIP,ProxyIP,User,Error | Export-Csv $EventsCSV -NoTypeInformation
    }
catch
    {
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Log -Level ERROR -logfile $MainLog -Message "There was an error while Exporting the Events to CSV."
    Write-Log -Level ERROR -logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
    Send-MailMessage -From $EmailFrom -To $EmailTo -Subject "Error running Client Access Rule IP Blacklist Script." -Body "There was an error running the Client Access Rule IP Blacklist Script, please see the attached log file for details." -Attachments $MainLog -SmtpServer $SMTPMailServer
    $ExportEventsCSVSuccessful = $false
    }
if ($ExportEventsCSVSuccessful) 
    {
    Write-Log -logfile $MainLog -Message "Successfully Exported the Events to CSV."
    }

try
    {
    $IPCount | Select-Object Count,Name | Export-Csv $IPCountCSV -NoTypeInformation
    }
catch
    {
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Log -Level ERROR -logfile $MainLog -Message "There was an error while Exporting the IP Count to CSV."
    Write-Log -Level ERROR -logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
    Send-MailMessage -From $EmailFrom -To $EmailTo -Subject "Error running Client Access Rule IP Blacklist Script." -Body "There was an error running the Client Access Rule IP Blacklist Script, please see the attached log file for details." -Attachments $MainLog -SmtpServer $SMTPMailServer
    $ExportIPCountCSVSuccessful = $false
    }
if ($ExportIPCountCSVSuccessful)
    {
    Write-Log -logfile $MainLog -Message "Successfully Exported the IPCount to CSV."
    }

if ($NewBadIPs[0] -ne $null)
    {
    try
        {
        $NewBadIPs | Select-Object IP,Count | Export-Csv $BadIPsCSV -NoTypeInformation
        }
    catch
        {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Log -Level ERROR -logfile $MainLog -Message "There was an error while Exporting the New Bad IPs to CSV."
        Write-Log -Level ERROR -logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
        Send-MailMessage -From $EmailFrom -To $EmailTo -Subject "Error running Client Access Rule IP Blacklist Script." -Body "There was an error running the Client Access Rule IP Blacklist Script, please see the attached log file for details." -Attachments $MainLog -SmtpServer $SMTPMailServer
        $ExportBadIPsCSVSuccessful = $false
        }
    if ($ExportBadIPsCSVSuccessful)
        {
        Write-Log -logfile $MainLog -Message "Successfully Exported the New Bad IPs to CSV."
        }
    }
else 
    {
    Write-Log -logfile $MainLog -Message "No New Bad IPs to export to CSV, file not created."
    }

<# 
If there were changes made to the blacklist, sends out an email with the log file attached and the new bad IPs in the body.  Comment out the following block if you do not want to 
send email alerts.  Currently set to use an anonymous email relay, can be updated to connect to a relay requiring authentication or a secure connection by adding the 
-Credential and -usessl paramaters respectively.  See the documentation of the Send-MailMessage command for full details.
#>
if ($BlacklistRuleChangesMade)
    {
    try
        {
        Send-MailMessage -From $EmailFrom -To $EmailTo -Subject "New Bad IP Blacklisted" -Body "The following new bad IP(s) were found and blacklisted: $($NewBadIPs.IP)" -Attachments $MainLog -SmtpServer $SMTPMailServer
        }
    catch
        {
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Log -Level ERROR -logfile $MainLog -Message "There was an error while sending the New Bad IPs email."
        Write-Log -Level ERROR -logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
        Send-MailMessage -From $EmailFrom -To $EmailTo -Subject "Error running Client Access Rule IP Blacklist Script." -Body "There was an error running the Client Access Rule IP Blacklist Script, please see the attached log file for details." -Attachments $MainLog -SmtpServer $SMTPMailServer
        $SendEmailSuccessful = $false
        }
    if ($SendEmailSuccessful)
        {
        Write-Log -logfile $MainLog -Message "Successfully sent the New Bad IPs email."
        }
    }

# Closes out the PSSession to O365.
Remove-PSSession $Session
}

<#
Author: Unknown
Created: May 12, 2018
Last Updated By: Eric Sobkowicz
Last Updated: May 12, 2018

Purpose: 
    Takes the input of the logging level, message, and logfile then outputs it to the specified logfile, if no logfile specified it outputs to the powershell window, if no
    logging level specified it uses the value of INFO.

Requirements: 
    N/A

Variables:
    $Level - Parameter - Accepts one of the following values: "INFO","WARN","ERROR","FATAL","DEBUG"; default value is INFO if none is specified.
    $Message - Parameter - Accepts any string.
    $logfile - Parameter - the full path and flilename of the logfile, e.g. "C:\temp\log.txt"
#>
Function Write-Log 
{
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$False)]
    [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
    [String]
    $Level = "INFO",

    [Parameter(Mandatory=$True)]
    [string]
    $Message,

    [Parameter(Mandatory=$False)]
    [string]
    $logfile
    )

    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $Line = "$Stamp $Level $Message"
    If($logfile) {
        Add-Content $logfile -Value $Line
    }
    Else {
        Write-Output $Line
    }
}

# Runs the Main function
# Putting the main code within a function and calling it at the end of the script allows for the main code to be at the top of the script and all other functions below it
Main