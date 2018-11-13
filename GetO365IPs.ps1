<#
Author: Eric Sobkowicz
Created: November 13, 2018
Last Updated By: Eric Sobkowicz
Last Updated: November 13, 2018

Purpose:
    Checks the currently available version of the O365 IP web list, if it's newer than the currently used version then it pulls down the latest one and updates the lists.  Stores all IP lists in UTF-8 format with Unix style new line to avoid issues with use in some firewall devices.
Requirements:
    None
Variables:
    $ScriptFolder - Path to the script and its config files, generates a new config file if one is missing.
    $OutputFolder - Path to store all the output files.
    $LoggingFolder - Path to store the log files.
#>
# Set the error action to stop to allow handling of non-terminating errors, this allows writing to the log file on a non-terminating error with a try catch codeblock.
$ErrorActionPreference = "Stop"

# Variables
$ScriptFolder = ""
$OutputFolder = ""
$LoggingFolder = ""

function Main{
# Check the path variables for a trailing \ and adds it if it's missing.
if ($OutputFolder.Substring($OutputFolder.Length-1) -ne "\") {
    $OutputFolder = $OutputFolder + "\"
}
if ($ScriptFolder.Substring($ScriptFolder.Length-1) -ne "\") {
    $ScriptFolder = $ScriptFolder + "\"
}
if ($LoggingFolder.Substring($LoggingFolder.Length-1) -ne "\") {
    $LoggingFolder = $LoggingFolder + "\"
}
# Creates the Timestamp to be used on all the logs and output files
$TimeStamp = Get-Date -Format o | ForEach-Object {$_ -replace ":", "."}
$TimeStamp = $TimeStamp.Substring(0,16)

# Create the variables for the outputs of all the log files
$MainLog = $LoggingFolder + "GetO365IPs" + $TimeStamp + ".log"

# Create the Main Logfile.
New-Item $MainLog -ItemType File

# Check the Script folder to see if the config file exists, reads in the values if it does, creates a new config file if it doesn't.
$ScriptConfigPath = $ScriptFolder + "GetO365IPs.xml"
if (Test-Path $ScriptConfigPath){
    try{
        $ScriptConfig = Import-Clixml $ScriptConfigPath
    }
    catch{
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Log -Level FATAL -Logfile $MainLog -Message "There was an error Importing the Script config from $ScriptConfigPath."
        Write-Log -Level FATAL -Logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
        Write-Log -Level FATAL -Logfile $MainLog -Message "Script terminated due to FATAL error"
        Exit
    }
    Write-Log -Level INFO -Logfile $MainLog -Message "Successfully imported the past config from $ScriptConfigPath "
}
else {
    $ScriptConfig = New-Object psobject
    $ScriptConfig | Add-Member -Type NoteProperty -Name GUID -Value (New-Guid)
    $ScriptConfig | Add-Member -Type NoteProperty -Name LastVersion -Value "0000000000"
    Write-Log -Level INFO -Logfile $MainLog -Message "The config file $ScriptConfigPath did not exist, generated new config."
}

# Get the current version of the O365 IP list and check to see if it's newer than the LastVersion pulled from the config file.
try{
    $URL = "https://endpoints.office.com/version/Worldwide?ClientRequestId=" + $ScriptConfig.GUID
    $ListVersion = Invoke-RestMethod $URL
}
catch{
    $ErrorMessage = $_.Exception.Message
    $FailedItem = $_.Exception.ItemName
    Write-Log -Level FATAL -Logfile $MainLog -Message "There was an error retrieving the current version of the IP list from Microsoft."
    Write-Log -Level FATAL -Logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
    Write-Log -Level FATAL -Logfile $MainLog -Message "Script terminated due to FATAL error"
    Exit
}
Write-Log -Logfile $MainLog -Message "Successfully retrieved the Current Version of the IP List, the current version is $($ListVersion.Latest), the previous version is $($ScriptConfig.LastVersion)."

# If a newer version is available.
if ($ListVersion.latest -gt $ScriptConfig.LastVersion){
    # Retrieve the current IP list.
    try{
        $URL = "https://endpoints.office.com/endpoints/Worldwide?ClientRequestId=" + $ScriptConfig.GUID
        $Data = Invoke-RestMethod $URL
    }
    catch{
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Log -Level FATAL -Logfile $MainLog -Message "There was an error retrieving the IP List from $URL"
        Write-Log -Level FATAL -Logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
        Write-Log -Level FATAL -Logfile $MainLog -Message "Script terminated due to FATAL error"
        Exit
    }
    Write-Log -Logfile $MainLog -Message "Retrieving the IP List was successful."

    # Parse the full IP list, remove duplicates, and store in an array of just the IPs.
    $BlockSuccess = $true
    try{
        $FullIPList = @()
        foreach ($Item in $Data) {
            foreach ($IP in $Item.ips){
                if (!($FullIPList -contains $IP)){
                    $FullIPList += $IP
                }
            }
        }
    }
    catch{
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Log -Level ERROR -Logfile $MainLog -Message "There was an error Creating the Full IP List."
        Write-Log -Level ERROR -Logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
        $BlockSuccess = $false
    }
    if ($BlockSuccess){
        Write-Log -Logfile $MainLog -Message "Creating the Full IP List was successful."
    }

    # Put additional parsing of individual lists and products here

    # Output the Parsed lists to the specified folder in UTF-8 format using Linux new line formatting.
    $BlockSuccess = $true
    try{
        $FullIPListPath = $OutputFolder + "O365IPs.txt"
        $FullIPList -join "`n" | Out-File $FullIPListPath -NoNewline -Encoding ascii
    }
    catch{
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Log -Level ERROR -Logfile $MainLog -Message "There was an error Exporting the IPList text file."
        Write-Log -Level ERROR -Logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
        $BlockSuccess = $false
    }
    if ($BlockSuccess){
        Write-Log -Logfile $MainLog -Message "Successfully Exported the updated IPList text file."
    }
    
    # Update the Script Config file
    $BlockSuccess = $true
    try{
        $ScriptConfig.LastVersion = $ListVersion.latest
        $ScriptConfig | Export-Clixml $ScriptConfigPath -Force
    }
    catch{
        $ErrorMessage = $_.Exception.Message
        $FailedItem = $_.Exception.ItemName
        Write-Log -Level ERROR -Logfile $MainLog -Message "There was an error updating and exporting the script config file."
        Write-Log -Level ERROR -Logfile $MainLog -Message "The error was caused by $FailedItem , the error message was $ErrorMessage."
        $BlockSuccess = $false
    }
    if ($BlockSuccess){
        Write-Log -Logfile $MainLog -Message "Successfully updated and exported the script config file to $ScriptConfigPath"
    }
}
else{
    Write-Log -Level INFO -Logfile $MainLog -Message "The currently available version of the IP List is not newer than the previously retrieved version, no changes made."
}
}

<#
Author: Unknown
Created: Unknown
Last Updated By: Eric Sobkowicz
Last Updated: October 3, 2018

Purpose:
    Takes the input of the logging level, message, and logfile then outputs it to the specified logfile, if no logfile specified it outputs to the powershell window, if no
    logging level specified it uses the value of INFO.

Requirements:
    N/A

Variables:
    $Level - Parameter - Accepts one of the following values: "INFO","WARN","ERROR","FATAL","DEBUG"; default value is INFO if none is specified.
    $Message - Parameter - Accepts any string.
    $Logfile - Parameter - the full path and flilename of the logfile, e.g. "C:\temp\log.txt"
#>
Function Write-Log
{
[CmdletBinding()]
Param
(
[Parameter(Mandatory=$False)]
[ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
[String]
$Level = "INFO",

[Parameter(Mandatory=$True)]
[string]
$Message,

[Parameter(Mandatory=$False)]
[string]
$Logfile
)

$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
$Line = "$Stamp $Level $Message"
If($Logfile){
    Add-Content $Logfile -Value $Line
}
Else{
    Write-Output $Line
}
}

# Runs the main function
# Putting the main code within a function and calling it at the end of the script allows for the main code to be at the top of the script and all other functions below it.
Main