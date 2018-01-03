# Created November 21, 2016 by Eric Sobkowicz
# 
# This script will ask the user for a username and a file location for a CSV full of mailbox names, then it will add full permissions for the user to all the listed mailboxes
# and then remove the permissions, this should fix the problem with mailboxes still mapping after a user's permissions have been removed.

# Connect to O365, prompts the user for the O365 credentials to connect with.
$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
Import-PSSession $Session

# Asks for the username and the input csv file, exits if either are not valid.
$Answer = "N"
While ($Answer-eq "N")
    {
    $User = Read-Host "Please enter the user"
    $Answer = Read-Host "You have entered $User, is this correct? (Y/N)"
    }
Try
    {
    Get-ADUser $User | Out-Null
    }
Catch
    {
    Write-Host "The user you entered $User, is not a valid username. Exiting script."
    Return
    }
$Answer = "N"
While ($Answer -eq "N")
	{
	$FileLocation = Read-Host "Please enter the path and filename with extention for the csv file, e.g. C:\temp\file.csv"
	Write-Host "You have entered:"
    $FileLocation
    $Answer = Read-Host "Is this correct? (Y/N)"
	}

# Imports the mailbox list and tests to see if it's valid, exits the script if it is not.
try
    {
    $Mailboxes = Import-Csv $FileLocation
    foreach ($Mailbox in $Mailboxes)
        {
		try
			{
			Get-Mailbox $Mailbox.Name | Out-Null
			}
        Catch
			{
			Write-Host "The list of mailboxes you have provided is invalid.  Exiting Script."
			Return
			}
        }
    }
Catch
    {
    Write-Host "The list of mailboxes you have provided is invalid.  Exiting Script."
    Return
    }

# Adds the user with full mailbox permissions and then removes them to fix the automapping issue.
Try
    {
    Foreach ($Mailbox in $Mailboxes)
        {
		
        Add-MailboxPermission $Mailbox.Name -User $User -AccessRights FullAccess -InheritanceType All | Out-Null
        Remove-MailboxPermission $Mailbox.Name -User $User -AccessRights FullAccess -InheritanceType All -Confirm:$false |Out-Null
		Write-Host "Automapping for the user $User on the following mailbox has been fixed: " $Mailbox.Name
        }
    }
Catch
    {
    Write-Host "An error occured while fixing the permissions.  Exiting script."
    Return
    }
Write-Host "The script completed successfully."