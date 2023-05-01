#This script will add an account to privileged groups. It MUST be used in conjunction with the RemoveExpiredPrivileges.ps1 script in order for account to be removed from groups.

#Globals - Set these for your organization
    #Script title. Change when new version is released
        $ScriptTitle = "==================== Welcome to Privileged Access Management 2.5 ===================="
    #Put your AD administrator account in the domain\username format. Example: abc\administrator
        $domainAndUsername = ""
    #Put your domain in the "LDAP://DC=mydomain,DC=org" format. Example, for the AD domain in abc.xyz.org put "LDAP://DC=abc,DC=xyz,DC=org"
        $CurrentDomain = ""
    #Send Mail From address
        $SendMailFrom = ""
    #Send Mail To Teams channel address. This is optional so comment or uncomment the Send-MailMessage lines in this script to enable or disable
        $SendMailToChannel = ""
    #Send Mail to email recipients. This is optional so comment or uncomment the Send-MailMessage lines in this script to enable or disable. Add commas for multiple addresses
        $SendMailToRecipients = ""
    #SMTP server
        $SMTPserver = ""
    #UNV path for data files. IMPORTANT: Make sure the folder structure already exists. The script will create the files but not the folders. The account that runs the script will also need write access to this location
        $PAMFiles = ""

function Start-PAM {

    function Get-Creds {
                do {
                $a = $a + 1
                $script:cred = Get-Credential $domainAndUsername -Message "Enter $domainAndUsername credentials"
                $adminusername = $cred.username
                $adminpassword = $cred.GetNetworkCredential().password
                $domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain,$adminUserName,$adminPassword)
                if ($domain.name -eq $null) {
                    Write-Host "Authentication failed."
                }
            }
            while ($a -lt "3" -and $domain.name -eq $null)

            if ($domain.name -eq $null)
                {
                write-host "Authentication failed - please verify the admin password."
                break
            } else {
                $domainName = $domain.name
                 write-host "Successfully authenticated with domain $domainName"
            }
    }

    Get-Creds

    function Show-Menu {
        
        Write-Host ""
        Write-Host -ForegroundColor Yellow $ScriptTitle
        Write-Host ""
        Write-Host "1: AD Administrator    (Admin access to AD only)"
        Write-Host "2: Domain Admin        (Admin access to AD and all domain joined systems)"
        Write-Host "3: Schema Admin        (For making AD schema changes)"
        Write-Host "q: Quit"
    }
 
    Show-Menu

#Ask all the questions
    $Selection = Read-Host "What level of privilege do you want to grant?"
        switch ($Selection)
         {
               '1' {
                 $Group = 'Administrators'
             } '2' {
                 $Group = 'Domain Admins'
             } '3' {
                 $Group = 'Schema Admins'
             } 'q' {
                 return
             }
         }

    $username = [string]$(Read-Host 'Who are you granting this privilege to? (enter username-su)')
    $expiration = $(Read-Host 'How many hours do they need it? (Example: 2 or .5)')
    $reason = [string]$(Read-Host 'Why do they need it? (enter a brief explanation)')

#Set the variables and add a PSDrive for accessing the csv and log file
    $time = get-date
    $expTime = (Get-Date).AddHours(+$Expiration)
    $expTime = $expTime | get-date -UFormat "%m/%d/%Y %R"
    $emptyCSV = New-Object PSObject -Property @{ Expiration = ""; Username = ""; Group = "" }
    $csv = New-Object PSObject -Property @{ Expiration = $expTime; Username = $Username; Group = $Group }
    New-PSDrive -Name dest -Root $PAMFiles -PSProvider FileSystem | Out-Null
    $csvlocation = "dest:\PAM.csv"
    $logLocation = "dest:\PAM.log"

#Does the csv file exist? If not then create it. Otherwise, import the csv into a variable
    $csvFileExist = Test-Path $csvlocation
    if (!($csvFileExist)) {
        Export-Csv -InputObject $emptyCSV -Path $csvlocation -NoTypeInformation
    }

    $csvImport = Import-Csv $csvlocation

#Does the user already have elevated privs?
    $userexists = import-csv $csvlocation | Where-Object {$_.username -eq $username}

#If they do then say so and give options
    if ($userexists) {
        $curUserExpiration = import-csv $csvlocation | Where-Object {$_.username -eq $username} | select -ExpandProperty expiration
        $CurrentLevelofElevation = import-csv $csvlocation | Where-Object {$_.username -eq $username} | select -ExpandProperty group

        Write-Host "`n$username already has privileged access to $CurrentLevelofElevation and will expire at $curUserExpiration"
        $Update = Read-Host "Would you like to update the user with the information you provided? (y/n)"
            if ($Update -eq "y") {
                Remove-ADGroupMember "$CurrentLevelofElevation" $username -Credential $Cred -Confirm:$false
                               $csvImport | Where-Object username -NotLike "$username" | export-csv $csvlocation -NoTypeInformation


###Elevate user privileges
                Add-ADGroupMember "$Group" $username -Credential $Cred
#Refresh kerberos ticket if running on self
                if ($env:USERNAME -eq $username) {
                    klist purge
                    Write-Host -ForegroundColor Yellow "Your kerberos ticket has been refreshed"
                }
                Export-Csv -InputObject $csv -Path $csvlocation -NoTypeInformation -Append
                Write-Host "The expiration time for $username has been updated to $expTime and is in the $Group group"
#Log it and send notification to the Teams Server Team TempElevatedAccess channel
                $LogMsg = "$time - $env:USERNAME updated $username to the $Group group with expiration date of $expTime. The reason given was: $reason."
                $CurrentCSVContent = import-csv $csvlocation | ConvertTo-Html -Fragment
                $mailBody = 
                    "
                    $env:USERNAME updated $username to the $Group group with expiration date of $expTime.</br>
                    </br>
                    The reason given was: $reason.</br>
                    </br>
                    Current privileged access:</br>
                    $CurrentCSVContent
                    "
                $LogMsg | Out-File $logLocation -Append
#To disable Teams channel alerts, comment the following line
                Send-MailMessage -From $SendMailFrom -To $SendMailToChannel -SmtpServer $SMTPserver -Subject "Privileged Access Notification" -Body $LogMsg
#To disable email alerts, comment the following line
                #Send-MailMessage -From $SendMailFrom -To $SendMailToRecipients -SmtpServer $SMTPserver -Subject "Privileged Access Notification" -Body $mailBody -BodyAsHtml

#Cleanup
                Remove-PSDrive dest

            } else { 
                break
#Cleanup
                Remove-PSDrive dest 
                }

    } else {
                $ErrorActionPreference = 'silentlycontinue'
                $userInAD = Get-ADUser $username
                $ErrorActionPreference = 'continue'
                if (!($userInAD)) {
                    Write-Host "$username not found in AD. Check the username and try again."
#Cleanup
                Remove-PSDrive dest
                    break
                }
                        
###Elevate user privileges
                Add-ADGroupMember "$Group" $username -Credential $cred
#Refresh kerberos ticket if running on self
                if ($env:USERNAME -eq $username) {
                    klist purge
                    Write-Host -ForegroundColor Yellow "Your kerberos ticket has been refreshed"
                }
                Export-Csv -InputObject $csv -Path $csvlocation -NoTypeInformation -Append
                Write-Host "`n$username has been added to the $Group group and will be removed at $expTime"
#Log it and send notification to the Teams Server Team TempElevatedAccess channel
                $LogMsg = "$time - $env:USERNAME added $username to the $group group with expiration date of $expTime. The reason given was: $reason."
                $CurrentCSVContent = import-csv $csvlocation | ConvertTo-Html -Fragment
                $mailBody = 
                    "
                    $env:USERNAME added $username to the $group group with expiration date of $expTime.</br>
                    </br>
                    The reason given was: $reason.</br>
                    </br>
                    Current privileged access:</br>
                    $CurrentCSVContent
                    "
                $LogMsg | Out-File $logLocation -Append
#To disable Teams channel alerts, comment the following line
                Send-MailMessage -From $SendMailFrom -To $SendMailToChannel -SmtpServer $SMTPserver -Subject "Privileged Access Notification" -Body $LogMsg
#To disable email alerts, comment the following line
                #Send-MailMessage -From $SendMailFrom -To $SendMailToRecipients -SmtpServer $SMTPserver -Subject "Privileged Access Notification" -Body $mailBody -BodyAsHtml
                
#Cleanup
                Remove-PSDrive dest
        }
}