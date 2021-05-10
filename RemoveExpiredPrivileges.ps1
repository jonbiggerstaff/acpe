#Set a scheduled task to run this script every 5 minutes. It will check for expired credentials and remove them from privileged groups. This is meant to be used in conjunction with Start-PAM script.

#Globals - Set these for your organization
    #Location of PAM.csv file
        $csvlocation = "C:\script\PrivAccess\PAM.csv"
    #Location of log file
        $logLocation = "C:\script\PrivAccess\PAM.log"
    #Domain controller hostname to use for PSSessions
        $DomainController = "dc1.mydomain.org"


$csvImport = Import-Csv $csvlocation
$time = Get-Date

# Check each row in csv
foreach ($item in $csvImport) {
        $username = $item.Username
            if ($username) {
                $group = $item.group
                # Put date into correct format for next if statement
                $expiration = $item.Expiration
                $expiredate = $expiration | get-date -UFormat "%m/%d/%Y %R"

                # Compare expiration date to current date and remove row from csv if expiration date is expired
                if ($expiredate -le (get-date)) {
                    $csvImport | Where-Object expiration -NE "$expiredate" | export-csv $csvlocation -NoTypeInformation

                    # Check for existing pssession to domain controller so it doesn't create duplicate sessions. Remove user from group
                    $curSessions = (Get-PSSession).ComputerName
                    if ($curSessions -eq $DomainController) {
                        Remove-ADGroupMember "$group" $username -Confirm:$false
                        "$time - The scheduled task removed $username from the $group group" | Out-File $logLocation -Append

                    }else {
                        $s = New-PSSession -ComputerName $DomainController
                        Invoke-Command -Session $s {Import-Module ActiveDirectory}
                        Import-PSSession $s -Module ActiveDirectory

                        Remove-ADGroupMember "$group" $username -Confirm:$false
                        "$time - The scheduled task removed $username from the $group group" | Out-File $logLocation -Append
        
                    }
                }
            }
}
