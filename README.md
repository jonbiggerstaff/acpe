# acpe

# Start-PAM
  # Description
    This script allows you to elevate your own account or another account by adding it to a privileged group for a limited amount of time.
  
  # Dependencies
    1. This script relies on RemoveExpiredPrivileges.ps1 to remove the privileges (use a scheduled task to run this script every 5 minutes).
    2. Create the folder structure in the Start-PAM $PAMFiles variable on the server where you want the csv and log files located. Usually this is the same server where the RemovedExpiredPrivileges.ps1 script is located.
    3. The account that runs Start-PAM must have write access to the csv and log files location

  # Other
    1. You must set the global variables at the top of Start-PAM.ps1 and RemoveExpiredPrivileges.ps1 to your org environment
    2. You will need to add the Start-PAM script to a PS module and import the module before running it. Otherwise, you can call the script directly but will need to add "Start-PAM" to the very end of the script to it will run

  # Questions or comments?
    jbiggerstaff@nsd.org
  
  
