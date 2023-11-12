cls
 Write-Host -foregroundcolor green "                                                        
                                    @@@@@@@@@@                   
                                @@@@@      -@@@@                
                              @@@*             @@@              
                             @@@                -@@*            
                            @@@                   @@*           
                      @@@@@@@@                     @@           
                    @@@@                           @@*          
                  *@@                              *@@@*        
                 -@@                                  @@@       
           -@@@@@@@@                                     @@@      
          @@@                                 @@@         @@@     
         @@          @@                       @@@          @@@     
        @@*          @@                   @@@     @@@      @@@     
        @@        @@@@@@@@                @@@     @@@      @@@     
        @@           @@                       @@@          @@@     
        @@@          @@                       @@@        @@@      
         @@@                                          @@@       
          @@@@                                     @@@@         
            -@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@           
                                                    

                    ~Cloud GPU Gaming Setup Script~

                    This script sets up your cloud computer
                    with a bunch of settings and drivers
                    to make your life easier.  
                    
                    It's provided with no warranty, 
                    so use it at your own risk.
                    
                    Check out the README.md for more
                    troubleshooting info.

                    This tool supports:
                    
                    OS:
                    Server 2022 Base AMI
                    Server 2019 Base AMI
                    
                    CLOUD GPU INSTANCES:
                    AWS G5.2xLarge    (Ampere A10G)
                    AWS g4dn.xlarge   (Tesla T4)
                    AWS g4ad.4xlarge  (AMD Radeon Pro V520)

    
"                                         
Write-Output "Setting up Environment"
$path = [Environment]::GetFolderPath("Desktop")
if((Test-Path -Path $path\ParsecTemp ) -eq $true){
    } 
Else {
    New-Item -Path $path\ParsecTemp -ItemType directory| Out-Null
    }

Unblock-File -Path .\*
copy-Item .\* -Destination $path\ParsecTemp\ -Force -Recurse | Out-Null
#lil nap
Start-Sleep -s 1
#Unblocking all script files
Write-Output "Unblocking files just in case"
Get-ChildItem -Path $path\ParsecTemp -Recurse | Unblock-File
Write-Output "Starting main script"
start-process powershell.exe -verb RunAS -argument "-file $path\parsectemp\PostInstall\PostInstall.ps1"
Write-Host "You can close this window now...progress will happen on the Powershell Window that just opened" -backgroundcolor red
stop-process -Id $PID
