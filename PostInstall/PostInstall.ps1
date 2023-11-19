param (
    [switch]$DontPromptPasswordUpdateGPU
)

$host.ui.RawUI.WindowTitle = "Cloud GPU Preparation Tool"
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 

# ###################################################################################
# Global envs
# ###################################################################################

$path = [Environment]::GetFolderPath("Desktop")
$parsecPath = "$env:ProgramData\ParsecLoader"
$currentusersid = Get-LocalUser "$env:USERNAME" | Select-Object SID | ft -HideTableHeaders | Out-String | ForEach-Object { $_.Trim() }

# ###################################################################################
# Utility Functions 
# ###################################################################################

function CloudProvider { 
    # Finds the cloud provider that this VM is hosted by  

    $aws = $(
        Try {
            (Invoke-WebRequest -uri http://169.254.169.254/latest/meta-data/ -TimeoutSec 5)
        }
        catch {
        }
    )

    if ($AWS.StatusCode -eq 200) {
        "Amazon AWS Instance"
    }  
    Else {
        "Generic Instance"
    }
}

function ProgressWriter {
    # Gives progress update message to a user 

    param (
        [int]$percentcomplete,
        [string]$status
    )
    Write-Progress -Activity "Setting Up Your Machine" -Status $status -PercentComplete $percentcomplete
}
function Test-RegistryValue {
    # https://www.jonathanmedd.net/2014/02/testing-for-the-presence-of-a-registry-key-and-Value.html
    param (
    
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Path,
    
        [parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]$Value
    )
    
    try {
        Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
    
}

# ##########################################################################################
# Setup ENV and Copy config files and scripts
# ##########################################################################################

function Setup-Environment {
    # Creating Folders and moving script files into System directories
    ProgressWriter -Status "Setting up ENV, Moving files and folders into place" -PercentComplete $percentcomplete

    Write-Output "[o] [Setup-Environment] Setting up ENV, Moving files and creating folders into place"

    if ((Test-Path -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Startup) -eq $true) {} 
    Else { 
        New-Item -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Startup -ItemType directory | Out-Null 
    }

    if ((Test-Path -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown) -eq $true) {} 
    Else {
        New-Item -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown -ItemType directory | Out-Null 
    }
    
    if ((Test-Path -Path $parsecPath) -eq $true) {
        Write-Output "[o][o] Directory exists, skipping..."
    } 
    Else { 
        Write-Output "[o][o] Creating New Directory @ 'C:\ProgramData\ParsecLoader'"
        New-Item -Path $parsecPath -ItemType directory | Out-Null 
    }

    if ((Test-Path -Path $parsecPath\Apps) -eq $true) {
        Write-Output "[o][o] Sub-Directory 'Apps' exists, skipping..."
    } 
    Else { New-Item -Path $parsecPath\Apps -ItemType directory | Out-Null }

    if ((Test-Path -Path $parsecPath\DirectX) -eq $true) {
        Write-Output "[o][o] Sub-Directory 'DirectX' exists, skipping..."
    } 
    Else { New-Item -Path $parsecPath\DirectX -ItemType directory | Out-Null }

    if ((Test-Path -Path $parsecPath\Drivers) -eq $true) {
        Write-Output "[o][o] Sub-Directory 'Drivers' exists, skipping..."
    } 
    Else { New-Item -Path $parsecPath\Drivers -ItemType Directory | Out-Null }

    if ((Test-Path -Path $parsecPath\Registry) -eq $true) {
        Write-Output "[o][o] Sub-Directory 'Registry' exists, skipping..."
    } 
    Else { New-Item -Path $parsecPath\Registry -ItemType Directory | Out-Null }

    if ((Test-Path C:\Windows\system32\GroupPolicy\Machine\Scripts\psscripts.ini) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\psscripts.ini -Destination C:\Windows\system32\GroupPolicy\Machine\Scripts 
    }

    if ((Test-Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown\NetworkRestore.ps1) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\NetworkRestore.ps1 -Destination C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown 
    } 

    if ((Test-Path $parsecPath\Automatic-Shutdown.ps1) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\Automatic-Shutdown.ps1 -Destination $parsecPath 
    }

    if ((Test-Path $parsecPath\CreateAutomaticShutdownScheduledTask.ps1) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\CreateAutomaticShutdownScheduledTask.ps1 -Destination $parsecPath 
    }

    if ((Test-Path $parsecPath\GPU-Update.ico) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\GPU-Update.ico -Destination $parsecPath 
    }

    # if ((Test-Path $parsecPath\GPUUpdaterTool.ps1) -eq $true) {} 
    # Else { 
    #     Move-Item -Path $path\ParsecTemp\GPUUpdater\GPUUpdaterTool.ps1 -Destination $parsecPath 
    # }

    if ((Test-Path $parsecPath\CreateOneHourWarningScheduledTask.ps1) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\CreateOneHourWarningScheduledTask.ps1 -Destination $parsecPath 
    }

    if ((Test-Path $parsecPath\WarningMessage.ps1) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\WarningMessage.ps1 -Destination $parsecPath 
    }

    if ((Test-Path $parsecPath\Parsec.png) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\Parsec.png -Destination $parsecPath 
    }

    if ((Test-Path $parsecPath\ShowDialog.ps1) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\ShowDialog.ps1 -Destination $parsecPath 
    }

    if ((Test-Path $parsecPath\OneHour.ps1) -eq $true) {} 
    Else {
        Move-Item -Path $path\ParsecTemp\PreInstall\OneHour.ps1 -Destination $parsecPath
    }

    if ((Test-Path $parsecPath\parsecpublic.cer) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\parsecpublic.cer -Destination $parsecPath 
    }
}

# ##########################################################################################
# Windows Registry Settings
# ##########################################################################################

function Add-GPOModifications {
    # Modifies Local Group Policy to enable Shutdown scripts items
    Write-Output "[o][o] [Add-GPOModifications] Modifying Local Group Policy (GPO) to enable Shutndown scripts items"
    $querygpt = Get-content C:\Windows\System32\GroupPolicy\gpt.ini
    $matchgpt = $querygpt -match '{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}'
    if ($matchgpt -contains "*0000F87571E3*" -eq $false) {
        $gptstring = Get-Content C:\Windows\System32\GroupPolicy\gpt.ini
        $gpoversion = $gptstring -match "Version"
        $GPO = $gptstring -match "gPCMachineExtensionNames"
        $add = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
        $replace = "$GPO" + "$add"
        (Get-Content "C:\Windows\System32\GroupPolicy\gpt.ini").Replace("$GPO", "$replace") | Set-Content "C:\Windows\System32\GroupPolicy\gpt.ini"
        [int]$i = $gpoversion.trim("Version=") 
        [int]$n = $gpoversion.trim("Version=")
        $n += 2
        (Get-Content C:\Windows\System32\GroupPolicy\gpt.ini) -replace "Version=$i", "Version=$n" | Set-Content C:\Windows\System32\GroupPolicy\gpt.ini
    }
    else {
        Write-Output "[o][o] GPO MOdifications Not Required"
    }
}

function Add-RegItems {
    # Adds Premade Group Policy Item if existing configuration doesn't exist
    ProgressWriter -Status "Adding Registry Items and Group Policy" -PercentComplete $percentcomplete
    Write-Output "[o] [Add-RegItems] Adding Registry Items and Group Policies"
    if (Test-Path ("C:\Windows\system32\GroupPolicy" + "\gpt.ini")) {
        Add-GPOModifications
    }
    Else {
        Move-Item -Path $path\ParsecTemp\PreInstall\gpt.ini -Destination C:\Windows\system32\GroupPolicy -Force | Out-Null
    }
    regedit /s $path\ParsecTemp\PreInstall\NetworkRestore.reg
    regedit /s $path\ParsecTemp\PreInstall\ForceCloseShutDown.reg
    New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS -ErrorAction SilentlyContinue | Out-Null
}

# ##########################################################################################
# Change Windows Settings
# ##########################################################################################

function Set-UpdatePolicy {
    # Disable's Windows Update
    ProgressWriter -Status "Disabling Windows Update" -PercentComplete $percentcomplete
    Write-Output "[o] [Set-UpdatePolicy] Disabling Windows Update"

    # 1. DoNotConnectToWindowsUpdateInternetLocations
    if ((Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Value 'DoNotConnectToWindowsUpdateInternetLocations') -eq $true) { 
        Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null 
    }
    else { 
        New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null 
    }

    # 2. UpdateServiceURLAlternativ
    if ((Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Value 'UpdateServiceURLAlternative') -eq $true) { 
        Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null 
    } 
    else { 
        New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null 
    }

    # 3. WUServer
    if ((Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Value 'WUServer') -eq $true) { 
        Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null 
    } 
    else { 
        New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null 
    }

    # 4. WUStatusServer
    if ((Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Value 'WUSatusServer') -eq $true) { 
        Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null 
    }
    else { 
        New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null 
    }

    # 5. AUOptions
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "AUOptions" -Value 1 | Out-Null

    # 6. UseWUServer
    if ((Test-RegistryValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Value 'UseWUServer') -eq $true) { 
        Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null 
    }
    else { 
        New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null 
    }
}

function Disable-NetworkWindow {
    # Disable's new network window pop up
    ProgressWriter -Status "Disabling New Network Window Popup" -PercentComplete $percentcomplete
    Write-Output "[o] [Disable-NetworkWindow] Disabling New Network Window Popup"
    if ((Test-RegistryValue -Path HKLM:\SYSTEM\CurrentControlSet\Control\Network -Value 'NewNetworkWindowOff') -eq $true) {
    }
    Else { 
        New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\Network -name "NewNetworkWindowOff" | Out-Null 
    }
}

function Disable-IESecurity {
    ProgressWriter -Status "Disabling Internet Explorer security to enable web browsing" -PercentComplete $percentcomplete
    Write-Output "[o] [Disable-IESecurity] Disabling Internet Explorer security to enable web browsing"
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -name IsInstalled -Value 0 -force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name IsInstalled -Value 0 -Force | Out-Null
    Stop-Process -Name Explorer -Force
}

function Set-Time {
    # Set Automatic Time and Timezone
    ProgressWriter -Status "Setting computer time to automatic" -PercentComplete $percentcomplete
    Write-Output "[o] [Set-Time] Setting computer time to automatic, change timezone to your preference"
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name Type -Value NTP | Out-Null
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate -Name Start -Value 00000003 | Out-Null
}
 
function Enable-PointerPrecision {
    # Enable Pointer Precision
    ProgressWriter -Status "Enabling enchanced pointer precision" -PercentComplete $PercentComplete
    Write-Output "[o] [Enable-PointerPrecision] Enabling enhanced pointer precision"
    Set-Itemproperty -Path 'HKCU:\Control Panel\Mouse' -Name MouseSpeed -Value 1 | Out-Null
}

function Enable-Mousekeys {
    ProgressWriter -Status "Enabling mouse keys to assist with mouse cursor" -PercentComplete $percentcomplete
    Write-Output "[o] [Enable-Mousekeys] Enabling mouse keys to assist with mouse cursor"
    Set-ItemProperty -Path 'HKCU:\Control Panel\Accessibility\MouseKeys' -Name Flags -Value 63 | Out-Null
}

function Force-Close-Apps {
    # Sets all applications to force close on shutdown
    ProgressWriter -Status "Setting Windows not to stop shutdown if there are unsaved apps" -PercentComplete $percentcomplete
    Write-Output "[o] [Force-Close-Apps] Setting Windows not to stop shutdown if there are unsaved apps"
    if (((Get-Item -Path "HKCU:\Control Panel\Desktop").GetValue("AutoEndTasks") -ne $null) -eq $true) {
        Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
    }
    Else {
        New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
    }
}

function Show-Hidden-Items {
    # Shows hidden items
    ProgressWriter -Status "Showing Hidden files in Windows Explorer" -PercentComplete $percentcomplete
    Write-Output "[o] [Show-Hidden-Items] Showing Hidden files in Windows Explorer"
    $hide = (Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced").Hidden
    if ($hide -eq 1) {
        Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Hidden -Value 1 | Out-Null
    }
}

function Show-FileExtensions {
    # Shows file extensions
    ProgressWriter -Status "Showing file extensions in Windows Explorer" -PercentComplete $percentcomplete
    Write-Output "[o] [Show-FileExtensions] Showing file extensions in Windows Explorer"
    $hide = (Get-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced).HideFileExt
    If ($hide -eq 1) {   
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Value 0 | Out-Null
    }   
}

function Disable-Logout {
    # Disable logout start menu
    ProgressWriter -Status "Disabling log out button on start menu" -PercentComplete $percentcomplete
    Write-Output "[o] [Disable-Logout] Disabling log out button from start menu"
    if ((Test-RegistryValue -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Value StartMenuLogOff ) -eq $true) { 
        Set-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null 
    } 
    Else { 
        New-ItemProperty -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name StartMenuLogOff -Value 1 | Out-Null 
    }
}

function Disable-Lock {
    # Disable lock start menu
    ProgressWriter -Status "Disabling option to lock your Windows user profile" -PercentComplete $percentcomplete
    Write-Output "[o] [Disable-Lock] Disabling lock button from Windows User Profile"
    if ((Test-Path -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System) -eq $true) {} Else {
        New-Item -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies -Name Software | Out-Null
    }
    if ((Test-RegistryValue -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Value DisableLockWorkstation) -eq $true) { 
        Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null 
    } 
    Else { 
        New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -Name DisableLockWorkstation -Value 1 | Out-Null 
    }
}


function Disable-RecentStartMenu {
    # Disable recent start menu items
    ProgressWriter -Status "Disabling Recent Start Menu items" -PercentComplete $percentcomplete
    Write-Output "[o] [Disable-RecentStartMenu] Disabling Recent Start Menu items"
    if (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -Name "HideRecentlyAddedApps") {
    }
    else {
        New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -name Explorer | Out-Null
        New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -PropertyType DWORD -Name HideRecentlyAddedApps -Value 1 | Out-Null
    }
}

function Disable-ServerManager {
    # Disable's Server Manager opening on Startup
    ProgressWriter -Status "Disabling Windows Server Manager from starting at startup" -PercentComplete $percentcomplete
    Write-Output "[o] [Disable-ServerManager] Disabling Windows Server Manager from starting at startup"
    Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null
}

function CleanUp-AWSShortcuts {
    # Removes AWS shortcuts
    ProgressWriter -Status "Removing AWS Shortcuts" -PercentComplete $percentcomplete
    Write-Output "[x] [CleanUp-AWSShortcuts] Deleting AWS Desktop Shortcuts"
    $shortcuts = @(
        "$path\EC2 Feedback.Website",
        "$path\EC2 Microsoft Windows Guide.website"
    )
    foreach ($shortcut in $shortcuts) {
        if (Test-Path $shortcut) {
            Remove-Item -Path $shortcut -Force
        }
    }    
}

function CleanUp-Recent {
    # Cleanups recent files
    ProgressWriter -Status "Delete recently accessed files list from Windows Explorer" -PercentComplete $percentcomplete
        Write-Output "[x] [CleanUp-Recent] Delete recently accessed files list from Windows Explorer"
    $recentFolderPath = "$env:APPDATA\Microsoft\Windows\Recent"
    if (Test-Path $recentFolderPath) {
        Get-ChildItem -Path $recentFolderPath -File | Remove-Item -Force
    }
}   

function Set-Wallpaper {
    ProgressWriter -Status "Setting gaming wallpaper" -PercentComplete $percentcomplete

    Write-Output "[o] [Set-Wallpaper] Setting gaming wallpaper"

    (New-Object System.Net.WebClient).DownloadFile("https://wallpapercave.com/uwp/uwp3415636.jpeg", "$parsecPath\uwp3415636.jpeg")

    if ((Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System) -eq $true) {} 
    Else { 
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies" -Name "System" | Out-Null 
    }

    if ((Test-RegistryValue -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -value Wallpaper) -eq $true) { 
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name Wallpaper -value "$parsecPath\uwp3415636.jpeg" | Out-Null 
    } 
    Else { 
        New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name Wallpaper -PropertyType String -value "$parsecPath\uwp3415636.jpeg" | Out-Null 
    }

    if ((Test-RegistryValue -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -value WallpaperStyle) -eq $true) { 
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name WallpaperStyle -value 2 | Out-Null 
    } 
    Else { 
        New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name WallpaperStyle -PropertyType String -value 2 | Out-Null 
    }

    Stop-Process -ProcessName explorer
}

function Enable-PhotoViewer {
    ProgressWriter -Status "Enabling Photo Viewer" -PercentComplete $percentcomplete
    Write-Output "[o] [Enable-PhotoViewer] Enabling Photo Viewer"
    # Step 1: Check if Photo Viewer DLLs exist
    $photoViewerDLLPath = "C:\Program Files (x86)\Windows Photo Viewer\PhotoViewer.dll"
    if (Test-Path -Path $photoViewerDLLPath) {
        # Step 2: Register PhotoViewer.dll
        regsvr32.exe /s "$photoViewerPath\PhotoViewer.dll"
        # Step 3: Download registry keys
        $registryFolderPath = "$parsecPath\Registry"
        $downloadPath = "$registryFolderPath\MSPhotoViewerRegFiles.zip"
        $downloadURL = "https://green.cloud/docs/wp-content/uploads/2023/02/MSPhotoViewerRegFiles.zip.zip"
        if (Test-Path -Path $downloadPath) {
        } 
        else {
            # Download the zip file
            Invoke-WebRequest -Uri $downloadURL -OutFile $downloadPath
        }
        # Step 4: Extract registry keys
        Expand-Archive -Path $downloadPath -DestinationPath "$registryFolderPath\MSPhotoViewerRegFiles" -Force
        # Step 5: Import each registry keys
        $regFiles = Get-ChildItem -Path "$registryFolderPath\MSPhotoViewerRegFiles\*.reg" -Recurse -Force
        if ($regFiles) {
            foreach ($regFile in $regFiles) {
                # Import each registry key
                reg import "$regFile" 2>$null
            }
        } 
        Write-Output "[o][o] [Enable-PhotoViewer] Windows Photo Viewer enabled and configured successfully!"
    }
    else {
        Write-Output "[o][o] [Enable-PhotoViewer] Windows Photo Viewer DLLs not found at $photoViewerDLLPath."
    }
}


# ##########################################################################################
# Install dependencies DirectX, Microsoft Xbox 360 Controller, .NET packages etc... and necessary software like Parsec, 7zip
# ##########################################################################################

function Install-DirectX {
    # Install DirectX
    ProgressWriter -Status "Installing DirectX June 2010 Redist" -PercentComplete $percentcomplete
    Write-Output "[o] [InstallDirectX] Installing DirectX June 2010 Redist"
    
    $downloadURL = "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe"
    $outpath = "$parsecPath\DirectX\directx_Jun2010_redist.exe"
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($downloadURL, $outpath)

    Start-Process -FilePath "$parsecPath\DirectX\directx_jun2010_redist.exe" -ArgumentList '/T:C:\ProgramData\ParsecLoader\DirectX /Q'-wait
    Start-Sleep -s 1
    Start-Process -FilePath "$parsecPath\DirectX\DXSETUP.EXE" -ArgumentList '/silent' -wait
    Start-Sleep -s 1
    Write-Output "[o][o] [InstallDirectX] Installing Direct Play"
    ProgressWriter -Status "Installing Direct Play" -PercentComplete $percentcomplete
    Install-WindowsFeature Direct-Play | Out-Null
    Start-Sleep -s 1
    Write-Output "[o][o] [InstallDirectX] Installing .net 3.5"
    ProgressWriter -Status "Installing .net 3.5" -PercentComplete $percentcomplete
    Install-WindowsFeature Net-Framework-Core | Out-Null
    Start-Sleep -s 1
}

function Install7Zip {
    # 7Zip is required to extract the Parsec-Windows.exe File
    ProgressWriter -Status "Installing 7zip" -PercentComplete $percentcomplete
    Write-Output "[o] [Install7Zip] Installing 7zip"
    $installationPath = Get-Item -Path "C:\Program Files\7-Zip" -ErrorAction SilentlyContinue
    if ($installationPath -ne $null) {
        Write-Output "[o][o] [Install7Zip] 7zip is Installed Skipping"
    }
    else {
        Write-Output "[o][o] [Install7Zip] Downloading 7zip"
        $url = Invoke-WebRequest -Uri "https://www.7-zip.org/download.html"
        (New-Object System.Net.WebClient).DownloadFile("https://www.7-zip.org/$($($($url.Links | Where-Object outertext -Like "Download")[1]).OuterHTML.split('"')[1])" , "$parsecPath\Apps\7zip.exe")
        Write-Output "[o][o] [Install7Zip] Installing 7zip"
        Start-Process $parsecPath\Apps\7zip.exe -ArgumentList '/S /D="C:\Program Files\7-Zip"' -Wait

    }
}

function Install-XBox360Controller {
    ProgressWriter -Status "Adding Xbox 360 Controller driver to Windows Server 2019/2022" -PercentComplete $percentcomplete
    Write-Output "[o] [Install-XBox360Controller] Adding Xbox 360 Controller driver to Windows Server 2019/2022"
    $operatingSystem = Get-WmiObject -Class Win32_OperatingSystem
    if ($operatingSystem.Caption -match "Server" -and ($operatingSystem.Version -eq "10.0.17763" -or $operatingSystem.Version -eq "10.0.20348")) {
        (New-Object System.Net.WebClient).DownloadFile("http://www.download.windowsupdate.com/msdownload/update/v3-19990518/cabpool/2060_8edb3031ef495d4e4247e51dcb11bef24d2c4da7.cab", "$parsecPath\Drivers\Xbox360_64Eng.cab")
        if ((Test-Path -Path $parsecPath\Drivers\Xbox360_64Eng) -eq $true) 
        {} 
        Else { 
            New-Item -Path $parsecPath\Drivers\Xbox360_64Eng -ItemType directory | Out-Null 
        }
        cmd.exe /c "C:\Windows\System32\expand.exe $parsecPath\Drivers\Xbox360_64Eng.cab -F:* $parsecPath\Drivers\Xbox360_64Eng" | Out-Null
        cmd.exe /c '"C:\Program Files\Parsec\vigem\10\x64\devcon.exe" dp_add "$parsecPath\Drivers\Xbox360_64Eng\xusb21.inf"' | Out-Null
    }
}
 
function Install-Parsec {
    ProgressWriter -Status "Installing Parsec" -PercentComplete $percentcomplete
    Write-Output "[o] [Install-Parsec] Downloading Parsec"
    (New-Object System.Net.WebClient).DownloadFile("https://builds.parsecgaming.com/package/parsec-windows.exe", "$parsecPath\Apps\parsec-windows.exe")
    Write-Output "[o][o] [Install-Parsec] Installing Parsec"
    Start-Process "$parsecPath\Apps\parsec-windows.exe" -ArgumentList "/silent" -wait
}

function Install-ParsecVDD {
    ProgressWriter -Status "Installing Parsec Virtual Display Driver" -percentcomplete $percentcomplete
    Write-Output "[o] [Install-ParsecVDD] Downloading ParsecVDD"
    (New-Object System.Net.WebClient).DownloadFile("https://builds.parsec.app/vdd/parsec-vdd-0.37.0.0.exe", "$parsecPath\Apps\parsec-vdd.exe")
    Write-Output "[o][o] [Install-ParsecVDD]Installing ParsecVDD"
    Import-Certificate -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" -FilePath "$parsecPath\parsecpublic.cer" | Out-Null
    Start-Process "$parsecPath\Apps\parsec-vdd.exe" -ArgumentList "/silent" 
    $iterator = 0    
    do {
        Start-Sleep -s 2
        $iterator++
    }
    Until (($null -ne ((Get-PnpDevice | Where-Object { $_.Name -eq "Parsec Virtual Display Adapter" }).DeviceID)) -or ($iterator -gt 7))
    if (Get-process -name parsec-vdd -ErrorAction SilentlyContinue) {
        Stop-Process -name parsec-vdd -Force
    }
    $configfile = Get-Content "$env:AppData\Parsec\config.txt"
    $configfile += "host_virtual_monitors = 1"
    $configfile += "host_privacy_mode = 1"
    $configfile | Out-File "$env:AppData\Parsec\config.txt" -Encoding ascii
}

function Start-Parsec {
    ProgressWriter -Status "Starting Parsec" -PercentComplete $percentcomplete
    Write-Output "[o] [Start-Parsec] Starting Parsec"
    Start-Process -FilePath "C:\Program Files\Parsec\parsecd.exe"
    Start-Sleep -s 1
}

function Install-VBAAudioDriver {
    # Audio Driver Install
    ProgressWriter -Status "Installing VBA Audio Driver" -percentcomplete $percentcomplete
    Write-Output "[o] [Install-VBAAudioDriver] Installing VBA Audio Driver"
    (New-Object System.Net.WebClient).DownloadFile("https://download.vb-audio.com/Download_CABLE/VBCABLE_Driver_Pack43.zip", "$parsecPath\Apps\VBCable.zip")
    New-Item -Path "$parsecPath\Apps\VBCable" -ItemType Directory | Out-Null
    Expand-Archive -Path "$parsecPath\Apps\VBCable.zip" -DestinationPath "$parsecPath\Apps\VBCable"
    $pathToCatFile = "$parsecPath\Apps\VBCable\vbaudio_cable64_win7.cat"
    $FullCertificateExportPath = "$parsecPath\Apps\VBCable\VBCert.cer"
    $VB = @{}
    $VB.DriverFile = $pathToCatFile;
    $VB.CertName = $FullCertificateExportPath;
    $VB.ExportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert;
    $VB.Cert = (Get-AuthenticodeSignature -filepath $VB.DriverFile).SignerCertificate;
    [System.IO.File]::WriteAllBytes($VB.CertName, $VB.Cert.Export($VB.ExportType))
    Import-Certificate -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -FilePath $VB.CertName | Out-Null
    Start-Process -FilePath "$parsecPath\Apps\VBCable\VBCABLE_Setup_x64.exe" -ArgumentList '-i', '-h'
    Set-Service -Name audiosrv -StartupType Automatic
    Start-Service -Name audiosrv
}

# ########################################################################################
# After Parsec Installation
# ########################################################################################

function Disable-Devices {
    # Disable Display Adapter Devices
    ProgressWriter -Status "Disabling Microsoft Basic Display Adapter, Generic Non PNP Monitor and other devices" -PercentComplete $percentcomplete
    Write-Output "[o] [Disable-Devices] Disabling Microsoft Basic Display Adapter, Generic Non PNP Monitor and other devices"
    Get-PnpDevice | where { $_.friendlyname -like "Generic Non-PNP Monitor" -and $_.status -eq "OK" } | Disable-PnpDevice -confirm:$false
    Get-PnpDevice | where { $_.friendlyname -like "Microsoft Basic Display Adapter" -and $_.status -eq "OK" } | Disable-PnpDevice -confirm:$false
    Get-PnpDevice | where { $_.friendlyname -like "Microsoft Hyper-V Video" -and $_.status -eq "OK" } | Disable-PnpDevice -confirm:$false

    # Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "PCI\VEN_1013&DEV_00B8*"'
    # Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "PCI\VEN_1D0F&DEV_1111*"'
    # Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "PCI\VEN_1AE0&DEV_A002*"'
    # Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "HDAUDIO\FUNC_01&VEN_10DE&DEV_0083&SUBSYS_10DE11A3*"'

}

# ########################################################################################
# Create Shortcuts 
# ########################################################################################

function Create-AutoShutdownShortcut {
    ProgressWriter -Status "Creating Auto Shutdown Shortcut" -PercentComplete $percentcomplete
    $Shell = New-Object -ComObject ("WScript.Shell")
    $ShortCut = $Shell.CreateShortcut("$env:USERPROFILE\Desktop\Setup Auto Shutdown.lnk")
    $ShortCut.TargetPath = "powershell.exe"
    $ShortCut.Arguments = '-ExecutionPolicy Bypass -File "$parsecPath\CreateAutomaticShutdownScheduledTask.ps1"'
    $ShortCut.WorkingDirectory = $parsecPath;
    $ShortCut.WindowStyle = 0;
    $ShortCut.Description = "Autoshutdown shortcut";
    $ShortCut.Save()
}

function Create-One-Hour-Warning-Shortcut {
    ProgressWriter -Status "Creating one hour warning shortcut" -PercentComplete $percentcomplete
    $Shell = New-Object -ComObject ("WScript.Shell")
    $ShortCut = $Shell.CreateShortcut("$env:USERPROFILE\Desktop\Setup One Hour Warning.lnk")
    $ShortCut.TargetPath = "powershell.exe"
    $ShortCut.Arguments = '-ExecutionPolicy Bypass -File "$parsecPath\CreateOneHourWarningScheduledTask.ps1"'
    $ShortCut.WorkingDirectory = $parsecPath;
    $ShortCut.WindowStyle = 0;
    $ShortCut.Description = "OneHourWarning shortcut";
    $ShortCut.Save()
}

function Create-GPUUpdateShortcut {
    Unblock-File -Path "$parsecPath\GPUUpdaterTool.ps1"
    ProgressWriter -Status "Creating GPU Updater icon on Desktop" -PercentComplete $percentcomplete
    $Shell = New-Object -ComObject ("WScript.Shell")
    $ShortCut = $Shell.CreateShortcut("$path\GPU Updater.lnk")
    $ShortCut.TargetPath = "powershell.exe"
    $ShortCut.Arguments = '-ExecutionPolicy Bypass -File "$parsecPath\GPUUpdaterTool.ps1"'
    $ShortCut.WorkingDirectory = $parsecPath;
    $ShortCut.IconLocation = "$parsecPath\GPU-Update.ico, 0";
    $ShortCut.WindowStyle = 0;
    $ShortCut.Description = "GPU Updater shortcut";
    $ShortCut.Save()
}

# ########################################################################################
# Post Install Cleanup
# ########################################################################################

function CleanUp-TempFolder {
    # Cleanup Tempfolder
    ProgressWriter -Status "Deleting temporary files from $path\ParsecTemp" -PercentComplete $percentcomplete
    Write-Output "[x] Cleaning Up TempFolder ($path\ParsecTemp)"
    Remove-Item -Path $path\ParsecTemp -Force -Recurse 
}

# function Start-GPUUpdate {
#     param(
#         [switch]$DontPromptPasswordUpdateGPU
#     )
#     if ($DontPromptPasswordUpdateGPU) {
#     }
#     Else {
#         Start-Process powershell.exe -verb RunAS -argument "-file $parsecPath\GPUUpdaterTool.ps1"
#     }
# }

Write-Host -foregroundcolor green "                                                        
                               ((//////                                
                             #######//////                             
                             ##########(/////.                         
                             #############(/////,                      
                             #################/////*                   
                             #######/############////.                 
                             #######/// ##########////                 
                             #######///    /#######///                 
                             #######///     #######///                 
                             #######///     #######///                 
                             #######////    #######///                 
                             ########////// #######///                 
                             ###########////#######///                 
                               ####################///                 
                                   ################///                 
                                     *#############///                 
                                         ##########///                 
                                            ######(*           
                                                    

                    ~Parsec Cloud GPU Gaming Setup Script~

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


Write-Output "[o] Setting up Environment"
if ((Test-Path -Path $path\ParsecTemp ) -eq $true) {
} 
Else {
    New-Item -Path $path\ParsecTemp -ItemType directory | Out-Null
}

$ScripttaskList = @(
    "Setup-Environment";
    "Add-RegItems";
    "Disable-IESecurity";
    "Enable-PhotoViewer";
    "Force-Close-Apps";
    "Disable-NetworkWindow";
    "Disable-Logout";
    "Disable-Lock";
    "Disable-RecentStartMenu";
    "Disable-ServerManager";
    "Show-Hidden-Items";
    "Show-FileExtensions";
    "Enable-Mousekeys";
    "Set-Time";
    "Set-Wallpaper";
    "Install-DirectX";
    "Install7Zip";
    "Install-XBox360Controller";
    "Install-Parsec";
    "Disable-Devices";
    "Install-ParsecVDD";
    "Install-VBAAudioDriver";
    "Start-Parsec";
    "CleanUp-AWSShortcuts";
    "CleanUp-Recent";
    "CleanUp-TempFolder";
)



foreach ($func in $ScripttaskList) {
    #$percentcomplete = $($ScriptTaskList.IndexOf($func) / $ScripttaskList.Count * 100)
    #& $func $percentcomplete
}

# StartGPUUpdate -DontPromptPasswordUpdateGPU:$DontPromptPasswordUpdateGPU
Write-Host "1. Open Parsec and Sign In to your account" -ForegroundColor black -BackgroundColor Green 
Write-Host "2. Use GPU Updater to update your GPU Drivers!" -ForegroundColor black -BackgroundColor Green 
Write-host "DONE!" -ForegroundColor black -BackgroundColor Green
if ($DontPromptPasswordUpdateGPU) {} 
Else { pause }




