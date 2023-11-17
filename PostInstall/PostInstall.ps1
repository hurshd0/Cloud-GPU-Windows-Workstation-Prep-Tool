param (
    [switch]$DontPromptPasswordUpdateGPU
)

$host.ui.RawUI.WindowTitle = "Cloud GPU Preparation Tool"
[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 

# ###################################################################################
# Global envs
# ###################################################################################

$path = [Environment]::GetFolderPath("Desktop")
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

Function Get-InstanceCredential {
    Try {
        $Credential = Get-Credential -Credential $null
        Try {
            TestCredential -Credential $Credential 
        }
        Catch {
            Remove-Variable Credential
            #$Error[0].Exception.Message
            # "Retry?"
            $Retry = Read-Host "(Y/N)"
            Switch ($Retry) {
                Y {
                    GetInstanceCredential 
                }
                N {
                    Return
                }
            }
        }
    }
    Catch {
        if ($Credential) { Remove-Variable Credential }
        "You pressed cancel, retry?"
        $Cancel = Read-Host "(Y/N)"
        Switch ($Cancel) {
            Y {
                GetInstanceCredential
            }
            N {
                Return
            }
        }
    }
    if ($Credential) { Set-AutoLogon -Credential $Credential }
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

function Remove-Item {
    param (
        [string]$path
    )
    # Check if the item exists
    if (Test-Path $path) {
        # Item exists, so remove it
        Remove-Item -Path $path -Force
    }
    else {
        # Item doesn't exist, so do nothing
    }
}

# ##########################################################################################
# Setup ENV and Copy config files and scripts
# ##########################################################################################

function SetupEnvironment {
    # Creating Folders and moving script files into System directories
    ProgressWriter -Status "Moving files and folders into place" -PercentComplete $percentcomplete

    if ((Test-Path -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Startup) -eq $true) {} 
    Else { 
        New-Item -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Startup -ItemType directory | Out-Null 
    }

    if ((Test-Path -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown) -eq $true) {} 
    Else {
        New-Item -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown -ItemType directory | Out-Null 
    }

    if ((Test-Path -Path $env:ProgramData\ParsecLoader) -eq $true) {} 
    Else { 
        New-Item -Path $env:ProgramData\ParsecLoader -ItemType directory | Out-Null 
    }

    if ((Test-Path C:\Windows\system32\GroupPolicy\Machine\Scripts\psscripts.ini) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\psscripts.ini -Destination C:\Windows\system32\GroupPolicy\Machine\Scripts 
    }

    if ((Test-Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown\NetworkRestore.ps1) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\NetworkRestore.ps1 -Destination C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown 
    } 

    if ((Test-Path $env:ProgramData\ParsecLoader\Automatic-Shutdown.ps1) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\Automatic-Shutdown.ps1 -Destination $env:ProgramData\ParsecLoader 
    }

    if ((Test-Path $env:ProgramData\ParsecLoader\CreateAutomaticShutdownScheduledTask.ps1) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\CreateAutomaticShutdownScheduledTask.ps1 -Destination $env:ProgramData\ParsecLoader 
    }

    if ((Test-Path $env:ProgramData\ParsecLoader\GPU-Update.ico) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\GPU-Update.ico -Destination $env:ProgramData\ParsecLoader 
    }

    if ((Test-Path $env:ProgramData\ParsecLoader\GPUUpdaterTool.ps1) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\GPUUpdater\GPUUpdaterTool.ps1 -Destination $env:ProgramData\ParsecLoader 
    }

    if ((Test-Path $env:ProgramData\ParsecLoader\CreateOneHourWarningScheduledTask.ps1) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\CreateOneHourWarningScheduledTask.ps1 -Destination $env:ProgramData\ParsecLoader 
    }

    if ((Test-Path $env:ProgramData\ParsecLoader\WarningMessage.ps1) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\WarningMessage.ps1 -Destination $env:ProgramData\ParsecLoader 
    }

    if ((Test-Path $env:ProgramData\ParsecLoader\Parsec.png) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\Parsec.png -Destination $env:ProgramData\ParsecLoader 
    }

    if ((Test-Path $env:ProgramData\ParsecLoader\ShowDialog.ps1) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\ShowDialog.ps1 -Destination $env:ProgramData\ParsecLoader 
    }

    if ((Test-Path $env:ProgramData\ParsecLoader\OneHour.ps1) -eq $true) {} 
    Else {
        Move-Item -Path $path\ParsecTemp\PreInstall\OneHour.ps1 -Destination $env:ProgramData\ParsecLoader
    }

    if ((Test-Path $env:ProgramData\ParsecLoader\parsecpublic.cer) -eq $true) {} 
    Else { 
        Move-Item -Path $path\ParsecTemp\PreInstall\parsecpublic.cer -Destination $env:ProgramData\ParsecLoader 
    }
}

function Create-Directories {
    ProgressWriter -Status "Creating Directories (C:\ParsecTemp)" -PercentComplete $percentcomplete

    if ((Test-Path -Path C:\ParsecTemp) -eq $true) {} Else { New-Item -Path C:\ParsecTemp -ItemType directory | Out-Null }
    if ((Test-Path -Path C:\ParsecTemp\Apps) -eq $true) {} Else { New-Item -Path C:\ParsecTemp\Apps -ItemType directory | Out-Null }
    if ((Test-Path -Path C:\ParsecTemp\DirectX) -eq $true) {} Else { New-Item -Path C:\ParsecTemp\DirectX -ItemType directory | Out-Null }
    if ((Test-Path -Path C:\ParsecTemp\Drivers) -eq $true) {} Else { New-Item -Path C:\ParsecTemp\Drivers -ItemType Directory | Out-Null }
}


# ##########################################################################################
# Windows Registry Settings
# ##########################################################################################

function Add-GPOModifications {
    # Modifies Local Group Policy to enable Shutdown scrips items
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
        Write-Output "Not Required"
    }
}

function Add-RegItems {
    #Adds Premade Group Policy Item if existing configuration doesn't exist
    ProgressWriter -Status "Adding Registry Items and Group Policy" -PercentComplete $percentcomplete
    if (Test-Path ("C:\Windows\system32\GroupPolicy" + "\gpt.ini")) {
        Add-GPO-Modifications
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

Add-Type  @"
        using System;
        using System.Collections.Generic;
        using System.Text;
        using System.Runtime.InteropServices;
 
        namespace ComputerSystem
        {
            public class LSAutil
            {
                [StructLayout(LayoutKind.Sequential)]
                private struct LSA_UNICODE_STRING
                {
                    public UInt16 Length;
                    public UInt16 MaximumLength;
                    public IntPtr Buffer;
                }
 
                [StructLayout(LayoutKind.Sequential)]
                private struct LSA_OBJECT_ATTRIBUTES
                {
                    public int Length;
                    public IntPtr RootDirectory;
                    public LSA_UNICODE_STRING ObjectName;
                    public uint Attributes;
                    public IntPtr SecurityDescriptor;
                    public IntPtr SecurityQualityOfService;
                }
 
                private enum LSA_AccessPolicy : long
                {
                    POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
                    POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
                    POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
                    POLICY_TRUST_ADMIN = 0x00000008L,
                    POLICY_CREATE_ACCOUNT = 0x00000010L,
                    POLICY_CREATE_SECRET = 0x00000020L,
                    POLICY_CREATE_PRIVILEGE = 0x00000040L,
                    POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
                    POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
                    POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
                    POLICY_SERVER_ADMIN = 0x00000400L,
                    POLICY_LOOKUP_NAMES = 0x00000800L,
                    POLICY_NOTIFICATION = 0x00001000L
                }
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaRetrievePrivateData(
                            IntPtr PolicyHandle,
                            ref LSA_UNICODE_STRING KeyName,
                            out IntPtr PrivateData
                );
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaStorePrivateData(
                        IntPtr policyHandle,
                        ref LSA_UNICODE_STRING KeyName,
                        ref LSA_UNICODE_STRING PrivateData
                );
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaOpenPolicy(
                    ref LSA_UNICODE_STRING SystemName,
                    ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
                    uint DesiredAccess,
                    out IntPtr PolicyHandle
                );
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaNtStatusToWinError(
                    uint status
                );
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaClose(
                    IntPtr policyHandle
                );
 
                [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
                private static extern uint LsaFreeMemory(
                    IntPtr buffer
                );
 
                private LSA_OBJECT_ATTRIBUTES objectAttributes;
                private LSA_UNICODE_STRING localsystem;
                private LSA_UNICODE_STRING secretName;
 
                public LSAutil(string key)
                {
                    if (key.Length == 0)
                    {
                        throw new Exception("Key lenght zero");
                    }
 
                    objectAttributes = new LSA_OBJECT_ATTRIBUTES();
                    objectAttributes.Length = 0;
                    objectAttributes.RootDirectory = IntPtr.Zero;
                    objectAttributes.Attributes = 0;
                    objectAttributes.SecurityDescriptor = IntPtr.Zero;
                    objectAttributes.SecurityQualityOfService = IntPtr.Zero;
 
                    localsystem = new LSA_UNICODE_STRING();
                    localsystem.Buffer = IntPtr.Zero;
                    localsystem.Length = 0;
                    localsystem.MaximumLength = 0;
 
                    secretName = new LSA_UNICODE_STRING();
                    secretName.Buffer = Marshal.StringToHGlobalUni(key);
                    secretName.Length = (UInt16)(key.Length * UnicodeEncoding.CharSize);
                    secretName.MaximumLength = (UInt16)((key.Length + 1) * UnicodeEncoding.CharSize);
                }
 
                private IntPtr GetLsaPolicy(LSA_AccessPolicy access)
                {
                    IntPtr LsaPolicyHandle;
 
                    uint ntsResult = LsaOpenPolicy(ref this.localsystem, ref this.objectAttributes, (uint)access, out LsaPolicyHandle);
 
                    uint winErrorCode = LsaNtStatusToWinError(ntsResult);
                    if (winErrorCode != 0)
                    {
                        throw new Exception("LsaOpenPolicy failed: " + winErrorCode);
                    }
 
                    return LsaPolicyHandle;
                }
 
                private static void ReleaseLsaPolicy(IntPtr LsaPolicyHandle)
                {
                    uint ntsResult = LsaClose(LsaPolicyHandle);
                    uint winErrorCode = LsaNtStatusToWinError(ntsResult);
                    if (winErrorCode != 0)
                    {
                        throw new Exception("LsaClose failed: " + winErrorCode);
                    }
                }
 
                public void SetSecret(string Value)
                {
                    LSA_UNICODE_STRING lusSecretData = new LSA_UNICODE_STRING();
 
                    if (Value.Length > 0)
                    {
                        //Create data and key
                        lusSecretData.Buffer = Marshal.StringToHGlobalUni(Value);
                        lusSecretData.Length = (UInt16)(Value.Length * UnicodeEncoding.CharSize);
                        lusSecretData.MaximumLength = (UInt16)((Value.Length + 1) * UnicodeEncoding.CharSize);
                    }
                    else
                    {
                        //Delete data and key
                        lusSecretData.Buffer = IntPtr.Zero;
                        lusSecretData.Length = 0;
                        lusSecretData.MaximumLength = 0;
                    }
 
                    IntPtr LsaPolicyHandle = GetLsaPolicy(LSA_AccessPolicy.POLICY_CREATE_SECRET);
                    uint result = LsaStorePrivateData(LsaPolicyHandle, ref secretName, ref lusSecretData);
                    ReleaseLsaPolicy(LsaPolicyHandle);
 
                    uint winErrorCode = LsaNtStatusToWinError(result);
                    if (winErrorCode != 0)
                    {
                        throw new Exception("StorePrivateData failed: " + winErrorCode);
                    }
                }
            }
        }
"@

function Set-AutoLogon {
    [CmdletBinding(SupportsShouldProcess)]
    param
    (
        [PSCredential]$Credential
    )
    Try {
        if ($Credential.GetNetworkCredential().Domain) {
            $DefaultDomainName = $Credential.GetNetworkCredential().Domain
        }
        elseif ((Get-WMIObject Win32_ComputerSystem).PartOfDomain) {
            $DefaultDomainName = "."
        }
        else {
            $DefaultDomainName = ""
        }
    
        if ($PSCmdlet.ShouldProcess(('User "{0}\{1}"' -f $DefaultDomainName, $Credential.GetNetworkCredential().Username), "Set Auto logon")) {
            Write-Verbose ('DomainName: {0} / UserName: {1}' -f $DefaultDomainName, $Credential.GetNetworkCredential().Username)
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "AutoAdminLogon" -Value 1
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "DefaultDomainName" -Value ""
            Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "DefaultUserName" -Value $Credential.UserName
            Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "AutoLogonCount" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name "DefaultPassword" -ErrorAction SilentlyContinue
            $private:LsaUtil = New-Object ComputerSystem.LSAutil -ArgumentList "DefaultPassword"
            $LsaUtil.SetSecret($Credential.GetNetworkCredential().Password)
            "Auto Logon Configured"
            Remove-Variable Credential
        }
    }
    Catch {
        $Error[0].Exception.Message
        Throw
    }
}

function PromptUserAutoLogon {
    param (
        [switch]$DontPromptPasswordUpdateGPU
    )
    $CloudProvider = CloudProvider
    If ($DontPromptPasswordUpdateGPU) {
    }
    Else {
        "Detected $CloudProvider"
        Write-Host @"
Do you want this computer to log on to Windows automatically? 
(Y): This is good when you want the cloud computer to boot straight to Parsec but is less secure as the computer will not be protected by a password at start up
(N): If you plan to log into Windows with RDP then connect via Parsec, or have been told you don't need to set this up
"@ -ForegroundColor White -BackgroundColor DarkMagenta
        $ReadHost = Read-Host "(Y/N)" 
        Switch ($ReadHost) {
            Y {
                GetInstanceCredential
            }
            N {
            }
        }
    }
}

function Set-UpdatePolicy {
    # Disable's Windows Update
    
    ProgressWriter -Status "Disabling Windows Update" -PercentComplete $percentcomplete

    # 1. DoNotConnectToWindowsUpdateInternetLocations
    if ((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Value 'DoNotConnectToWindowsUpdateInternetLocations') -eq $true) { 
        Set-ItemProperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null 
    }
    else { 
        New-ItemProperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "DoNotConnectToWindowsUpdateInternetLocations" -Value "1" | Out-Null 
    }

    # 2. UpdateServiceURLAlternativ
    if ((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Value 'UpdateServiceURLAlternative') -eq $true) { 
        Set-ItemProperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null 
    } 
    else { 
        New-ItemProperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "UpdateServiceURLAlternative" -Value "http://intentionally.disabled" | Out-Null 
    }

    # 3. WUServer
    if ((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Value 'WUServer') -eq $true) { 
        Set-ItemProperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null 
    } 
    else { 
        New-ItemProperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUServer" -Value "http://intentionally.disabled" | Out-Null 
    }

    # 4. WUStatusServer
    if ((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Value 'WUSatusServer') -eq $true) { 
        Set-ItemProperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null 
    }
    else { 
        New-ItemProperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "WUSatusServer" -Value "http://intentionally.disabled" | Out-Null 
    }

    # 5. AUOptions
    Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "AUOptions" -Value 1 | Out-Null

    # 6. UseWUServer
    if ((Test-RegistryValue -path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Value 'UseWUServer') -eq $true) { 
        Set-ItemProperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null 
    }
    else { 
        New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name "UseWUServer" -Value 1 | Out-Null 
    }
}

function Disable-NetworkWindow {
    # Disable's new network window pop up
    ProgressWriter -Status "Disabling New Network Window" -PercentComplete $percentcomplete
    if ((Test-RegistryValue -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -Value 'NewNetworkWindowOff') -eq $true) {
    }
    Else { 
        New-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Control\Network -name "NewNetworkWindowOff" | Out-Null 
    }
}

function Disable-IESecurity {
    ProgressWriter -Status "Disabling Internet Explorer security to enable web browsing" -PercentComplete $percentcomplete
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -name IsInstalled -Value 0 -force | Out-Null
    Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name IsInstalled -Value 0 -Force | Out-Null
    Stop-Process -Name Explorer -Force
}

function Set-Time {
    # Set Automatic Time and Timezone
    ProgressWriter -Status "Setting computer time to automatic" -PercentComplete $percentcomplete
    Set-ItemProperty -path HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters -Name Type -Value NTP | Out-Null
    Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\tzautoupdate -Name Start -Value 00000003 | Out-Null
}

function Enable-Mousekeys {
    ProgressWriter -Status "Enabling mouse keys to assist with mouse cursor" -PercentComplete $percentcomplete
    Set-ItemProperty -Path 'HKCU:\Control Panel\Accessibility\MouseKeys' -Name Flags -Value 63 | Out-Null
}

function Force-Close-Apps {
    # Sets all applications to force close on shutdown
    ProgressWriter -Status "Setting Windows not to stop shutdown if there are unsaved apps" -PercentComplete $percentcomplete
    if (((Get-Item -Path "HKCU:\Control Panel\Desktop").GetValue("AutoEndTasks") -ne $null) -eq $true) {
        Set-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
    }
    Else {
        New-ItemProperty -path "HKCU:\Control Panel\Desktop" -Name "AutoEndTasks" -Value "1"
    }
}

function Show-Hidden-Items {
    # Shows hidden items
    ProgressWriter -Status "Showing hidden files in Windows Explorer" -PercentComplete $percentcomplete
    $hide = (Get-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced").Hidden
    if ($hide -eq 1) {
        Set-ItemProperty -path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name Hidden -Value 1 | Out-Null
    }
}

function Show-FileExtensions {
    # Shows file extensions
    ProgressWriter -Status "Showing file extensions in Windows Explorer" -PercentComplete 
    $percentcomplete
    $hide = (Get-ItemProperty -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced).HideFileExt
    If ($hide -eq 1) {   
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Name HideFileExt -Value 0 | Out-Null
    }   
}

function Disable-Logout {
    # Disable logout start menu
    ProgressWriter -Status "Disabling log out button on start menu" -PercentComplete $percentcomplete
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
    ProgressWriter -Status "Disabling Recent Start Menu Items" -PercentComplete $percentcomplete
    New-Item -path HKLM:\SOFTWARE\Policies\Microsoft\Windows -name Explorer
    New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer -PropertyType DWORD -Name HideRecentlyAddedApps -Value 1
}

function Disable-ServerManager {
    # Disable's Server Manager opening on Startup
    ProgressWriter -Status "Disabling Windows Server Manager from starting at startup" -PercentComplete $percentcomplete
    Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask | Out-Null
}

function CleanUp-AWSShortcuts {
    # Removes AWS shortcuts
    ProgressWriter -Status "Remove AWS Shortcuts" -PercentComplete $percentcomplete
    $shortcuts = @(
        "$path\EC2 Feedback.Website",
        "$path\EC2 Microsoft Windows Guide.website"
    )
    foreach ($shortcut in $shortcuts) {
        Write-Host $shortcut
        if (Test-Path $shortcut) {
            Remove-Item -Path $shortcut -Force
        }
    }    
}

function CleanUp-Recent {
    # Cleanups recent files
    ProgressWriter -Status "Delete recently accessed files list from Windows Explorer" -PercentComplete $percentcomplete
    Remove-Item "$env:AppData\Microsoft\Windows\Recent\*" -Force -Recurse 
}

function Set-Wallpaper {
    ProgressWriter -Status "Setting the Parsec logo as computer wallpaper" -PercentComplete $percentcomplete

    (New-Object System.Net.WebClient).DownloadFile("https://s3.amazonaws.com/parseccloud/image/parsec+desktop.png", "C:\ParsecTemp\parsec+desktop.png")

    if ((Test-Path -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System) -eq $true) {} 
    Else { 
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies" -Name "System" | Out-Null 
    }

    if ((Test-RegistryValue -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -value Wallpaper) -eq $true) { 
        Set-ItemProperty -Path (New-Object System.Net.WebClient).DownloadFile("https://s3.amazonaws.com/parseccloud/image/parsec+desktop.png", "C:\ParsecTemp\parsec+desktop.png") -Name Wallpaper -value "C:\ParsecTemp\parsec+desktop.png" | Out-Null 
    } 
    Else { 
        New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name Wallpaper -PropertyType String -value "C:\ParsecTemp\parsec+desktop.png" | Out-Null 
    }

    if ((Test-RegistryValue -path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -value WallpaperStyle) -eq $true) { 
        Set-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name WallpaperStyle -value 2 | Out-Null 
    } 
    Else { 
        New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System -Name WallpaperStyle -PropertyType String -value 2 | Out-Null 
    }
    Stop-Process -ProcessName explorer
}

function Enable-PhotoViewer {
    ProgressWriter -Status "Enabling Photo Viewer" -PercentComplete $percentcomplete
    
    # Step 1: Check if Photo Viewer DLLs exist
    $photoViewerDLLPath = "C:\Program Files (x86)\Windows Photo Viewer\PhotoViewer.dll"
    if (Test-Path -Path $photoViewerDLLPath) {
        Write-Host "Found Photo Viewer DLL files"

        # Step 2: Register PhotoViewer.dll
        Write-Host "Registering PhotoViewer.dll"
        regsvr32.exe /s "$photoViewerPath\PhotoViewer.dll"
        
        # Step 3: Download registry keys
        $downloadPath = "$path\ParsecTemp\MSPhotoViewerRegFiles.zip"
        $downloadURL = "https://green.cloud/docs/wp-content/uploads/2023/02/MSPhotoViewerRegFiles.zip.zip"
        if (Test-Path -Path $downloadPath) {
            Write-Host "MSPhotoViewerRegFiles.zip already exists, skipping ..."
        } else {
            # Download the zip file
            Write-Host "Downloading Photo Viewer Registry Files"
            Invoke-WebRequest -Uri $downloadURL -OutFile $downloadPath
        }

        # Step 4: Extract registry keys
        Write-Host "Extracting registry keys"
        Expand-Archive -Path $downloadPath -DestinationPath "$path\ParsecTemp\MSPhotoViewerRegFiles" -Force
        
        # Step 5: Import each registry keys
        Write-Host "Importing registry keys"
        $regFiles = Get-ChildItem -Path "$path\ParsecTemp\MSPhotoViewerRegFiles\*.reg" -Recurse -Force
        if ($regFiles) {
            foreach ($regFile in $regFiles) {
                $regFileName = $regFile.Name
                Write-Host "Importing $regFileName"
                # Import each registry key
                reg import "$regFile" 2>$null
            }
        } 
        ProgressWriter -Status "Windows Photo Viewer enabled and configured successfully!" -PercentComplete $percentcomplete
    } else {
        ProgressWriter -Status "Windows Photo Viewer DLLs not found at $photoViewerDLLPath." -PercentComplete $percentcomplete
    }
}


# ##########################################################################################
# Install dependencies DirectX, Microsoft Xbox 360 Controller, .NET packages etc... and necessary software like Parsec, 7zip
# ##########################################################################################

function Install-DirectX {
    # Install DirectX
    ProgressWriter -Status "Downloading DirectX June 2010 Redist" -PercentComplete $percentcomplete
    (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe", "C:\ParsecTemp\Apps\directx_Jun2010_redist.exe") 

    ProgressWriter -Status "Installing DirectX June 2010 Redist" -PercentComplete $percentcomplete
    Start-Process -FilePath "C:\ParsecTemp\Apps\directx_jun2010_redist.exe" -ArgumentList '/T:C:\ParsecTemp\DirectX /Q'-wait
    Start-Process -FilePath "C:\ParsecTemp\DirectX\DXSETUP.EXE" -ArgumentList '/silent' -wait
    ProgressWriter -Status "Installing Direct Play" -PercentComplete $percentcomplete
    Install-WindowsFeature Direct-Play | Out-Null
    ProgressWriter -Status "Installing .net 3.5" -PercentComplete $percentcomplete
    Install-WindowsFeature Net-Framework-Core | Out-Null
}

function Install7Zip {
    # 7Zip is required to extract the Parsec-Windows.exe File
    $installationPath = Get-Item -Path "C:\Program Files\7-Zip" -ErrorAction SilentlyContinue
    if ($installationPath -ne $null) {
        ProgressWriter -Status "7zip is Installed Skipping" -PercentComplete $percentcomplete
    }
    else {
        ProgressWriter -Status "Downloading 7zip" -PercentComplete $percentcomplete
        $url = Invoke-WebRequest -Uri https://www.7-zip.org/download.html
        (New-Object System.Net.WebClient).DownloadFile("https://www.7-zip.org/$($($($url.Links | Where-Object outertext -Like "Download")[1]).OuterHTML.split('"')[1])" , "C:\ParsecTemp\Apps\7zip.exe")
    
        ProgressWriter -Status "Installing 7zip" -PercentComplete $percentcomplete
        Start-Process C:\ParsecTemp\Apps\7zip.exe -ArgumentList '/S /D="C:\Program Files\7-Zip"' -Wait

    }
}

function Install-XBox360Controller {
    ProgressWriter -Status "Adding Xbox 360 Controller driver to Windows Server 2019/2022" -PercentComplete $percentcomplete

    $operatingSystem = Get-WmiObject -Class Win32_OperatingSystem
    if ($operatingSystem.Caption -match "Server" -and ($operatingSystem.Version -eq "10.0.17763" -or $operatingSystem.Version -eq "10.0.20348")) {
        (New-Object System.Net.WebClient).DownloadFile("http://www.download.windowsupdate.com/msdownload/update/v3-19990518/cabpool/2060_8edb3031ef495d4e4247e51dcb11bef24d2c4da7.cab", "C:\ParsecTemp\Drivers\Xbox360_64Eng.cab")
        if ((Test-Path -Path C:\ParsecTemp\Drivers\Xbox360_64Eng) -eq $true) 
        {} 
        Else { 
            New-Item -Path C:\ParsecTemp\Drivers\Xbox360_64Eng -ItemType directory | Out-Null 
        }
        cmd.exe /c "C:\Windows\System32\expand.exe C:\ParsecTemp\Drivers\Xbox360_64Eng.cab -F:* C:\ParsecTemp\Drivers\Xbox360_64Eng" | Out-Null
        cmd.exe /c '"C:\Program Files\Parsec\vigem\10\x64\devcon.exe" dp_add "C:\ParsecTemp\Drivers\Xbox360_64Eng\xusb21.inf"' | Out-Null
    }
}
 
function Install-Parsec {
    ProgressWriter -Status "Downloading Parsec" -PercentComplete $percentcomplete
    (New-Object System.Net.WebClient).DownloadFile("https://builds.parsecgaming.com/package/parsec-windows.exe", "C:\ParsecTemp\Apps\parsec-windows.exe")

    ProgressWriter -Status "Installing Parsec" -PercentComplete $percentcomplete
    Start-Process "C:\ParsecTemp\Apps\parsec-windows.exe" -ArgumentList "/silent" -wait
}

function Install-ParsecVDD {
    ProgressWriter -Status "Downloading Parsec Virtual Display Driver" -percentcomplete $percentcomplete
    (New-Object System.Net.WebClient).DownloadFile("https://builds.parsec.app/vdd/parsec-vdd-0.37.0.0.exe", "C:\ParsecTemp\Apps\parsec-vdd.exe")

    ProgressWriter -Status "Installing Parsec Virtual Display Driver" -PercentComplete $percentcomplete
    Import-Certificate -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" -FilePath "$env:ProgramData\ParsecLoader\parsecpublic.cer" | Out-Null
    Start-Process "C:\ParsecTemp\Apps\parsec-vdd.exe" -ArgumentList "/silent" 
    $iterator = 0    
    do {
        Start-Sleep -s 2
        $iterator++
    }
    Until (($null -ne ((Get-PnpDevice | Where-Object { $_.Name -eq "Parsec Virtual Display Adapter" }).DeviceID)) -or ($iterator -gt 7))
    if (Get-process -name parsec-vdd -ErrorAction SilentlyContinue) {
        Stop-Process -name parsec-vdd -Force
    }
    $configfile = Get-Content C:\ProgramData\Parsec\config.txt
    $configfile += "host_virtual_monitors = 1"
    $configfile += "host_privacy_mode = 1"
    $configfile | Out-File C:\ProgramData\Parsec\config.txt -Encoding ascii
}

function Start-Parsec {
    ProgressWriter -Status "Starting Parsec" -PercentComplete $percentcomplete
    Start-Process -FilePath "C:\Program Files\Parsec\parsecd.exe"
    Start-Sleep -s 1
}

function Install-VBAAudioDriver {
    # Audio Driver Install
    ProgressWriter -Status "Downloading VBA Audio Driver" -percentcomplete $percentcomplete
    (New-Object System.Net.WebClient).DownloadFile("https://download.vb-audio.com/Download_CABLE/VBCABLE_Driver_Pack43.zip", "C:\ParsecTemp\Apps\VBCable.zip")

    ProgressWriter -Status "Installing VBA Audio Driver" -percentcomplete $percentcomplete
    New-Item -Path "C:\ParsecTemp\Apps\VBCable" -ItemType Directory | Out-Null
    Expand-Archive -Path "C:\ParsecTemp\Apps\VBCable.zip" -DestinationPath "C:\ParsecTemp\Apps\VBCable"
    $pathToCatFile = "C:\ParsecTemp\Apps\VBCable\vbaudio_cable64_win7.cat"
    $FullCertificateExportPath = "C:\ParsecTemp\Apps\VBCable\VBCert.cer"
    $VB = @{}
    $VB.DriverFile = $pathToCatFile;
    $VB.CertName = $FullCertificateExportPath;
    $VB.ExportType = [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert;
    $VB.Cert = (Get-AuthenticodeSignature -filepath $VB.DriverFile).SignerCertificate;
    [System.IO.File]::WriteAllBytes($VB.CertName, $VB.Cert.Export($VB.ExportType))
    Import-Certificate -CertStoreLocation Cert:\LocalMachine\TrustedPublisher -FilePath $VB.CertName | Out-Null
    Start-Process -FilePath "C:\ParsecTemp\Apps\VBCable\VBCABLE_Setup_x64.exe" -ArgumentList '-i', '-h'
    Set-Service -Name audiosrv -StartupType Automatic
    Start-Service -Name audiosrv
}

# ########################################################################################
# After Parsec Installation
# ########################################################################################

function Disable-Devices {
    # Disable Display Adapter Devices
    ProgressWriter -Status "Disabling Microsoft Basic Display Adapter, Generic Non PNP Monitor and other devices" -PercentComplete $percentcomplete

    Get-PnpDevice | where { $_.friendlyname -like "Generic Non-PNP Monitor" -and $_.status -eq "OK" } | Disable-PnpDevice -confirm:$false
    Get-PnpDevice | where { $_.friendlyname -like "Microsoft Basic Display Adapter" -and $_.status -eq "OK" } | Disable-PnpDevice -confirm:$false
    Get-PnpDevice | where { $_.friendlyname -like "Microsoft Hyper-V Video" -and $_.status -eq "OK" } | Disable-PnpDevice -confirm:$false

    Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "PCI\VEN_1013&DEV_00B8*"'
    Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "PCI\VEN_1D0F&DEV_1111*"'
    Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "PCI\VEN_1AE0&DEV_A002*"'
    Start-Process -FilePath "C:\Program Files\Parsec\vigem\10\x64\devcon.exe" -ArgumentList '/r disable "HDAUDIO\FUNC_01&VEN_10DE&DEV_0083&SUBSYS_10DE11A3*"'

}

# ########################################################################################
# Create Shortcuts 
# ########################################################################################

function Create-AutoShutdownShortcut {
    ProgressWriter -Status "Creating Auto Shutdown Shortcut" -PercentComplete $percentcomplete
    $Shell = New-Object -ComObject ("WScript.Shell")
    $ShortCut = $Shell.CreateShortcut("$env:USERPROFILE\Desktop\Setup Auto Shutdown.lnk")
    $ShortCut.TargetPath = "powershell.exe"
    $ShortCut.Arguments = '-ExecutionPolicy Bypass -File "C:\ProgramData\ParsecLoader\CreateAutomaticShutdownScheduledTask.ps1"'
    $ShortCut.WorkingDirectory = "$env:ProgramData\ParsecLoader";
    $ShortCut.WindowStyle = 0;
    $ShortCut.Description = "Autoshutdown shortcut";
    $ShortCut.Save()
}

function Create-One-Hour-Warning-Shortcut {
    ProgressWriter -Status "Creating one hour warning shortcut" -PercentComplete $percentcomplete
    $Shell = New-Object -ComObject ("WScript.Shell")
    $ShortCut = $Shell.CreateShortcut("$env:USERPROFILE\Desktop\Setup One Hour Warning.lnk")
    $ShortCut.TargetPath = "powershell.exe"
    $ShortCut.Arguments = '-ExecutionPolicy Bypass -File "C:\ProgramData\ParsecLoader\CreateOneHourWarningScheduledTask.ps1"'
    $ShortCut.WorkingDirectory = "$env:ProgramData\ParsecLoader";
    $ShortCut.WindowStyle = 0;
    $ShortCut.Description = "OneHourWarning shortcut";
    $ShortCut.Save()
}

function Create-GPUUpdateShortcut {


    Unblock-File -Path "$env:ProgramData\ParsecLoader\GPUUpdaterTool.ps1"

    ProgressWriter -Status "Creating GPU Updater icon on Desktop" -PercentComplete $percentcomplete

    $Shell = New-Object -ComObject ("WScript.Shell")
    $ShortCut = $Shell.CreateShortcut("$path\GPU Updater.lnk")
    $ShortCut.TargetPath = "powershell.exe"
    $ShortCut.Arguments = '-ExecutionPolicy Bypass -File "C:\ProgramData\ParsecLoader\GPUUpdaterTool.ps1"'
    $ShortCut.WorkingDirectory = "$env:ProgramData\ParsecLoader";
    $ShortCut.IconLocation = "$env:ProgramData\ParsecLoader\GPU-Update.ico, 0";
    $ShortCut.WindowStyle = 0;
    $ShortCut.Description = "GPU Updater shortcut";
    $ShortCut.Save()
}

# ########################################################################################
# Post Install Cleanup
# ########################################################################################

function CleanUp-TempFolder {
    # Cleanup Tempfolder
    ProgressWriter -Status "Deleting temporary files from C:\ParsecTemp" -PercentComplete $percentcomplete
    Remove-Item -Path $path\ParsecTemp -Force -Recurse 
}

# function Start-GPUUpdate {
#     param(
#         [switch]$DontPromptPasswordUpdateGPU
#     )
#     if ($DontPromptPasswordUpdateGPU) {
#     }
#     Else {
#         Start-Process powershell.exe -verb RunAS -argument "-file $env:ProgramData\ParsecLoader\GPUUpdaterTool.ps1"
#     }
# }

# Write-Host -foregroundcolor green "                                                        
#                                ((//////                                
#                              #######//////                             
#                              ##########(/////.                         
#                              #############(/////,                      
#                              #################/////*                   
#                              #######/############////.                 
#                              #######/// ##########////                 
#                              #######///    /#######///                 
#                              #######///     #######///                 
#                              #######///     #######///                 
#                              #######////    #######///                 
#                              ########////// #######///                 
#                              ###########////#######///                 
#                                ####################///                 
#                                    ################///                 
#                                      *#############///                 
#                                          ##########///                 
#                                             ######(*           
                                                    

#                     ~Parsec Cloud GPU Gaming Setup Script~

#                     This script sets up your cloud computer
#                     with a bunch of settings and drivers
#                     to make your life easier.  
                    
#                     It's provided with no warranty, 
#                     so use it at your own risk.
                    
#                     Check out the README.md for more
#                     troubleshooting info.

#                     This tool supports:
                    
#                     OS:
#                     Server 2022 Base AMI
#                     Server 2019 Base AMI
                    
#                     CLOUD GPU INSTANCES:
#                     AWS G5.2xLarge    (Ampere A10G)
#                     AWS g4dn.xlarge   (Tesla T4)
#                     AWS g4ad.4xlarge  (AMD Radeon Pro V520)

    
# "        


Write-Output "[o] Setting up Environment"
if ((Test-Path -Path $path\ParsecTemp ) -eq $true) {
} 
Else {
  New-Item -Path $path\ParsecTemp -ItemType directory | Out-Null
}

$ScripttaskList = @(
    "Enable-PhotoViewer";
)



foreach ($func in $ScripttaskList) {
    $percentcomplete = $($ScriptTaskList.IndexOf($func) / $ScripttaskList.Count * 100)
    & $func $percentcomplete
}

# StartGPUUpdate -DontPromptPasswordUpdateGPU:$DontPromptPasswordUpdateGPU
# Write-Host "1. Open Parsec and Sign In to your account" -ForegroundColor black -BackgroundColor Green 
# Write-Host "2. Use GPU Updater to update your GPU Drivers!" -ForegroundColor black -BackgroundColor Green 
# Write-host "DONE!" -ForegroundColor black -BackgroundColor Green
if ($DontPromptPasswordUpdateGPU) {} 
Else { pause }




