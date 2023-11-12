param (
    [switch]$DontPromptPasswordUpdateGPU
)


$host.ui.RawUI.WindowTitle = "Cloud GPU Preparation Tool"

[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls" 

add-type  @"
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
 
                public void SetSecret(string value)
                {
                    LSA_UNICODE_STRING lusSecretData = new LSA_UNICODE_STRING();
 
                    if (value.Length > 0)
                    {
                        //Create data and key
                        lusSecretData.Buffer = Marshal.StringToHGlobalUni(value);
                        lusSecretData.Length = (UInt16)(value.Length * UnicodeEncoding.CharSize);
                        lusSecretData.MaximumLength = (UInt16)((value.Length + 1) * UnicodeEncoding.CharSize);
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
# ###################################################################################
# Global envs
# ###################################################################################
$path = [Environment]::GetFolderPath("Desktop")
$currentusersid = Get-LocalUser "$env:USERNAME" | Select-Object SID | ft -HideTableHeaders | Out-String | ForEach-Object { $_.Trim() }

# ###################################################################################
# UTIL FUNCTIONS
# ###################################################################################
Function SetupEnvironment {
    # Creating Folders and moving script files into System directories
    ProgressWriter -Status "Moving files and folders into place" -PercentComplete $PercentComplete
    if ((Test-Path -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Startup) -eq $true) {} Else { New-Item -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Startup -ItemType directory | Out-Null }
    if ((Test-Path -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown) -eq $true) {} Else { New-Item -Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown -ItemType directory | Out-Null }
    if ((Test-Path -Path $env:ProgramData\ParsecLoader) -eq $true) {} Else { New-Item -Path $env:ProgramData\ParsecLoader -ItemType directory | Out-Null }
    if ((Test-Path C:\Windows\system32\GroupPolicy\Machine\Scripts\psscripts.ini) -eq $true) {} Else { Move-Item -Path $path\ParsecTemp\PreInstall\psscripts.ini -Destination C:\Windows\system32\GroupPolicy\Machine\Scripts }
    if ((Test-Path C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown\NetworkRestore.ps1) -eq $true) {} Else { Move-Item -Path $path\ParsecTemp\PreInstall\NetworkRestore.ps1 -Destination C:\Windows\system32\GroupPolicy\Machine\Scripts\Shutdown } 
    if ((Test-Path $env:ProgramData\ParsecLoader\clear-proxy.ps1) -eq $true) {} Else { Move-Item -Path $path\ParsecTemp\PreInstall\clear-proxy.ps1 -Destination $env:ProgramData\ParsecLoader }
    if ((Test-Path $env:ProgramData\ParsecLoader\CreateClearProxyScheduledTask.ps1) -eq $true) {} Else { Move-Item -Path $path\ParsecTemp\PreInstall\CreateClearProxyScheduledTask.ps1 -Destination $env:ProgramData\ParsecLoader }
    if ((Test-Path $env:ProgramData\ParsecLoader\Automatic-Shutdown.ps1) -eq $true) {} Else { Move-Item -Path $path\ParsecTemp\PreInstall\Automatic-Shutdown.ps1 -Destination $env:ProgramData\ParsecLoader }
    if ((Test-Path $env:ProgramData\ParsecLoader\CreateAutomaticShutdownScheduledTask.ps1) -eq $true) {} Else { Move-Item -Path $path\ParsecTemp\PreInstall\CreateAutomaticShutdownScheduledTask.ps1 -Destination $env:ProgramData\ParsecLoader }
    if ((Test-Path $env:ProgramData\ParsecLoader\GPU-Update.ico) -eq $true) {} Else { Move-Item -Path $path\ParsecTemp\PreInstall\GPU-Update.ico -Destination $env:ProgramData\ParsecLoader }
    if ((Test-Path $env:ProgramData\ParsecLoader\CreateOneHourWarningScheduledTask.ps1) -eq $true) {} Else { Move-Item -Path $path\ParsecTemp\PreInstall\CreateOneHourWarningScheduledTask.ps1 -Destination $env:ProgramData\ParsecLoader }
    if ((Test-Path $env:ProgramData\ParsecLoader\WarningMessage.ps1) -eq $true) {} Else { Move-Item -Path $path\ParsecTemp\PreInstall\WarningMessage.ps1 -Destination $env:ProgramData\ParsecLoader }
    if ((Test-Path $env:ProgramData\ParsecLoader\Parsec.png) -eq $true) {} Else { Move-Item -Path $path\ParsecTemp\PreInstall\Parsec.png -Destination $env:ProgramData\ParsecLoader }
    if ((Test-Path $env:ProgramData\ParsecLoader\ShowDialog.ps1) -eq $true) {} Else { Move-Item -Path $path\ParsecTemp\PreInstall\ShowDialog.ps1 -Destination $env:ProgramData\ParsecLoader }
    if ((Test-Path $env:ProgramData\ParsecLoader\OneHour.ps1) -eq $true) {} Else { Move-Item -Path $path\ParsecTemp\PreInstall\OneHour.ps1 -Destination $env:ProgramData\ParsecLoader }
    if ((Test-Path $env:ProgramData\ParsecLoader\TeamMachineSetup.ps1) -eq $true) {} Else { Move-Item -Path $path\ParsecTemp\PreInstall\TeamMachineSetup.ps1 -Destination $env:ProgramData\ParsecLoader }
    if ((Test-Path $env:ProgramData\ParsecLoader\parsecpublic.cer) -eq $true) {} Else { Move-Item -Path $path\ParsecTemp\PreInstall\parsecpublic.cer -Destination $env:ProgramData\ParsecLoader }
}


Function CloudProvider { 
    # finds the cloud provider that this VM is hosted by   
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

Function ProgressWriter {
    # Gives progress update message to a user 
    param (
        [int]$percentcomplete,
        [string]$status
    )
    Write-Progress -Activity "Setting Up Your Machine" -Status $status -PercentComplete $PercentComplete
}


Function Set-AutoLogon {
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

Function GetInstanceCredential {
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


Function PromptUserAutoLogon {
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

#Modifies Local Group Policy to enable Shutdown scrips items
Function AddGPOModifications {
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