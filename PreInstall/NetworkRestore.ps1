function Get-GPUStatus {
    # Enables disabled GPU device
    $getdisabled = Get-WmiObject win32_videocontroller | Where-Object { $_.name -like '*NVIDIA*' -and $_.status -like 'Error' } | Select-Object -ExpandProperty PNPDeviceID
    if ($getdisabled -ne $null) {
        Write-Output "Enabling GPU"
        $var = $getdisabled.Substring(0, 21)
        $arguement = "/r enable" + ' ' + "*" + "$var" + "*"
        Start-Process -FilePath "C:\ParsecTemp\Apps\devcon.exe" -ArgumentList $arguement
    }
    else { Write-Output "Device is enabled" }
}

function Get-DriverInstallStatus {
    # Checks if NVIDIA driver is installed, if not it enables it
    $checkdevicedriver = Get-WmiObject win32_videocontroller | Where-Object { $_.PNPDeviceID -like '*VEN_10DE*' }
    if ($checkdevicedriver.name -eq "Microsoft Basic Display Adapter") {
        Write-Output "Driver not installed"
    }
    else { Get-GPUStatus }
}

function Check-NvidiaDriverMode {
    # Check's NVIDIA driver mode WDDM vs. TCC
    $nvidiasmiarg = "-i 0 --query-gpu=driver_model.current --format=csv,noheader"
    $nvidiasmidir = "c:\program files\nvidia corporation\nvsmi\nvidia-smi" 
    $nvidiasmiresult = Invoke-Expression "& `"$nvidiasmidir`" $nvidiasmiarg"
    $nvidiadriverstatus = if ($nvidiasmiresult -eq "WDDM") {
        "GPU Driver status is good"
    }
    elseif ($nvidiasmiresult -eq "TCC") {
        Write-Output "The GPU has incorrect mode TCC set - setting WDDM"
        $nvidiasmiwddm = "-g 0 -dm 0"
        $nvidiasmidir = "c:\program files\nvidia corporation\nvsmi\nvidia-smi" 
        Invoke-Expression "& `"$nvidiasmidir`" $nvidiasmiwddm"
    }
    else {}
    Write-Output $nvidiadriverstatus
}

function Set-DHCP {
    # Set's IP and DNS to DHCP
    $global:interfaceindex = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object ifindex -ExpandProperty ifindex
    $Global:interfacename = Get-NetIPInterface -InterfaceIndex $interfaceindex -AddressFamily IPv4 | select interfacealias -ExpandProperty interfacealias
    $Global:setdhcp = "netsh interface ip set address '$interfacename' dhcp" 
    $Global:setdnsdhcp = "netsh interface ip set dns '$interfacename' dhcp" 
    Invoke-expression -command "$setdhcp"
    Invoke-expression -command "$setdnsdhcp"
}

function Enable-NetAdapter {
    # Enables adapter if required
    Get-NetAdapter | Where-Object { $_.Status -ne 'Up' } | Enable-NetAdapter
}

function Check-NetAdapter {    
    # Query netadapter and fixes it if requried
    $disabledAdapters = Get-NetAdapter | Where-Object { $_.Status -ne 'Up' }
    if ($disabledAdapters -ne $null) {
        # No adapters found - enabling disabled adapters and setting DHCP
        Write-Output "No adapters found - enabling disabled adapters and setting DHCP"
        Enable-NetAdapter
        Set-DHCP

    } else {
        # Resetting DHCP
        Write-Output "Resetting DHCP"
        Set-DHCP
    }
}
    
Get-DriverInstallStatus
Check-NvidiaDriverMode
Check-NetAdapter


