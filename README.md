[![Build status](https://ci.appveyor.com/api/projects/status/github/pldmgg/=master&svg=true)](https://ci.appveyor.com/project/pldmgg/PUDAdminCenterPrototype/branch/master)


# PUDAdminCenterPrototype

The goal of PUDAdminCenter is to provide a comprehensive, **easily customizable** Web App capable of managing Windows and Linux machines in your environment. It is based on functionality found in Microsoft's Windows Admin Center (https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/overview).

The PUDAdminCenterPrototype Module is a proof-of-concept that is currently only capable of managing Windows machines that have WinRM implemented via Windows PowerShell 5.1. PowerShell Core 6.X will allow for cross-platform management, however, for various reasons, the PUDAdminCenterPrototype Module is not fully compatible. As I refactor my own code and assist with bug fixes for PowerShell Universal Dashboard (https://github.com/ironmansoftware/universal-dashboard), I will slowly be adding features to the PowerShell Core compatible version here: https://github.com/pldmgg/PUDAdminCenter

In the mean time, you can install and run PUDAdminCenterPrototype by using Windows PowerShell 5.1 on Windows 10, Windows 2012 R2, Windows 2016, or Windows 2019.

# Screenshots

![Home](/Media/Home.png)
![Overview](/Media/Overview.png)

## Getting Started

Launch Windows PowerShell 5.1 via 'Run As Administrator' and do the following:

```powershell
# Make sure you have .Net 4.7.2 (or later) installed
# NOTE: The Install-DotNet472 function will not do anything if you already have .Net 4.7.2 installed.
# NOTE: If you do NOT already have .Net 4.7.2 installed, you will need to restart computer post-install!
$InstallDotNet472FunctionUrl = "https://raw.githubusercontent.com/pldmgg/misc-powershell/master/MyFunctions/Install-DotNet472.ps1"
$OutFilePath = "$HOME\Downloads\Install-DotNet472.ps1"
Invoke-WebRequest -Uri $InstallDotNet472FunctionUrl -OutFile $OutFilePath
. $OutFilePath
Install-DotNet472

# If you need to restart, do so now.

# Install and Import the UniversalDashboard.Community Module
Install-Module UniversalDashboard.Community
# Accept the license agreement
Import-Module UniversalDashboard.Community

# Finally, install and import the PUDAdminCenterPrototype Module
Install-Module PUDAdminCenterPrototype
Import-Module PUDAdminCenterPrototype
```

There are many functions available upon Module import, and they can all be used independent of the Web Application. However, the main function that handles starting the Universal Dashboard WebServer is `Get-PUDAdminPrototype`.

## Examples

### Scenario 1: Run the WebServer on localhost port 80 from an interactive Windows PowerShell 5.1 Session

IMPORTANT NOTE: Running `Get-PUDAdminCenter` without any parameters will install nmap (https://nmap.org/book/inst-windows.html). If you do NOT want nmap installed, use the parameter `-InstallNmap:$False`

```powershell
PS C:\Users\zeroadmin> Get-PUDAdminCenter

Name       Port Running
----       ---- -------
Dashboard0   80    True
```

Navigate to http://localhost in Chrome, Firefox, or Edge. (Internet Explorer does NOT work)

### Scenario 2: Run the WebServer on localhost port 8888 from an interactive Windows PowerShell 5.1 Session

```powershell
PS C:\Users\zeroadmin> Get-PUDAdminCenter -Port 8888

Name         Port Running
----         ---- -------
Dashboard0   8888    True
```

Navigate to http://localhost:8888 in Chrome, Firefox, or Edge. (Internet Explorer does NOT work)

### Scenario 3: Run the WebServer as a Windows Service

```powershell
Install-Program -ProgramName nssm -CommandName nssm.exe
$NssmExePath = $(Get-Command nssm).Source
$PowershellExePath = $(Get-Command powershell).Source
$NewServiceName = 'PUDAdminCenterService'
$PUDAdminCenterManifestPath = $(@($(Get-Module -ListAvailable -Name "PUDAdminCenterPrototype")) | Sort-Object -Property Version)[-1].Path
$LocalPSScriptDir = "C:\Scripts\powershell"
if (!$(Test-Path $LocalPSScriptDir)) {$null = New-Item -Path $LocalPSScriptDir -ItemType Directory -Force}
$ScriptPath = "$LocalPSScriptDir\RunPUDAdminCenter.ps1"
Set-Content -Path $ScriptPath -Value "Import-Module '$PUDAdminCenterManifestPath'; Get-PUDAdminCenter"
$NssmArguments = '-ExecutionPolicy Bypass -NoProfile -File "{0}"' -f $ScriptPath
& $NssmExePath install $NewServiceName $PowershellExePath $NssmArguments
& $NssmExePath status $NewServiceName
Start-Service $NewServiceName
Get-Service $NewServiceName
```

Navigate to http://localhost in Chrome, Firefox, or Edge. (Internet Explorer does NOT work)

## Notes

* PSGallery: https://www.powershellgallery.com/packages/PUDAdminCenterProtoType
