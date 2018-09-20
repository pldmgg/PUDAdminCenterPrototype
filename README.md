[![Build status](https://ci.appveyor.com/api/projects/status/github/pldmgg/=master&svg=true)](https://ci.appveyor.com/project/pldmgg/PUDAdminCenterPrototype/branch/master)


# PUDAdminCenterPrototype
Web-based GUI (PowerShell Universal Dashboard) that manages remote devices. Based on Windows Admin Center: https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/overview.

# Screenshots

![Home](/Media/Home.png)
![Overview](/Media/Overview.png)

## Getting Started

Currently, PUDAdminCenterPrototype is not compatible with PowerShell Core 6.X (for various reasons). However, I will be working on refactoring this Module and bug fixing PowerShell Universal Dashboard in order to make a PowerShell Core 6.X solution. You can view my progress on this refactor here: "placeholder"

In the mean time, you can install and run PUDAdminCenterPrototype by launch Windows PowerShell 5.1 via 'Run As Administrator' and do the following:

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

There are many function available upon Module import, and they can all be used independent of the Web Application. However, the main
function that handles starting the Universal Dashboard WebServer is `Get-PUDAdminPrototype`.

## Examples

### Scenario 1: Run the WebServer on localhost port 80 from an interactive Windows PowerShell 5.1 Session

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
