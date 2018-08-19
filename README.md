[![Build status](https://ci.appveyor.com/api/projects/status/github/pldmgg/=master&svg=true)](https://ci.appveyor.com/project/pldmgg/PUDAdminCenterPrototype/branch/master)


# PUDAdminCenterPrototype
Web-based GUI (PowerShell Universal Dashboard) that manages remote devices

## Getting Started

```powershell
# One time setup
    # Download the repository
    # Unblock the zip
    # Extract the PUDAdminCenterPrototype folder to a module path (e.g. $env:USERPROFILE\Documents\WindowsPowerShell\Modules\)
# Or, with PowerShell 5 or later or PowerShellGet:
    Install-Module PUDAdminCenterPrototype

# Import the module.
    Import-Module PUDAdminCenterPrototype    # Alternatively, Import-Module <PathToModuleFolder>

# Get commands in the module
    Get-Command -Module PUDAdminCenterPrototype

# Get help
    Get-Help <PUDAdminCenterPrototype Function> -Full
    Get-Help about_PUDAdminCenterPrototype
```

## Examples

### Scenario 1: Run the WebServer on localhost port 80 from an interactive Windows PowerShell 5.1 Session

```powershell
PS C:\Users\zeroadmin> Get-PUDAdminCenter

Name       Port Running
----       ---- -------
Dashboard0   80    True
```

### Scenario 2: Run the WebServer on localhost port 8888 from an interactive Windows PowerShell 5.1 Session

```powershell
PS C:\Users\zeroadmin> Get-PUDAdminCenter -Port 8888

Name         Port Running
----         ---- -------
Dashboard0   8888    True
```

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

## Notes

* PSGallery: 
