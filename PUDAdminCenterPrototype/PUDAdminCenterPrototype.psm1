[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Get public and private function definition files.
[array]$Public  = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
[array]$Private = Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue
$ThisModule = $(Get-Item $PSCommandPath).BaseName

# Dot source the Private functions
foreach ($import in $Private) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

[System.Collections.Arraylist]$ModulesToInstallAndImport = @()
if (Test-Path "$PSScriptRoot\module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot\module.requirements.psd1"
    $ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
}

if ($ModulesToInstallAndImport.Count -gt 0) {
    # NOTE: If you're not sure if the Required Module is Locally Available or Externally Available,
    # add it the the -RequiredModules string array just to be certain
    $InvModDepSplatParams = @{
        RequiredModules                     = $ModulesToInstallAndImport
        InstallModulesNotAvailableLocally   = $True
        ErrorAction                         = "SilentlyContinue"
        WarningAction                       = "SilentlyContinue"
    }
    $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
}

# Public Functions


<#
    
    .SYNOPSIS
        Gets 'Machine' and 'User' environment variables.
    
    .DESCRIPTION
        Gets 'Machine' and 'User' environment variables.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-EnvironmentVariables {
    Set-StrictMode -Version 5.0
    
    $data = @()
    
    $system = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Machine)
    $user = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::User)
    
    foreach ($h in $system.GetEnumerator()) {
        $obj = [pscustomobject]@{"Name" = $h.Name; "Value" = $h.Value; "Type" = "Machine"}
        $data += $obj
    }
    
    foreach ($h in $user.GetEnumerator()) {
        $obj = [pscustomobject]@{"Name" = $h.Name; "Value" = $h.Value; "Type" = "User"}
        $data += $obj
    }
    
    $data
}


<#
    
    .SYNOPSIS
        Gets the local users.
    
    .DESCRIPTION
        Gets the local users. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-LocalUsers {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $SID
    )
    
    $isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
    # ADSI does NOT support 2016 Nano, meanwhile New-LocalUser, Get-LocalUser, Set-LocalUser do NOT support downlevel
    if ($SID)
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalUser -SID $SID | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpires,
                                                Description,
                                                Enabled,
                                                FullName,
                                                LastLogon,
                                                Name,
                                                ObjectClass,
                                                PasswordChangeableDate,
                                                PasswordExpires,
                                                PasswordLastSet,
                                                PasswordRequired,
                                                @{Name="SID"; Expression={$_.SID.Value}},
                                                UserMayChangePassword;
        }
        else
        {
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' AND SID='$SID'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpirationDate,
                                                                                            Description,
                                                                                            @{Name="Enabled"; Expression={-not $_.Disabled}},
                                                                                            FullName,
                                                                                            LastLogon,
                                                                                            Name,
                                                                                            ObjectClass,
                                                                                            PasswordChangeableDate,
                                                                                            PasswordExpires,
                                                                                            PasswordLastSet,
                                                                                            PasswordRequired,
                                                                                            SID,
                                                                                            @{Name="UserMayChangePassword"; Expression={$_.PasswordChangeable}}
        }
    }
    else
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalUser | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpires,
                                    Description,
                                    Enabled,
                                    FullName,
                                    LastLogon,
                                    Name,
                                    ObjectClass,
                                    PasswordChangeableDate,
                                    PasswordExpires,
                                    PasswordLastSet,
                                    PasswordRequired,
                                    @{Name="SID"; Expression={$_.SID.Value}},
                                    UserMayChangePassword;
        }
        else
        {
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpirationDate,
                                                                                            Description,
                                                                                            @{Name="Enabled"; Expression={-not $_.Disabled}},
                                                                                            FullName,
                                                                                            LastLogon,
                                                                                            Name,
                                                                                            ObjectClass,
                                                                                            PasswordChangeableDate,
                                                                                            PasswordExpires,
                                                                                            PasswordLastSet,
                                                                                            PasswordRequired,
                                                                                            SID,
                                                                                            @{Name="UserMayChangePassword"; Expression={$_.PasswordChangeable}}
        }
    }    
}


<#
    .SYNOPSIS
        This function starts a PowerShell Universal Dashboard (Web-based GUI) instance on the specified port on the
        localhost. The Dashboard features a Network Monitor tool that pings the specified Remote Hosts in your Domain
        every 5 seconds and reports the results to the site.

    .DESCRIPTION
        See .SYNOPSIS

    .PARAMETER Port
        This parameter is OPTIONAL, however, it has a default value of 80.

        This parameter takes an integer between 1 and 32768 that represents the port on the localhost that the site
        will run on.

    .PARAMETER RemoveExistingPUD
        This parameter is OPTIONAL, however, it has a default value of $True.

        This parameter is a switch. If used, all running PowerShell Universal Dashboard instances will be removed
        prior to starting the Network Monitor Dashboard.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> Get-PUDAdminCenter
        
#>
function Get-PUDAdminCenter {
    Param (
        [Parameter(Mandatory=$False)]
        [ValidateRange(1,32768)]
        [int]$Port = 80,

        [Parameter(Mandatory=$False)]
        [switch]$RemoveExistingPUD = $True
    )

    #region >> Prep

    # Remove all current running instances of PUD
    if ($RemoveExistingPUD) {
        Get-UDDashboard | Stop-UDDashboard
    }

    # Remove All Runspaces to Remote Hosts
    Get-PSSession | Remove-PSSession
    $RunspacesToDispose = @(
        Get-Runspace | Where-Object {$_.Type -eq "Remote"}
    )
    if ($RunspacesToDispose.Count -gt 0) {
        foreach ($RSpace in $RunspacesToDispose) {$_.Dispose()}
    }

    # Create the $Pages ArrayList that will be used with 'New-UDDashboard -Pages'
    [System.Collections.ArrayList]$Pages = @()

    # Create a $Cache: and Current Scope variable (ArrayList) containing the names of all of **Dynamic** Pages -
    # i.e. Pages where the URL contains a variable/parameter that is referenced within the Page itself.
    # For example, in this PUDAdminCenter App, the Overview Page (and all other Dynamic Pages in this list) is
    # eventually created via...
    #     New-UDPage -Url "/Overview/:RemoteHost" -Endpoint {param($RemoteHost) ...}
    # ...meaning that if a user were to navigate to http://localhost/Overview/Server01, Overview Page Endpoint scriptblock
    # code that referenced the variable $RemoteHost would contain the string value 'Server01' (unless it is specifcally
    # overriden within the Overview Page Endpoint scriptblock, which is NOT recommended).
    $Cache:DynamicPages = $DynamicPages = @(
        "PSRemotingCreds"
        "ToolSelect"
        "Overview"
        "Certificates"
        "Devices"
        "Events"
        "Files"
        "Firewall"
        "Users And Groups"
        "Network"
        "Processes"
        "Registry"
        "Roles And Features"
        "Scheduled Tasks"
        "Services"
        "Storage"
        "Updates"
    )

    # Make sure we can resolve the $DomainName
    try {
        $DomainName = $(Get-CimInstance Win32_ComputerSystem).Domain
        $ResolveDomainInfo = [System.Net.Dns]::Resolve($DomainName)
    }
    catch {
        Write-Error "Unable to resolve domain '$DomainName'! Halting!"
        $global:FunctionResult = "1"
        return
    }    

    # Create Synchronized Hashtable so that we can pass variables between Pages regardless of scope.
    # This provides benefits above and beyond Universal Dashboard's $Cache: scope for two main reasons:
    #     1) It can be referenced anywhere (not just within an -Endpoint, which is what $Cache: scope is limited to)
    #     2) It allows us to more easily communicate with our own custom Runspace(s) that handle Live (Realtime) Data. For
    #     examples of this, see uses of the 'New-Runspace' function within each of the Dynamic Pages (excluding the
    #     PSRemotingCreds and ToolSelect Pages)
    Remove-Variable -Name PUDRSSyncHT -Scope Global -Force -ErrorAction SilentlyContinue
    $global:PUDRSSyncHT = [hashtable]::Synchronized(@{})

    # Populate $PUDRSSyncHT with information that you will need for your PUD Application. This will vary depending on
    # how your application works, but at the very least, you should:
    #     1) Add a Key that will contain information that will be displayed on your HomePage (for the PUDAdminCenter App,
    #     this is the Value contained within the 'RemoteHostList' Key)
    #     2) If you are planning on using Live (Realtime) Data, ensure you add one or more keys that will contain
    #     Live Data. (For the PUDAdminCenter App, this is the LiveDataRSInfo Key that exists within a hashtable
    #     dedicated to each specific Remote Host)
    # For this PUDAdminCenterPrototype Application, the structure of the $PUDRSSyncHT will look like...
    <#
        @{
            RemoteHostList   = $null
            <RemoteHostInfo> = @{
                NetworkInfo                 = $null
                RelevantNetworkInterfaces   = $null
                ServerInventoryStatic       = $null
                LiveDataRSInfo              = $null
                LiveDataTracker             = @{
                    Current     = $null
                    Previous    = $null
                }
            }
        }
    #>
    # In other words. each Key within the $PUDRSSyncHT Synchronized Hashtable (with the exception of the 'RemoteHostList' key)
    # will represent a Remote Host that we intend to manage. Each RemoteHost key value will be a hashtable containing the keys
    # 'NetworkInfo', 'RelevantNetworkInterfaces', 'ServerInventoryStatic', 'LiveDataRSInfo', and 'LiveDataTracker'. The values
    # for each of these keys is set to $null initially because actions prior to starting the UDDashboard (in the case of the
    # 'RemoteHostList' key) or actions taken within the PUDAdminCenter WebApp itself will set/reset their values as appropriate.

    # Let's populate $PUDRSSyncHT.RemoteHostList with information that will be needed immediately upon navigating to the $HomePage.
    # For this reason, we're gathering the info before we start the UDDashboard. (Note that the below 'GetComputerObjectInLDAP' Private
    # function gets all Computers in Active Directory without using the ActiveDirectory PowerShell Module)
    [System.Collections.ArrayList]$InitialRemoteHostListPrep = $(GetComputerObjectsInLDAP).Name
    if ($PSVersionTable.PSEdition -eq "Core") {
        [System.Collections.ArrayList]$InitialRemoteHostListPrep = $InitialRemoteHostListPrep | foreach {$_ -replace "CN=",""}
    }

    # Filter Out the Remote Hosts that we can't resolve
    [System.Collections.ArrayList]$InitialRemoteHostList = @()

    $null = Clear-DnsClientCache
    foreach ($HName in $InitialRemoteHostListPrep) {
        try {
            $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $HName -ErrorAction Stop

            $null = $InitialRemoteHostList.Add($RemoteHostNetworkInfo)
        }
        catch {
            continue
        }
    }

    $PUDRSSyncHT.Add("RemoteHostList",$InitialRemoteHostList)

    # Add Keys for each of the Remote Hosts in the $InitialRemoteHostList    
    foreach ($RHost in $InitialRemoteHostList) {
        $Key = $RHost.HostName + "Info"
        $Value = @{
            NetworkInfo                 = $RHost
            CredHT                      = $null
            ServerInventoryStatic       = $null
            RelevantNetworkInterfaces   = $null
            LiveDataRSInfo              = $null
            LiveDataTracker             = @{Current = $null; Previous = $null}
        }
        $PUDRSSyncHT.Add($Key,$Value)
    }

    #endregion >> Prep


    #region >> Dynamic Pages

# Add Dynamic Pages Here

    #endregion >> Dynamic Pages


    #region >> Static Pages

# Add Static Pages Here

    #endregion >> Static Pages
    
    # Finalize the Site
    $Theme = New-UDTheme -Name "DefaultEx" -Parent Default -Definition @{
        UDDashboard = @{
            BackgroundColor = "rgb(255,255,255)"
        }
    }
    $MyDashboard = New-UDDashboard -Title "PUD Admin Center" -Pages $Pages -Theme $Theme

    # Start the Site
    Start-UDDashboard -Dashboard $MyDashboard -Port $Port
}


<#
    
    .SYNOPSIS
        Gets a computer's remote desktop settings.
    
    .DESCRIPTION
        Gets a computer's remote desktop settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-RemoteDesktop {
    function Get-DenyTSConnectionsValue {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        
        $exists = Get-ItemProperty -Path $key -Name fDenyTSConnections -ErrorAction SilentlyContinue
        if ($exists)
        {
            $keyValue = $exists.fDenyTSConnections
            return $keyValue -ne 1
        }
    
        Write-Error "The value for key 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' was not found."
    }
    
    function Get-UserAuthenticationValue {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    
        $exists = Get-ItemProperty -Path $key -Name UserAuthentication -ErrorAction SilentlyContinue
        if ($exists)
        {
            $keyValue = $exists.UserAuthentication
            return $keyValue -eq 1
        }
    
        Write-Error "The value for key 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' was not found."
    }
    
    function Get-RemoteAppSetting {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        
        $exists = Get-ItemProperty -Path $key -Name EnableRemoteApp -ErrorAction SilentlyContinue
        if ($exists)
        {
            $keyValue = $exists.EnableRemoteApp
            return $keyValue -eq 1
    
        } else {
            return $false;
        }
    }
    
    $denyValue = Get-DenyTSConnectionsValue;
    $nla = Get-UserAuthenticationValue;
    $remoteApp = Get-RemoteAppSetting;
    
    $result = New-Object -TypeName PSObject
    $result | Add-Member -MemberType NoteProperty -Name "allowRemoteDesktop" $denyValue;
    $result | Add-Member -MemberType NoteProperty -Name "allowRemoteDesktopWithNLA" $nla;
    $result | Add-Member -MemberType NoteProperty -Name "enableRemoteApp" $remoteApp;
    $result
}


<#
    .SYNOPSIS
        Retrieves the inventory data for a server.
    
    .DESCRIPTION
        Retrieves the inventory data for a server.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
#>
function Get-ServerInventory {
    Set-StrictMode -Version 5.0
    
    import-module CimCmdlets
    
    <#
        .SYNOPSIS
        Converts an arbitrary version string into just 'Major.Minor'
        
        .DESCRIPTION
        To make OS version comparisons we only want to compare the major and 
        minor version.  Build number and/os CSD are not interesting.
    #>
    function convertOsVersion([string] $osVersion) {
        try {
            $version = New-Object Version $osVersion -ErrorAction Stop
    
            if ($version -and $version.Major -ne -1 -and $version.Minor -ne -1) {
                $versionString = "{0}.{1}" -f $version.Major, $version.Minor
    
                return New-Object Version $versionString
            }
        }
        catch {
            # The version string is not in the correct format
            return $null
        }
    }
    
    <#
        .SYNOPSIS
        Determines if CredSSP is enabled for the current server or client.
        
        .DESCRIPTION
        Check the registry value for the CredSSP enabled state.
    #>
    function isCredSSPEnabled() {
        $CredSsp = Get-Item WSMan:\localhost\Service\Auth\CredSSP -ErrorAction SilentlyContinue
        if ($CredSSp) {
            return [System.Convert]::ToBoolean($CredSsp.Value)
        }
    
        return $false
    }
    
    <#
        .SYNOPSIS
        Determines if the Hyper-V role is installed for the current server or client.
        
        .DESCRIPTION
        The Hyper-V role is installed when the VMMS service is available.  This is much
        faster then checking Get-WindowsFeature and works on Windows Client SKUs.
    #>
    function isHyperVRoleInstalled() {
        $vmmsService = Get-Service -Name "VMMS" -ErrorAction SilentlyContinue
    
        return $vmmsService -and $vmmsService.Name -eq "VMMS"
    }
    
    <#
        .SYNOPSIS
        Determines if the Hyper-V PowerShell support module is installed for the current server or client.
        
        .DESCRIPTION
        The Hyper-V PowerShell support module is installed when the modules cmdlets are available.  This is much
        faster then checking Get-WindowsFeature and works on Windows Client SKUs.
    #>
    function isHyperVPowerShellSupportInstalled() {
        # quicker way to find the module existence. it doesn't load the module.
        return !!(Get-Module -ListAvailable Hyper-V -ErrorAction SilentlyContinue)
    }
    
    <#
        .SYNOPSIS
        Determines if Windows Management Framework (WMF) 5.0, or higher, is installed for the current server or client.
        
        .DESCRIPTION
        Windows Admin Center requires WMF 5 so check the registey for WMF version on Windows versions that are less than
        Windows Server 2016.
    #>
    function isWMF5Installed([string] $operatingSystemVersion) {
        Set-Variable Server2016 -Option Constant -Value (New-Object Version '10.0')   # And Windows 10 client SKUs
        Set-Variable Server2012 -Option Constant -Value (New-Object Version '6.2')
    
        $version = convertOsVersion $operatingSystemVersion
        if ($version -eq $null) {
            return $false        # Since the OS version string is not properly formatted we cannot know the true installed state.
        }
        
        if ($version -ge $Server2016) {
            # It's okay to assume that 2016 and up comes with WMF 5 or higher installed
            return $true
        } else {
            if ($version -ge $Server2012) {
                # Windows 2012/2012R2 are supported as long as WMF 5 or higher is installed
                $registryKey = 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine'
                $registryKeyValue = Get-ItemProperty -Path $registryKey -Name PowerShellVersion -ErrorAction SilentlyContinue
        
                if ($registryKeyValue -and ($registryKeyValue.PowerShellVersion.Length -ne 0)) {
                    $installedWmfVersion = [Version]$registryKeyValue.PowerShellVersion
        
                    if ($installedWmfVersion -ge [Version]'5.0') {
                        return $true
                    }
                }
            }
        }
        
        return $false
    }
    
    <#
        .SYNOPSIS
        Determines if the current usser is a system administrator of the current server or client.
        
        .DESCRIPTION
        Determines if the current usser is a system administrator of the current server or client.
    #>
    function isUserAnAdministrator() {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    }
    
    <#
        .SYNOPSIS
        Determines if the current server supports Failover Clusters Time Series Database.
        
        .DESCRIPTION
        Use the existance of the cluster cmdlet Get-ClusterPerformanceHistory to determine if TSDB 
        is supported or not.
    #>
    function getClusterPerformanceHistoryCmdLet($failoverClusters) {
        return $failoverClusters.ExportedCommands.ContainsKey("Get-ClusterPerformanceHistory")
    }
    
    <#
        .SYNOPSIS
        Get some basic information about the Failover Cluster that is running on this server.
        
        .DESCRIPTION
        Create a basic inventory of the Failover Cluster that may be running in this server.
    #>
    function getClusterInformation() {
        # JEA code requires to pre-import the module (this is slow on failover cluster environment.)
        Import-Module FailoverClusters -ErrorAction SilentlyContinue
    
        $returnValues = @{}
    
        $returnValues.IsTsdbEnabled = $false
        $returnValues.IsCluster = $false
        $returnValues.ClusterFqdn = $null
    
        $failoverClusters = Get-Module FailoverClusters -ErrorAction SilentlyContinue
        if ($failoverClusters) {
            $returnValues.IsTsdbEnabled = getClusterPerformanceHistoryCmdLet $failoverClusters
        }
    
        $namespace = Get-CimInstance -Namespace root/MSCluster -ClassName __NAMESPACE -ErrorAction SilentlyContinue
        if ($namespace) {
            $cluster = Get-CimInstance -Namespace root/MSCluster -Query "Select fqdn from MSCluster_Cluster" -ErrorAction SilentlyContinue
            if ($cluster) {
                $returnValues.IsCluster = $true
                $returnValues.ClusterFqdn = $cluster.fqdn
            }
        }
        
        return $returnValues
    }
    
    <#
        .SYNOPSIS
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the passed in computer name.
        
        .DESCRIPTION
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the passed in computer name.
    #>
    function getComputerFqdn($computerName) {
        return ([System.Net.Dns]::GetHostEntry($computerName)).HostName
    }
    
    <#
        .SYNOPSIS
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the current server or client.
        
        .DESCRIPTION
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the current server or client.
    #>
    function getHostFqdn($computerSystem) {
        $computerName = $computerSystem.DNSHostName
        if ($computerName -eq $null) {
            $computerName = $computerSystem.Name
        }
    
        return getComputerFqdn $computerName
    }
    
    <#
        .SYNOPSIS
        Are the needed management CIM interfaces available on the current server or client.
        
        .DESCRIPTION
        Check for the presence of the required server management CIM interfaces.
    #>
    function getManagementToolsSupportInformation() {
        $returnValues = @{}
    
        $returnValues.ManagementToolsAvailable = $false
        $returnValues.ServerManagerAvailable = $false
    
        $namespaces = Get-CimInstance -Namespace root/microsoft/windows -ClassName __NAMESPACE -ErrorAction SilentlyContinue
    
        if ($namespaces) {
            $returnValues.ManagementToolsAvailable = ($namespaces | Where-Object { $_.Name -ieq "ManagementTools" }) -ne $null
            $returnValues.ServerManagerAvailable = ($namespaces | Where-Object { $_.Name -ieq "ServerManager" }) -ne $null
        }
    
        return $returnValues
    }
    
    <#
        .SYNOPSIS
        Check the remote app enabled or not.
        
        .DESCRIPTION
        Check the remote app enabled or not.
    #>
    function isRemoteAppEnabled() {
        Set-Variable key -Option Constant -Value "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
        Set-Variable enableRemoteAppPropertyName -Option Constant -Value "EnableRemoteApp"
    
        $registryKeyValue = Get-ItemProperty -Path $key -Name EnableRemoteApp -ErrorAction SilentlyContinue
        
        return $registryKeyValue -and ($registryKeyValue.PSObject.Properties.Name -match $enableRemoteAppPropertyName)
    }
    
    <#
        .SYNOPSIS
        Check the remote app enabled or not.
        
        .DESCRIPTION
        Check the remote app enabled or not.
    #>
    
    <#
        .SYNOPSIS
        Get the Win32_OperatingSystem information
        
        .DESCRIPTION
        Get the Win32_OperatingSystem instance and filter the results to just the required properties.
        This filtering will make the response payload much smaller.
    #>
    function getOperatingSystemInfo() {
        return Get-CimInstance Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object csName, Caption, OperatingSystemSKU, Version, ProductType
    }
    
    <#
        .SYNOPSIS
        Get the Win32_ComputerSystem information
        
        .DESCRIPTION
        Get the Win32_ComputerSystem instance and filter the results to just the required properties.
        This filtering will make the response payload much smaller.
    #>
    function getComputerSystemInfo() {
        return Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | `
            Microsoft.PowerShell.Utility\Select-Object TotalPhysicalMemory, DomainRole, Manufacturer, Model, NumberOfLogicalProcessors, Domain, Workgroup, DNSHostName, Name, PartOfDomain
    }
    
    ###########################################################################
    # main()
    ###########################################################################
    
    $operatingSystem = getOperatingSystemInfo
    $computerSystem = getComputerSystemInfo
    $isAdministrator = isUserAnAdministrator
    $fqdn = getHostFqdn $computerSystem
    $managementToolsInformation = getManagementToolsSupportInformation
    $isWmfInstalled = isWMF5Installed $operatingSystem.Version
    $clusterInformation = getClusterInformation -ErrorAction SilentlyContinue
    $isHyperVPowershellInstalled = isHyperVPowerShellSupportInstalled
    $isHyperVRoleInstalled = isHyperVRoleInstalled
    $isCredSSPEnabled = isCredSSPEnabled
    $isRemoteAppEnabled = isRemoteAppEnabled
    
    $result = New-Object PSObject
    
    $result | Add-Member -MemberType NoteProperty -Name 'IsAdministrator' -Value $isAdministrator
    $result | Add-Member -MemberType NoteProperty -Name 'OperatingSystem' -Value $operatingSystem
    $result | Add-Member -MemberType NoteProperty -Name 'ComputerSystem' -Value $computerSystem
    $result | Add-Member -MemberType NoteProperty -Name 'Fqdn' -Value $fqdn
    $result | Add-Member -MemberType NoteProperty -Name 'IsManagementToolsAvailable' -Value $managementToolsInformation.ManagementToolsAvailable
    $result | Add-Member -MemberType NoteProperty -Name 'IsServerManagerAvailable' -Value $managementToolsInformation.ServerManagerAvailable
    $result | Add-Member -MemberType NoteProperty -Name 'IsCluster' -Value $clusterInformation.IsCluster
    $result | Add-Member -MemberType NoteProperty -Name 'ClusterFqdn' -Value $clusterInformation.ClusterFqdn
    $result | Add-Member -MemberType NoteProperty -Name 'IsWmfInstalled' -Value $isWmfInstalled
    $result | Add-Member -MemberType NoteProperty -Name 'IsTsdbEnabled' -Value $clusterInformation.IsTsdbEnabled
    $result | Add-Member -MemberType NoteProperty -Name 'IsHyperVRoleInstalled' -Value $isHyperVRoleInstalled
    $result | Add-Member -MemberType NoteProperty -Name 'IsHyperVPowershellInstalled' -Value $isHyperVPowershellInstalled
    $result | Add-Member -MemberType NoteProperty -Name 'IsCredSSPEnabled' -Value $isCredSSPEnabled
    $result | Add-Member -MemberType NoteProperty -Name 'isRemoteAppEnabled' -Value $isRemoteAppEnabled
    
    $result
    
}


<#
    
    .SYNOPSIS
        Creates a new environment variable specified by name, type and data.
    
    .DESCRIPTION
        Creates a new environment variable specified by name, type and data.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function New-EnvironmentVariable {
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $name,
    
        [Parameter(Mandatory = $True)]
        [String]
        $value,
    
        [Parameter(Mandatory = $True)]
        [String]
        $type
    )
    
    Set-StrictMode -Version 5.0
    
    If ([Environment]::GetEnvironmentVariable($name, $type) -eq $null) {
        return [Environment]::SetEnvironmentVariable($name, $value, $type)
    }
    Else {
        Write-Error "An environment variable of this name and type already exists."
    }
}


<#
    .SYNOPSIS
        The New-Runspace function creates a Runspace that executes the specified ScriptBlock in the background
        and posts results to a Global Variable called $global:RSSyncHash.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER RunspaceName
        This parameter is MANDATORY.

        This parameter takes a string that represents the name of the new Runspace that you are creating. The name
        is represented as a key in the $global:RSSyncHash variable called: <RunspaceName>Result

    .PARAMETER ScriptBlock
        This parameter is MANDATORY.

        This parameter takes a scriptblock that will be executed in the new Runspace.

    .PARAMETER MirrorCurrentEnv
        This parameter is OPTIONAL, however, it is set to $True by default.

        This parameter is a switch. If used, all variables, functions, and Modules that are loaded in your
        current scope will be forwarded to the new Runspace.

        You can prevent the New-Runspace function from automatically mirroring your current environment by using
        this switch like: -MirrorCurrentEnv:$False 

    .PARAMETER Wait
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the main PowerShell thread will wait for the Runsapce to return
        output before proceeeding.

    .EXAMPLE
        # Open a PowerShell Session, source the function, and -

        PS C:\Users\zeroadmin> $GetProcessResults = Get-Process

        # In the below, Runspace1 refers to your current interactive PowerShell Session...

        PS C:\Users\zeroadmin> Get-Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        1 Runspace1       localhost       Local         Opened        Busy

        # The below will create a 'Runspace Manager Runspace' (if it doesn't already exist)
        # to manage all other new Runspaces created by the New-Runspace function.
        # Additionally, it will create the Runspace that actually runs the -ScriptBlock.
        # The 'Runspace Manager Runspace' disposes of new Runspaces when they're
        # finished running.

        PS C:\Users\zeroadmin> New-RunSpace -RunSpaceName PSIds -ScriptBlock {$($GetProcessResults | Where-Object {$_.Name -eq "powershell"}).Id}

        # The 'Runspace Manager Runspace' persists just in case you create any additional
        # Runspaces, but the Runspace that actually ran the above -ScriptBlock does not.
        # In the below, 'Runspace2' is the 'Runspace Manager Runspace. 

        PS C:\Users\zeroadmin> Get-Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        1 Runspace1       localhost       Local         Opened        Busy
        2 Runspace2       localhost       Local         Opened        Busy

        # You can actively identify (as opposed to infer) the 'Runspace Manager Runspace'
        # by using one of three Global variables created by the New-Runspace function:

        PS C:\Users\zeroadmin> $global:RSJobCleanup.PowerShell.Runspace

        Id Name            ComputerName    Type          State         Availability
        -- ----            ------------    ----          -----         ------------
        2 Runspace2       localhost       Local         Opened        Busy

        # As mentioned above, the New-RunspaceName function creates three Global
        # Variables. They are $global:RSJobs, $global:RSJobCleanup, and
        # $global:RSSyncHash. Your output can be found in $global:RSSyncHash.

        PS C:\Users\zeroadmin> $global:RSSyncHash

        Name                           Value
        ----                           -----
        PSIdsResult                    @{Done=True; Errors=; Output=System.Object[]}
        ProcessedJobRecords            {@{Name=PSIdsHelper; PSInstance=System.Management.Automation.PowerShell; Runspace=System.Management.Automation.Runspaces.Loca...


        PS C:\Users\zeroadmin> $global:RSSyncHash.PSIdsResult

        Done Errors Output
        ---- ------ ------
        True        {1300, 2728, 2960, 3712...}


        PS C:\Users\zeroadmin> $global:RSSyncHash.PSIdsResult.Output
        1300
        2728
        2960
        3712
        4632

        # Important Note: You don't need to worry about passing variables / functions /
        # Modules to the Runspace. Everything in your current session/scope is
        # automatically forwarded by the New-Runspace function:

        PS C:\Users\zeroadmin> function Test-Func {'This is Test-Func output'}
        PS C:\Users\zeroadmin> New-RunSpace -RunSpaceName FuncTest -ScriptBlock {Test-Func}
        PS C:\Users\zeroadmin> $global:RSSyncHash

        Name                           Value
        ----                           -----
        FuncTestResult                 @{Done=True; Errors=; Output=This is Test-Func output}
        PSIdsResult                    @{Done=True; Errors=; Output=System.Object[]}
        ProcessedJobRecords            {@{Name=PSIdsHelper; PSInstance=System.Management.Automation.PowerShell; Runspace=System.Management.Automation.Runspaces.Loca...

        PS C:\Users\zeroadmin> $global:RSSyncHash.FuncTestResult.Output
        This is Test-Func output  
#>
function New-RunSpace {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [string]$RunspaceName,

        [Parameter(Mandatory=$True)]
        [scriptblock]$ScriptBlock,

        [Parameter(Mandatory=$False)]
        [switch]$MirrorCurrentEnv = $True,

        [Parameter(Mandatory=$False)]
        [switch]$Wait
    )

    #region >> Helper Functions

    function NewUniqueString {
        [CmdletBinding()]
        Param(
            [Parameter(Mandatory=$False)]
            [string[]]$ArrayOfStrings,
    
            [Parameter(Mandatory=$True)]
            [string]$PossibleNewUniqueString
        )
    
        if (!$ArrayOfStrings -or $ArrayOfStrings.Count -eq 0 -or ![bool]$($ArrayOfStrings -match "[\w]")) {
            $PossibleNewUniqueString
        }
        else {
            $OriginalString = $PossibleNewUniqueString
            $Iteration = 1
            while ($ArrayOfStrings -contains $PossibleNewUniqueString) {
                $AppendedValue = "_$Iteration"
                $PossibleNewUniqueString = $OriginalString + $AppendedValue
                $Iteration++
            }
    
            $PossibleNewUniqueString
        }
    }

    #endregion >> Helper Functions

    #region >> Runspace Prep

    # Create Global Variable Names that don't conflict with other exisiting Global Variables
    $ExistingGlobalVariables = Get-Variable -Scope Global
    $DesiredGlobalVariables = @("RSSyncHash","RSJobCleanup","RSJobs")
    if ($ExistingGlobalVariables.Name -notcontains 'RSSyncHash') {
        $GlobalRSSyncHashName = NewUniqueString -PossibleNewUniqueString "RSSyncHash" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSSyncHashName = [hashtable]::Synchronized(@{})"
        $globalRSSyncHash = Get-Variable -Name $GlobalRSSyncHashName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSSyncHashName = 'RSSyncHash'

        # Also make sure that $RunSpaceName is a unique key in $global:RSSyncHash
        if ($RSSyncHash.Keys -contains $RunSpaceName) {
            $RSNameOriginal = $RunSpaceName
            $RunSpaceName = NewUniqueString -PossibleNewUniqueString $RunSpaceName -ArrayOfStrings $RSSyncHash.Keys
            if ($RSNameOriginal -ne $RunSpaceName) {
                Write-Warning "The RunspaceName '$RSNameOriginal' already exists. Your new RunspaceName will be '$RunSpaceName'"
            }
        }

        $globalRSSyncHash = $global:RSSyncHash
    }
    if ($ExistingGlobalVariables.Name -notcontains 'RSJobCleanup') {
        $GlobalRSJobCleanupName = NewUniqueString -PossibleNewUniqueString "RSJobCleanup" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSJobCleanupName = [hashtable]::Synchronized(@{})"
        $globalRSJobCleanup = Get-Variable -Name $GlobalRSJobCleanupName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSJobCleanupName = 'RSJobCleanup'
        $globalRSJobCleanup = $global:RSJobCleanup
    }
    if ($ExistingGlobalVariables.Name -notcontains 'RSJobs') {
        $GlobalRSJobsName = NewUniqueString -PossibleNewUniqueString "RSJobs" -ArrayOfStrings $ExistingGlobalVariables.Name
        Invoke-Expression "`$global:$GlobalRSJobsName = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())"
        $globalRSJobs = Get-Variable -Name $GlobalRSJobsName -Scope Global -ValueOnly
    }
    else {
        $GlobalRSJobsName = 'RSJobs'
        $globalRSJobs = $global:RSJobs
    }
    $GlobalVariables = @($GlobalSyncHashName,$GlobalRSJobCleanupName,$GlobalRSJobsName)
    #Write-Host "Global Variable names are: $($GlobalVariables -join ", ")"

    # Prep an empty pscustomobject for the RunspaceNameResult Key in $globalRSSyncHash
    $globalRSSyncHash."$RunspaceName`Result" = [pscustomobject]@{}

    #endregion >> Runspace Prep


    ##### BEGIN Runspace Manager Runspace (A Runspace to Manage All Runspaces) #####

    $globalRSJobCleanup.Flag = $True

    if ($ExistingGlobalVariables.Name -notcontains 'RSJobCleanup') {
        #Write-Host '$global:RSJobCleanup does NOT already exists. Creating New Runspace Manager Runspace...'
        $RunspaceMgrRunspace = [runspacefactory]::CreateRunspace()
        if ($PSVersionTable.PSEdition -ne "Core") {
            $RunspaceMgrRunspace.ApartmentState = "STA"
        }
        $RunspaceMgrRunspace.ThreadOptions = "ReuseThread"
        $RunspaceMgrRunspace.Open()

        # Prepare to Receive the Child Runspace Info to the RunspaceManagerRunspace
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("jobs",$globalRSJobs)
        $RunspaceMgrRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

        $globalRSJobCleanup.PowerShell = [PowerShell]::Create().AddScript({

            ##### BEGIN Runspace Manager Runspace Helper Functions #####

            # Load the functions we packed up
            $FunctionsForSBUse | foreach { Invoke-Expression $_ }

            ##### END Runspace Manager Runspace Helper Functions #####

            # Routine to handle completed Runspaces
            $ProcessedJobRecords = [System.Collections.ArrayList]::new()
            $SyncHash.ProcessedJobRecords = $ProcessedJobRecords
            while ($JobCleanup.Flag) {
                if ($jobs.Count -gt 0) {
                    $Counter = 0
                    foreach($job in $jobs) { 
                        if ($ProcessedJobRecords.Runspace.InstanceId.Guid -notcontains $job.Runspace.InstanceId.Guid) {
                            $job | Export-CliXml "$HOME\job$Counter.xml" -Force
                            $CollectJobRecordPrep = Import-CliXML -Path "$HOME\job$Counter.xml"
                            Remove-Item -Path "$HOME\job$Counter.xml" -Force
                            $null = $ProcessedJobRecords.Add($CollectJobRecordPrep)
                        }

                        if ($job.AsyncHandle.IsCompleted -or $job.AsyncHandle -eq $null) {
                            [void]$job.PSInstance.EndInvoke($job.AsyncHandle)
                            $job.Runspace.Dispose()
                            $job.PSInstance.Dispose()
                            $job.AsyncHandle = $null
                            $job.PSInstance = $null
                        }
                        $Counter++
                    }

                    # Determine if we can have the Runspace Manager Runspace rest
                    $temparray = $jobs.clone()
                    $temparray | Where-Object {
                        $_.AsyncHandle.IsCompleted -or $_.AsyncHandle -eq $null
                    } | foreach {
                        $temparray.remove($_)
                    }

                    <#
                    if ($temparray.Count -eq 0 -or $temparray.AsyncHandle.IsCompleted -notcontains $False) {
                        $JobCleanup.Flag = $False
                    }
                    #>

                    Start-Sleep -Seconds 5

                    # Optional -
                    # For realtime updates to a GUI depending on changes in data within the $globalRSSyncHash, use
                    # a something like the following (replace with $RSSyncHash properties germane to your project)
                    <#
                    if ($RSSyncHash.WPFInfoDatagrid.Items.Count -ne 0 -and $($RSSynchash.IPArray.Count -ne 0 -or $RSSynchash.IPArray -ne $null)) {
                        if ($RSSyncHash.WPFInfoDatagrid.Items.Count -ge $RSSynchash.IPArray.Count) {
                            Update-Window -Control $RSSyncHash.WPFInfoPleaseWaitLabel -Property Visibility -Value "Hidden"
                        }
                    }
                    #>
                }
            } 
        })

        # Start the RunspaceManagerRunspace
        $globalRSJobCleanup.PowerShell.Runspace = $RunspaceMgrRunspace
        $globalRSJobCleanup.Thread = $globalRSJobCleanup.PowerShell.BeginInvoke()
    }

    ##### END Runspace Manager Runspace #####


    ##### BEGIN New Generic Runspace #####

    $GenericRunspace = [runspacefactory]::CreateRunspace()
    if ($PSVersionTable.PSEdition -ne "Core") {
        $GenericRunspace.ApartmentState = "STA"
    }
    $GenericRunspace.ThreadOptions = "ReuseThread"
    $GenericRunspace.Open()

    # Pass the $globalRSSyncHash to the Generic Runspace so it can read/write properties to it and potentially
    # coordinate with other runspaces
    $GenericRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

    # Pass $globalRSJobCleanup and $globalRSJobs to the Generic Runspace so that the Runspace Manager Runspace can manage it
    $GenericRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
    $GenericRunspace.SessionStateProxy.SetVariable("Jobs",$globalRSJobs)
    $GenericRunspace.SessionStateProxy.SetVariable("ScriptBlock",$ScriptBlock)

    # Pass all other notable environment characteristics 
    if ($MirrorCurrentEnv) {
        [System.Collections.ArrayList]$SetEnvStringArray = @()

        $VariablesNotToForward = @('globalRSSyncHash','RSSyncHash','globalRSJobCleanUp','RSJobCleanup',
        'globalRSJobs','RSJobs','ExistingGlobalVariables','DesiredGlobalVariables','$GlobalRSSyncHashName',
        'RSNameOriginal','GlobalRSJobCleanupName','GlobalRSJobsName','GlobalVariables','RunspaceMgrRunspace',
        'GenericRunspace','ScriptBlock')

        $Variables = Get-Variable
        foreach ($VarObj in $Variables) {
            if ($VariablesNotToForward -notcontains $VarObj.Name) {
                try {
                    $GenericRunspace.SessionStateProxy.SetVariable($VarObj.Name,$VarObj.Value)
                }
                catch {
                    Write-Verbose "Skipping `$$($VarObj.Name)..."
                }
            }
        }

        # Set Environment Variables
        $EnvVariables = Get-ChildItem Env:\
        if ($PSBoundParameters['EnvironmentVariablesToForward'] -and $EnvironmentVariablesToForward -notcontains '*') {
            $EnvVariables = foreach ($VarObj in $EnvVariables) {
                if ($EnvironmentVariablesToForward -contains $VarObj.Name) {
                    $VarObj
                }
            }
        }
        $SetEnvVarsPrep = foreach ($VarObj in $EnvVariables) {
            if ([char[]]$VarObj.Name -contains '(' -or [char[]]$VarObj.Name -contains ' ') {
                $EnvStringArr = @(
                    'try {'
                    $('    ${env:' + $VarObj.Name + '} = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            else {
                $EnvStringArr = @(
                    'try {'
                    $('    $env:' + $VarObj.Name + ' = ' + "@'`n$($VarObj.Value)`n'@")
                    '}'
                    'catch {'
                    "    Write-Verbose 'Unable to forward environment variable $($VarObj.Name)'"
                    '}'
                )
            }
            $EnvStringArr -join "`n"
        }
        $SetEnvVarsString = $SetEnvVarsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetEnvVarsString)

        # Set Modules
        $Modules = Get-Module
        if ($PSBoundParameters['ModulesToForward'] -and $ModulesToForward -notcontains '*') {
            $Modules = foreach ($ModObj in $Modules) {
                if ($ModulesToForward -contains $ModObj.Name) {
                    $ModObj
                }
            }
        }

        $ModulesNotToForward = @('MiniLab')

        $SetModulesPrep = foreach ($ModObj in $Modules) {
            if ($ModulesNotToForward -notcontains $ModObj.Name) {
                $ModuleManifestFullPath = $(Get-ChildItem -Path $ModObj.ModuleBase -Recurse -File | Where-Object {
                    $_.Name -eq "$($ModObj.Name).psd1"
                }).FullName

                $ModStringArray = @(
                    '$tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())'
                    "if (![bool]('$($ModObj.Name)' -match '\.WinModule')) {"
                    '    try {'
                    "        Import-Module '$($ModObj.Name)' -NoClobber -ErrorAction Stop 2>`$tempfile"
                    '    }'
                    '    catch {'
                    '        try {'
                    "            Import-Module '$ModuleManifestFullPath' -NoClobber -ErrorAction Stop 2>`$tempfile"
                    '        }'
                    '        catch {'
                    "            Write-Warning 'Unable to Import-Module $($ModObj.Name)'"
                    '        }'
                    '    }'
                    '}'
                    'if (Test-Path $tempfile) {'
                    '    Remove-Item $tempfile -Force'
                    '}'
                )
                $ModStringArray -join "`n"
            }
        }
        $SetModulesString = $SetModulesPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetModulesString)
    
        # Set Functions
        $Functions = Get-ChildItem Function:\ | Where-Object {![System.String]::IsNullOrWhiteSpace($_.Name)}
        if ($PSBoundParameters['FunctionsToForward'] -and $FunctionsToForward -notcontains '*') {
            $Functions = foreach ($FuncObj in $Functions) {
                if ($FunctionsToForward -contains $FuncObj.Name) {
                    $FuncObj
                }
            }
        }
        $SetFunctionsPrep = foreach ($FuncObj in $Functions) {
            $FunctionText = Invoke-Expression $('@(${Function:' + $FuncObj.Name + '}.Ast.Extent.Text)')
            if ($($FunctionText -split "`n").Count -gt 1) {
                if ($($FunctionText -split "`n")[0] -match "^function ") {
                    if ($($FunctionText -split "`n") -match "^'@") {
                        Write-Warning "Unable to forward function $($FuncObj.Name) due to heredoc string: '@"
                    }
                    else {
                        'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                    }
                }
            }
            elseif ($($FunctionText -split "`n").Count -eq 1) {
                if ($FunctionText -match "^function ") {
                    'Invoke-Expression ' + "@'`n$FunctionText`n'@"
                }
            }
        }
        $SetFunctionsString = $SetFunctionsPrep -join "`n"

        $null = $SetEnvStringArray.Add($SetFunctionsString)

        $GenericRunspace.SessionStateProxy.SetVariable("SetEnvStringArray",$SetEnvStringArray)
    }

    $GenericPSInstance = [powershell]::Create()

    # Define the main PowerShell Script that will run the $ScriptBlock
    $null = $GenericPSInstance.AddScript({
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Done -Value $False
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Errors -Value $null
        $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name ErrorsDetailed -Value $null
        $SyncHash."$RunspaceName`Result".Errors = [System.Collections.ArrayList]::new()
        $SyncHash."$RunspaceName`Result".ErrorsDetailed = [System.Collections.ArrayList]::new()
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name ThisRunspace -Value $($(Get-Runspace)[-1])
        [System.Collections.ArrayList]$LiveOutput = @()
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name LiveOutput -Value $LiveOutput
        $SyncHash."$RunspaceName`Result" | Add-Member -Type NoteProperty -Name ScriptBeingRun -Value $ScriptBlock
        

        
        ##### BEGIN Generic Runspace Helper Functions #####

        # Load the environment we packed up
        if ($SetEnvStringArray) {
            foreach ($obj in $SetEnvStringArray) {
                if (![string]::IsNullOrWhiteSpace($obj)) {
                    try {
                        Invoke-Expression $obj
                    }
                    catch {
                        $null = $SyncHash."$RunSpaceName`Result".Errors.Add($_)

                        $ErrMsg = "Problem with:`n$obj`nError Message:`n" + $($_ | Out-String)
                        $null = $SyncHash."$RunSpaceName`Result".ErrorsDetailed.Add($ErrMsg)
                    }
                }
            }
        }

        ##### END Generic Runspace Helper Functions #####

        ##### BEGIN Script To Run #####

        try {
            # NOTE: Depending on the content of the scriptblock, InvokeReturnAsIs() and Invoke-Command can cause
            # the Runspace to hang. Invoke-Expression works all the time.
            #$Result = $ScriptBlock.InvokeReturnAsIs()
            #$Result = Invoke-Command -ScriptBlock $ScriptBlock
            #$SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name SBString -Value $ScriptBlock.ToString()
            Invoke-Expression -Command $ScriptBlock.ToString() -OutVariable Result
            $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Output -Value $Result
        }
        catch {
            $SyncHash."$RunSpaceName`Result" | Add-Member -Type NoteProperty -Name Output -Value $Result

            $null = $SyncHash."$RunSpaceName`Result".Errors.Add($_)

            $ErrMsg = "Problem with:`n$($ScriptBlock.ToString())`nError Message:`n" + $($_ | Out-String)
            $null = $SyncHash."$RunSpaceName`Result".ErrorsDetailed.Add($ErrMsg)
        }

        ##### END Script To Run #####

        $SyncHash."$RunSpaceName`Result".Done = $True
    })

    # Start the Generic Runspace
    $GenericPSInstance.Runspace = $GenericRunspace

    if ($Wait) {
        # The below will make any output of $GenericRunspace available in $Object in current scope
        $Object = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
        $GenericAsyncHandle = $GenericPSInstance.BeginInvoke($Object,$Object)

        $GenericRunspaceInfo = [pscustomobject]@{
            Name            = $RunSpaceName + "Generic"
            PSInstance      = $GenericPSInstance
            Runspace        = $GenericRunspace
            AsyncHandle     = $GenericAsyncHandle
        }
        $null = $globalRSJobs.Add($GenericRunspaceInfo)

        #while ($globalRSSyncHash."$RunSpaceName`Done" -ne $True) {
        while ($GenericAsyncHandle.IsCompleted -ne $True) {
            #Write-Host "Waiting for -ScriptBlock to finish..."
            Start-Sleep -Milliseconds 10
        }

        $globalRSSyncHash."$RunspaceName`Result".Output
        #$Object
    }
    else {
        $HelperRunspace = [runspacefactory]::CreateRunspace()
        if ($PSVersionTable.PSEdition -ne "Core") {
            $HelperRunspace.ApartmentState = "STA"
        }
        $HelperRunspace.ThreadOptions = "ReuseThread"
        $HelperRunspace.Open()

        # Pass the $globalRSSyncHash to the Helper Runspace so it can read/write properties to it and potentially
        # coordinate with other runspaces
        $HelperRunspace.SessionStateProxy.SetVariable("SyncHash",$globalRSSyncHash)

        # Pass $globalRSJobCleanup and $globalRSJobs to the Helper Runspace so that the Runspace Manager Runspace can manage it
        $HelperRunspace.SessionStateProxy.SetVariable("JobCleanup",$globalRSJobCleanup)
        $HelperRunspace.SessionStateProxy.SetVariable("Jobs",$globalRSJobs)

        # Set any other needed variables in the $HelperRunspace
        $HelperRunspace.SessionStateProxy.SetVariable("GenericRunspace",$GenericRunspace)
        $HelperRunspace.SessionStateProxy.SetVariable("GenericPSInstance",$GenericPSInstance)
        $HelperRunspace.SessionStateProxy.SetVariable("RunSpaceName",$RunSpaceName)

        $HelperPSInstance = [powershell]::Create()

        # Define the main PowerShell Script that will run the $ScriptBlock
        $null = $HelperPSInstance.AddScript({
            ##### BEGIN Script To Run #####

            # The below will make any output of $GenericRunspace available in $Object in current scope
            $Object = New-Object 'System.Management.Automation.PSDataCollection[psobject]'
            $GenericAsyncHandle = $GenericPSInstance.BeginInvoke($Object,$Object)

            $GenericRunspaceInfo = [pscustomobject]@{
                Name            = $RunSpaceName + "Generic"
                PSInstance      = $GenericPSInstance
                Runspace        = $GenericRunspace
                AsyncHandle     = $GenericAsyncHandle
            }
            $null = $Jobs.Add($GenericRunspaceInfo)

            #while ($SyncHash."$RunSpaceName`Done" -ne $True) {
            while ($GenericAsyncHandle.IsCompleted -ne $True) {
                #Write-Host "Waiting for -ScriptBlock to finish..."
                Start-Sleep -Milliseconds 10
            }

            ##### END Script To Run #####
        })

        # Start the Helper Runspace
        $HelperPSInstance.Runspace = $HelperRunspace
        $HelperAsyncHandle = $HelperPSInstance.BeginInvoke()

        $HelperRunspaceInfo = [pscustomobject]@{
            Name            = $RunSpaceName + "Helper"
            PSInstance      = $HelperPSInstance
            Runspace        = $HelperRunspace
            AsyncHandle     = $HelperAsyncHandle
        }
        $null = $globalRSJobs.Add($HelperRunspaceInfo)
    }

    ##### END Generic Runspace
}


<#
    .SYNOPSIS
        Removes an environment variable specified by name and type.
    
    .DESCRIPTION
        Removes an environment variable specified by name and type.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Remove-EnvironmentVariable {
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $name,
    
        [Parameter(Mandatory = $True)]
        [String]
        $type
    )
    
    Set-StrictMode -Version 5.0
    
    If ([Environment]::GetEnvironmentVariable($name, $type) -eq $null) {
        Write-Error "An environment variable of this name and type does not exist."
    }
    Else {
        [Environment]::SetEnvironmentVariable($name, $null, $type)
    }
}


<#
    
    .SYNOPSIS
        Sets a computer and/or its domain/workgroup information.
    
    .DESCRIPTION
        Sets a computer and/or its domain/workgroup information.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-ComputerIdentification {
    param(
        [Parameter(Mandatory = $False)]
        [string]
        $ComputerName = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $NewComputerName = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $Domain = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $NewDomain = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $Workgroup = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $UserName = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $Password = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $UserNameNew = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $PasswordNew = '',
    
        [Parameter(Mandatory = $False)]
        [switch]
        $Restart)
    
    function CreateDomainCred($username, $password) {
        $secureString = ConvertTo-SecureString $password -AsPlainText -Force
        $domainCreds = New-Object System.Management.Automation.PSCredential($username, $secureString)
    
        return $domainCreds
    }
    
    function UnjoinDomain($domain) {
        If ($domain) {
            $unjoinCreds = CreateDomainCred $UserName $Password
            Remove-Computer -UnjoinDomainCredential $unjoinCreds -PassThru -Force
        }
    }
    
    If ($NewDomain) {
        $newDomainCreds = $null
        If ($Domain) {
            UnjoinDomain $Domain
            $newDomainCreds = CreateDomainCred $UserNameNew $PasswordNew
        }
        else {
            $newDomainCreds = CreateDomainCred $UserName $Password
        }
    
        If ($NewComputerName) {
            Add-Computer -ComputerName $ComputerName -DomainName $NewDomain -Credential $newDomainCreds -Force -PassThru -NewName $NewComputerName -Restart:$Restart
        }
        Else {
            Add-Computer -ComputerName $ComputerName -DomainName $NewDomain -Credential $newDomainCreds -Force -PassThru -Restart:$Restart
        }
    }
    ElseIf ($Workgroup) {
        UnjoinDomain $Domain
    
        If ($NewComputerName) {
            Add-Computer -WorkGroupName $Workgroup -Force -PassThru -NewName $NewComputerName -Restart:$Restart
        }
        Else {
            Add-Computer -WorkGroupName $Workgroup -Force -PassThru -Restart:$Restart
        }
    }
    ElseIf ($NewComputerName) {
        If ($Domain) {
            $domainCreds = CreateDomainCred $UserName $Password
            Rename-Computer -NewName $NewComputerName -DomainCredential $domainCreds -Force -PassThru -Restart:$Restart
        }
        Else {
            Rename-Computer -NewName $NewComputerName -Force -PassThru -Restart:$Restart
        }
    }
}


<#
    
    .SYNOPSIS
        Updates or renames an environment variable specified by name, type, data and previous data.
    
    .DESCRIPTION
        Updates or Renames an environment variable specified by name, type, data and previrous data.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-EnvironmentVariable {
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $oldName,
    
        [Parameter(Mandatory = $True)]
        [String]
        $newName,
    
        [Parameter(Mandatory = $True)]
        [String]
        $value,
    
        [Parameter(Mandatory = $True)]
        [String]
        $type
    )
    
    Set-StrictMode -Version 5.0
    
    $nameChange = $false
    if ($newName -ne $oldName) {
        $nameChange = $true
    }
    
    If (-not [Environment]::GetEnvironmentVariable($oldName, $type)) {
        @{ Status = "currentMissing" }
        return
    }
    
    If ($nameChange -and [Environment]::GetEnvironmentVariable($newName, $type)) {
        @{ Status = "targetConflict" }
        return
    }
    
    If ($nameChange) {
        [Environment]::SetEnvironmentVariable($oldName, $null, $type)
        [Environment]::SetEnvironmentVariable($newName, $value, $type)
        @{ Status = "success" }
    }
    Else {
        [Environment]::SetEnvironmentVariable($newName, $value, $type)
        @{ Status = "success" }
    }    
}


<#
    
    .SYNOPSIS
        Sets a computer's remote desktop settings.
    
    .DESCRIPTION
        Sets a computer's remote desktop settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-RemoteDesktop {
    param(
        [Parameter(Mandatory = $False)]
        [boolean]
        $AllowRemoteDesktop,
        
        [Parameter(Mandatory = $False)]
        [boolean]
        $AllowRemoteDesktopWithNLA,
        
        [Parameter(Mandatory=$False)]
        [boolean]
        $EnableRemoteApp)
    
    Import-Module NetSecurity
    Import-Module Microsoft.PowerShell.Management
        
    $regKey1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $regKey2 = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    
    $keyProperty1 = "fDenyTSConnections"
    $keyProperty2 = "UserAuthentication"
    $keyProperty3 = "EnableRemoteApp"
    
    $keyPropertyValue1 = $(if ($AllowRemoteDesktop -eq $True) { 0 } else { 1 })
    $keyPropertyValue2 = $(if ($AllowRemoteDesktopWithNLA -eq $True) { 1 } else { 0 })
    $keyPropertyValue3 = $(if ($EnableRemoteApp -eq $True) { 1 } else { 0 })
    
    if (!(Test-Path $regKey1)) {
        New-Item -Path $regKey1 -Force | Out-Null
    }
    
    New-ItemProperty -Path $regKey1 -Name $keyProperty1 -Value $keyPropertyValue1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $regKey1 -Name $keyProperty3 -Value $keyPropertyValue3 -PropertyType DWORD -Force | Out-Null
    
    if (!(Test-Path $regKey2)) {
        New-Item -Path $regKey2 -Force | Out-Null
    }
    
    New-ItemProperty -Path $regKey2 -Name $keyProperty2 -Value $keyPropertyValue2 -PropertyType DWORD -Force | Out-Null
    
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
}


<#
    
    .SYNOPSIS
        Start Disk Performance monitoring.
    
    .DESCRIPTION
        Start Disk Performance monitoring.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Start-DiskPerf {
    # Update the registry key at HKLM:SYSTEM\\CurrentControlSet\\Services\\Partmgr
    #   EnableCounterForIoctl = DWORD 3
    & diskperf -Y
}


<#
    
    .SYNOPSIS
        Stop Disk Performance monitoring.
    
    .DESCRIPTION
        Stop Disk Performance monitoring.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Stop-DiskPerf {
    # Update the registry key at HKLM:SYSTEM\\CurrentControlSet\\Services\\Partmgr
    #   EnableCounterForIoctl = DWORD 1
    & diskperf -N
}



if (![bool]$(Get-Module UniversalDashboard.Community)) {
    try {
        Import-Module UniversalDashboard.Community -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -match "\.Net Framework") {
            try {
                Write-Host "Installing .Net Framework 4.7.2 ... This will take a little while, and you will need to restart afterwards..."
                $InstallDotNet47Result = Install-Program -ProgramName dotnet4.7.2 -ErrorAction Stop
            }
            catch {
                Write-Error $_
                Write-Warning ".Net Framework 4.7.2 was NOT installed successfully."
                Write-Warning "The $ThisModule Module will NOT be loaded. Please run`n    Remove-Module $ThisModule"
                $global:FunctionResult = "1"
                return
            }

            Write-Warning ".Net Framework 4.7.2 was installed successfully, however *****you must restart $env:ComputerName***** before using the $ThisModule Module! Halting!"
            return
        }
        else {
            Write-Error $_
            Write-Warning "The $ThisModule Module was NOT loaded successfully! Please run:`n    Remove-Module $ThisModule"
            $global:FunctionResult = "1"
            return
        }
    }
}

[System.Collections.ArrayList]$script:FunctionsForSBUse = @(
    ${Function:AddWinRMTrustedHost}.Ast.Extent.Text
    ${Function:AddWinRMTrustLocalHost}.Ast.Extent.Text
    ${Function:EnableWinRMViaRPC}.Ast.Extent.Text
    ${Function:GetComputerObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetDomainController}.Ast.Extent.Text
    ${Function:GetElevation}.Ast.Extent.Text
    ${Function:GetGroupObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetModuleDependencies}.Ast.Extent.Text
    ${Function:GetNativePath}.Ast.Extent.Text
    ${Function:GetUserObjectsInLDAP}.Ast.Extent.Text
    ${Function:GetWorkingCredentials}.Ast.Extent.Text
    ${Function:InvokeModuleDependencies}.Ast.Extent.Text
    ${Function:InvokePSCompatibility}.Ast.Extent.Text
    ${Function:ManualPSGalleryModuleInstall}.Ast.Extent.Text
    ${Function:NewUniqueString}.Ast.Extent.Text
    ${Function:ResolveHost}.Ast.Extent.Text
    ${Function:TestIsValidIPAddress}.Ast.Extent.Text
    ${Function:TestLDAP}.Ast.Extent.Text
    ${Function:TestPort}.Ast.Extent.Text
    ${Function:UnzipFile}.Ast.Extent.Text
    ${Function:Get-EnvironmentVariables}.Ast.Extent.Text
    ${Function:Get-LocalUsers}.Ast.Extent.Text
    ${Function:Get-PUDAdminCenter}.Ast.Extent.Text
    ${Function:Get-RemoteDesktop}.Ast.Extent.Text
    ${Function:Get-ServerInventory}.Ast.Extent.Text
    ${Function:New-EnvironmentVariable}.Ast.Extent.Text
    ${Function:New-Runspace}.Ast.Extent.Text
    ${Function:Remove-EnvironmentVariable}.Ast.Extent.Text
    ${Function:Set-ComputerIdentification}.Ast.Extent.Text
    ${Function:Set-EnvironmentVariable}.Ast.Extent.Text
    ${Function:Set-RemoteDesktop}.Ast.Extent.Text
    ${Function:Start-DiskPerf}.Ast.Extent.Text
    ${Function:Stop-DiskPerf}.Ast.Extent.Text
)

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUayBoQgxBvt92zkDFWiI3yagA
# ddugggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOwMF6uuDhf10DtN
# XinefBP7z7VNMA0GCSqGSIb3DQEBAQUABIIBAHUegVHedt+VRakipe7bZP4s4nFd
# fZNABD7IDbw1G3O4l/nlI3/YhhYtGGMYI3oGJHzLzkMEUkb94rmEbHS9MmchAXZC
# hPBunEPSWu6odWG14Xfaxcim1vXqUmQ5tKfvgBIEkdBUqzv7GAUYFOelgZooAkb4
# Luyc7BU5Sk+89quQF2tB1c6A2xeQJw2ZNLjwfzp3NBhrhzpJUfuP/LcughK73mNl
# mLbT0hquknB43gzRb3Qu9k6a+vDQmjg7qkgr8ITG0editaPLRvdYK8DBpbl67H2E
# d4FlMsUCLYdiXRBl0fNCQ6+vMrit0OP9jI5vS+7W0cVUl2LLNj5cNTeaPRU=
# SIG # End signature block
