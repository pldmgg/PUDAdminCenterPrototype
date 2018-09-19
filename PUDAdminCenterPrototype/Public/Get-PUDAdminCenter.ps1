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

    # Define all of this Module's functions (both Public and Private) as an array of strings so that we can easily load them in different contexts/scopes
    $ThisModuleFunctionsStringArray =  $(Get-Module PUDAdminCenterPrototype).Invoke({$FunctionsForSBUse})

    # Create the $Pages ArrayList that will be used with 'New-UDDashboard -Pages'
    [System.Collections.ArrayList]$Pages = @()

    # Current Scope variable (ArrayList) containing the names of all of **Dynamic** Pages -
    # i.e. Pages where the URL contains a variable/parameter that is referenced within the Page itself.
    # For example, in this PUDAdminCenter App, the Overview Page (and all other Dynamic Pages in this list) is
    # eventually created via...
    #     New-UDPage -Url "/Overview/:RemoteHost" -Endpoint {param($RemoteHost) ...}
    # ...meaning that if a user were to navigate to http://localhost/Overview/Server01, Overview Page Endpoint scriptblock
    # code that referenced the variable $RemoteHost would contain the string value 'Server01' (unless it is specifcally
    # overriden within the Overview Page Endpoint scriptblock, which is NOT recommended).
    $DynamicPages = @(
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
                <DynamicPage>               = @{
                    <StaticInfoKey>     = $null
                    LiveDataRSInfo      = $null
                    LiveDataTracker     = @{
                        Current     = $null
                        Previous    = $null
                    }
                }
            }
        }
    #>
    # In other words. each Key within the $PUDRSSyncHT Synchronized Hashtable (with the exception of the 'RemoteHostList' key)
    # will represent a Remote Host that we intend to manage. Each RemoteHost key value will be a hashtable containing the key
    # 'NetworkInfo', as well as keys that rperesent relevant Dynamic Pages ('Overview','Certificates',etc). Each Dynamic Page
    # key value will be a hashtable containing one or more keys with value(s) representing static info that is queried at the time
    # the page loads as well as the keys 'LiveDataRSInfo', and 'LiveDataTracker'. Some key values are initially set to $null because
    # actions taken either prior to starting the UDDashboard or actions taken within the PUDAdminCenter WebApp itself on different
    # pages will set/reset their values as appropriate.

    # Let's populate $PUDRSSyncHT.RemoteHostList with information that will be needed immediately upon navigating to the $HomePage.
    # For this reason, we're gathering the info before we start the UDDashboard. (Note that the below 'GetComputerObjectInLDAP' Private
    # function gets all Computers in Active Directory without using the ActiveDirectory PowerShell Module)
    [System.Collections.ArrayList]$InitialRemoteHostListPrep = $(GetComputerObjectsInLDAP).Name
    # Let's just get 20 of them initially. We want *something* on the HomePage but we don't want hundreds/thousands of entries. We want
    # the user to specify individual/range of hosts/devices that they want to manage.
    $InitialRemoteHostListPrep = $InitialRemoteHostListPrep[0..20]
    if ($PSVersionTable.PSEdition -eq "Core") {
        [System.Collections.ArrayList]$InitialRemoteHostListPrep = $InitialRemoteHostListPrep | foreach {$_ -replace "CN=",""}
    }

    # Filter Out the Remote Hosts that we can't resolve
    [System.Collections.ArrayList]$InitialRemoteHostList = @()

    $null = Clear-DnsClientCache
    foreach ($HName in $InitialRemoteHostListPrep) {
        try {
            $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $HName -ErrorAction Stop

            if ($InitialRemoteHostList.FQDN -notcontains $RemoteHostNetworkInfo.FQDN) {
                $null = $InitialRemoteHostList.Add($RemoteHostNetworkInfo)
            }
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
        foreach ($DynPage in $($DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
            $DynPageHT = @{
                LiveDataRSInfo      = $null
                LiveDataTracker     = @{Current = $null; Previous = $null}
            }
            $Value.Add($($DynPage -replace "[\s]",""),$DynPageHT)
        }
        $PUDRSSyncHT.Add($Key,$Value)
    }

    # Install nmap
    if ($(Get-Module -ListAvailable).Name -notcontains "ProgramManagement") {Install-Module ProgramManagement}
    if ($(Get-Module).Name -notcontains "ProgramManagement") {Import-Module ProgramManagement}
    if (!$(Get-Command nmap -ErrorAction SilentlyContinue)) {
        try {
            Write-Host "Installing 'nmap'. This could take up to 10 minutes..." -ForegroundColor Yellow
            $InstallnmapResult = Install-Program -ProgramName nmap -CommandName nmap
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }
    if (!$(Get-Command nmap -ErrorAction SilentlyContinue)) {
        Write-Error "Unable to find the command 'nmap'! Halting!"
        $global:FunctionResult = "1"
        return
    }
    $NmapParentDir = $(Get-Command nmap).Source | Split-Path -Parent
    [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ';' | Where-Object {![System.String]::IsNullOrWhiteSpace($_)}
    if ($CurrentEnvPathArray -notcontains $NmapParentDir) {
        $CurrentEnvPathArray.Insert(0,$NmapParentDir)
        $env:Path = $CurrentEnvPathArray -join ';'
    }
    $SystemPathInRegistry = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment'
    $CurrentSystemPath = $(Get-ItemProperty -Path $SystemPathInRegistry -Name PATH).Path
    [System.Collections.Arraylist][array]$CurrentSystemPathArray = $CurrentSystemPath -split ";" | Where-Object {![System.String]::IsNullOrWhiteSpace($_)}
    if ($CurrentSystemPathArray -notcontains $NmapParentDir) {
        $CurrentSystemPathArray.Insert(0,$NmapParentDir)
        $UpdatedSystemPath = $CurrentSystemPathArray -join ';'
        Set-ItemProperty -Path $SystemPathInRegistry -Name PATH -Value $UpdatedSystemPath
    }
    
    

    #endregion >> Prep


    #region >> Dynamic Pages

    $CertificatesPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:CertificatesPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:CertificatesPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $GetCertificateOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-CertificateOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetCertificatesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Certificates" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetCertificateOverviewFunc
                Invoke-Expression $using:GetCertificatesFunc
                
                $CertificateSummary = Get-CertificateOverview -channel "Microsoft-Windows-CertificateServicesClient-Lifecycle-System*"
                $AllCertificates = Get-Certificates
    
                [pscustomobject]@{
                    CertificateSummary          = $CertificateSummary
                    AllCertificates             = [pscustomobject]$AllCertificates
                }
            }
            $Session:CertSummaryStatic = $StaticInfo.CertificateSummary
            $Session:AllCertsStatic = $StaticInfo.AllCertificates
            if ($PUDRSSyncHT."$RemoteHost`Info".Certificates.Keys -notcontains "CertSummary") {
                $PUDRSSyncHT."$RemoteHost`Info".Certificates.Add("CertSummary",$Session:CertSummaryStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Certificates.CertSummary = $Session:CertSummaryStatic
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Certificates.Keys -notcontains "AllCerts") {
                $PUDRSSyncHT."$RemoteHost`Info".Certificates.Add("AllCerts",$Session:AllCertsStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Certificates.AllCerts = $Session:AllCertsStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Certificates (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetCertificateOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-CertificateOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetCertificatesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Certificates" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetCertificateOverviewFunc,$GetCertificatesFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Certificates$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Certificates$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllCerts = Get-Certificates}
                            }
    
                            # Operations that you want to run once every second go here
                            @{CertSummary = Get-CertificateOverview -channel "Microsoft-Windows-CertificateServicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Certificates$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo equal to
                # $RSSyncHash."Certificates$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo = $RSSyncHash."Certificates$RemoteHost`LiveDataResult"
            }
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            $AllCertsProperties = @("CertificateName","FriendlyName","Subject","Issuer","Path","Status","PrivateKey","PublicKey","NotBefore","NotAfter")
            $AllCertsUDTableSplatParams = @{
                Headers         = $AllCertsProperties
                Properties      = $AllCertsProperties
                PageSize        = 5
            }
            New-UDGrid @AllCertsUDTableSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $AllCertsGridData = $PUDRSSyncHT."$RemoteHost`Info".Certificates.AllCerts | Out-UDGridData
    
                $AllCertsGridData
            }
    
            # Live Data Element Example
            $CertSummaryProperties = @("allCount","expiredCount","nearExpiredCount","eventCount")
            $CertSummaryUDTableSplatParams = @{
                Headers         = $CertSummaryProperties
                AutoRefresh     = $True 
                RefreshInterval = 5
            }
            New-UDTable @CertSummaryUDTableSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $CertSummaryLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo.LiveOutput.Count
                if ($CertSummaryLiveOutputCount -gt 0) {
                    $ArrayOfCertSummaryEntries = @(
                        $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataTracker.Previous.CertSummary
                    ) | Where-Object {$_ -ne $null}
                    if ($ArrayOfCertSummaryEntries.Count -gt 0) {
                        $CertSummaryTableData = $ArrayOfCertSummaryEntries[-1] | Out-UDTableData -Property $CertSummaryProperties
                    }
                }
                if (!$CertSummaryTableData) {
                    $CertSummaryTableData = [pscustomobject]@{
                        allCount            = "Collecting Info"
                        expiredCount        = "Collecting Info"
                        nearExpiredcount    = "Collecting Info"
                        eventCount          = "Collecting Info"
                    } | Out-UDTableData -Property $CertSummaryProperties
                }
    
                $CertSummaryTableData
            }
    
            # Remove the Loading  Indicator
            $null = $Session:CertificatesPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Certificates/:RemoteHost" -Endpoint $CertificatesPageContent
    $null = $Pages.Add($Page)
    
    $DevicesPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:DevicesPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:DevicesPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $GetCimPnPFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-CimPnpEntity" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetCimPnPFunc
                
                $DevicesInfo = Get-CimPnpEntity
    
                [pscustomobject]@{
                    AllDevices  = $DevicesInfo
                }
            }
            $Session:AllDevicesStatic = $StaticInfo.AllDevices
            if ($PUDRSSyncHT."$RemoteHost`Info".Devices.Keys -notcontains "AllDevices") {
                $PUDRSSyncHT."$RemoteHost`Info".Devices.Add("AllDevices",$Session:AllDevicesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Devices.AllDevices = $Session:AllDevicesStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Devices (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            <#
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetCimPnPFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-CimPnpEntity" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetCimPnPFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Devices$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Devices$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllDevices = Get-CimPnpEntity}
                            }
    
                            # Operations that you want to run once every second go here
                            #@{AllDevices = Get-CimPnpEntity}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Devices$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo equal to
                # $RSSyncHash."Devices$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Devices.LiveDataRSInfo = $RSSyncHash."Devices$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            $AllDevicesProperties = @("Name","Status","InstallDate","PNPClass","PNPDeviceID","Service","Manufacturer","Present")
            $AllDevicesUDTableSplatParams = @{
                Headers         = $AllDevicesProperties
                Properties      = $AllDevicesProperties
                PageSize        = 5
            }
            New-UDGrid @AllDevicesUDTableSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $AllDevicesGridData = $PUDRSSyncHT."$RemoteHost`Info".Devices.AllDevices | Out-UDGridData
    
                $AllDevicesGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:DevicesPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Devices/:RemoteHost" -Endpoint $DevicesPageContent
    $null = $Pages.Add($Page)
    
    #region >> Disconnected Page
    
    $DisconnectedPageContent = {
        param($RemoteHost)
    
        # Add the SyncHash to the Page so that we can pass output to other pages
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        $ConnectionStatusTableProperties = @("RemoteHost", "Status")
    
        New-UDRow -Columns {
            New-UDColumn -Size 4 -Content {
                New-UDHeading -Text ""
            }
            New-UDColumn -Size 4 -Content {
                New-UDTable -Headers $ConnectionStatusTableProperties -AutoRefresh -Endpoint {
                    [PSCustomObject]@{
                        RemoteHost      = $RemoteHost.ToUpper()
                        Status          = "Disconnected"
                    } | Out-UDTableData -Property @("RemoteHost", "Status")
                }
            }
            New-UDColumn -Size 4 -Content {
                New-UDHeading -Text ""
            }
        }
    
        New-UDRow -Columns {
            New-UDColumn -Size 5 -Content {
                New-UDHeading -Text ""
            }
            New-UDColumn -Size 2 -Content {
                New-UDLink -Text "|| Return Home ||" -Url "/Home"
            }
            New-UDColumn -Size 5 -Content {
                New-UDHeading -Text ""
            }
        }
    
        New-UDRow -Columns {
            New-UDColumn -Size 12 -Content {
                # Grid below UDTable
                $ResultProperties = @("HostName","FQDN","IPAddress","PingStatus","WSMan","WSManPorts","SSH","DateTime","ManageLink")
    
                $RHost = $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo
    
                $GridEndpoint = {
                    $GridData = @{}
                    $GridData.Add("HostName",$RHost.HostName.ToUpper())
                    $GridData.Add("FQDN",$RHost.FQDN)
                    $GridData.Add("IPAddress",$RHost.IPAddressList[0])
    
                    # Check Ping
                    try {
                        $PingResult =  [System.Net.NetworkInformation.Ping]::new().Send(
                            $RHost.IPAddressList[0],1000
                        ) | Select-Object -Property Address,Status,RoundtripTime -ExcludeProperty PSComputerName,PSShowComputerName,RunspaceId
    
                        $PingStatus = if ($PingResult.Status.ToString() -eq "Success") {"Available"} else {"Unavailable"}
                        $GridData.Add("PingStatus",$PingStatus)
                    }
                    catch {
                        $GridData.Add("PingStatus","Unavailable")
                    }
    
                    # Check WSMan Ports
                    try {
                        $WSMan5985Url = "http://$($RHost.IPAddressList[0])`:5985/wsman"
                        $WSMan5986Url = "http://$($RHost.IPAddressList[0])`:5986/wsman"
                        $WSManUrls = @($WSMan5985Url,$WSMan5986Url)
                        foreach ($WSManUrl in $WSManUrls) {
                            $Request = [System.Net.WebRequest]::Create($WSManUrl)
                            $Request.Timeout = 1000
                            try {
                                [System.Net.WebResponse]$Response = $Request.GetResponse()
                            }
                            catch {
                                if ($_.Exception.Message -match "The remote server returned an error: \(405\) Method Not Allowed") {
                                    if ($WSManUrl -match "5985") {
                                        $WSMan5985Available = $True
                                    }
                                    else {
                                        $WSMan5986Available = $True
                                    }
                                }
                                elseif ($_.Exception.Message -match "The operation has timed out") {
                                    if ($WSManUrl -match "5985") {
                                        $WSMan5985Available = $False
                                    }
                                    else {
                                        $WSMan5986Available = $False
                                    }
                                }
                                else {
                                    if ($WSManUrl -match "5985") {
                                        $WSMan5985Available = $False
                                    }
                                    else {
                                        $WSMan5986Available = $False
                                    }
                                }
                            }
                        }
    
                        if ($WSMan5985Available -or $WSMan5986Available) {
                            $GridData.Add("WSMan","Available")
    
                            [System.Collections.ArrayList]$WSManPorts = @()
                            if ($WSMan5985Available) {
                                $null = $WSManPorts.Add("5985")
                            }
                            if ($WSMan5986Available) {
                                $null = $WSManPorts.Add("5986")
                            }
    
                            $WSManPortsString = $WSManPorts -join ', '
                            $GridData.Add("WSManPorts",$WSManPortsString)
                        }
                    }
                    catch {
                        $GridData.Add("WSMan","Unavailable")
                    }
    
                    # Check SSH
                    try {
                        $TestSSHResult = TestPort -HostName $RHost.IPAddressList[0] -Port 22
    
                        if ($TestSSHResult.Open) {
                            $GridData.Add("SSH","Available")
                        }
                        else {
                            $GridData.Add("SSH","Unavailable")
                        }
                    }
                    catch {
                        $GridData.Add("SSH","Unavailable")
                    }
    
                    $GridData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                    if ($GridData.WSMan -eq "Available" -or $GridData.SSH -eq "Available") {
                        if ($PUDRSSyncHT."$($RHost.HostName)`Info".PSRemotingCreds -ne $null) {
                            $GridData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/ToolSelect/$($RHost.HostName)"))
                        }
                        else {
                            $GridData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/PSRemotingCreds/$($RHost.HostName)"))
                        }
                    }
                    else {
                        $GridData.Add("ManageLink","Unavailable")
                    }
                    
                    [pscustomobject]$GridData | Out-UDGridData
                }
    
                $NewUdGridSplatParams = @{
                    Headers         = $ResultProperties 
                    NoPaging        = $True
                    Properties      = $ResultProperties
                    AutoRefresh     = $True
                    RefreshInterval = 5
                    Endpoint        = $GridEndpoint
                }
                New-UdGrid @NewUdGridSplatParams
            }
        }
    }
    $Page = New-UDPage -Url "/Disconnected/:RemoteHost" -Endpoint $DisconnectedPageContent
    $null = $Pages.Add($Page)
    # We need this page as a string for later on. For some reason, we can't use this same ScriptBlock directly on other Pages
    $DisconnectedPageContentString = $DisconnectedPageContent.ToString()
    
    #endregion >> Disconnected Page
    
    $EventsPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:EventsPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:EventsPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $GetEventLogSummaryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-EventLogSummary" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetEventLogSummaryFunc
                
                $EventLogChannelSummaries = Get-EventLogSummary -channel *
    
                [pscustomobject]@{
                    EventLogChannelSummaries    = $EventLogChannelSummaries
                }
            }
            $Session:EventLogChannelSummariesStatic = $StaticInfo.EventLogChannelSummaries
            if ($PUDRSSyncHT."$RemoteHost`Info".Events.Keys -notcontains "EventLogChannelSummaries") {
                $PUDRSSyncHT."$RemoteHost`Info".Events.Add("EventLogChannelSummaries",$Session:EventLogChannelSummariesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Events.EventLogChannelSummaries = $Session:EventLogChannelSummariesStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Events (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetEventLogSummaryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-EventLogSummary" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetEventLogSummaryFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Events$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Events$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 100) {
                            $LiveOutput.RemoveRange(0,90)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{EventLogChannelSummaries = Get-EventLogSummary -channel *}
                            }
    
                            # Operations that you want to run once every second go here
                            @{EventLogChannelSummaries = Get-EventLogSummary -channel *}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Events$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo equal to
                # $RSSyncHash."Events$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Events.LiveDataRSInfo = $RSSyncHash."Events$RemoteHost`LiveDataResult"
            }
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            $EventLogChannelSummaryProperties = @("LogName","LogMode","MaximumSizeInBytes","RecordCount")
            $EventLogChannelSummaryUDTableSplatParams = @{
                Headers         = $EventLogChannelSummaryProperties
                Properties      = $EventLogChannelSummaryProperties
                PageSize        = 10
            }
            New-UDGrid @EventLogChannelSummaryUDTableSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $EventLogChannelSummaryGridData = $PUDRSSyncHT."$RemoteHost`Info".Events.EventLogChannelSummaries | Out-UDGridData
    
                $EventLogChannelSummaryGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:EventsPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Events/:RemoteHost" -Endpoint $EventsPageContent
    $null = $Pages.Add($Page)
    
    $FilesPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:FilesPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:FilesPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            if (!$Session:RootDirChildItems) {
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    $RootDirChildItems = Get-ChildItem -Path "$env:SystemDrive\"
                    $RootDirItem = Get-Item -Path "$env:SystemDrive\"
    
                    [pscustomobject]@{
                        RootDirItem             = $RootDirItem
                        RootDirChildItems      = $RootDirChildItems
                    }
                }
                $Session:RootDirChildItems = $StaticInfo.RootDirChildItems
                $Session:RootDirItem = $StaticInfo.RootDirItem
                if ($PUDRSSyncHT."$RemoteHost`Info".Files.Keys -notcontains "RootDirChildItems") {
                    $PUDRSSyncHT."$RemoteHost`Info".Files.Add("RootDirChildItems",$StaticInfo.RootDirChildItems)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirChildItems = $StaticInfo.RootDirChildItems
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Files.Keys -notcontains "RootDirItem") {
                    $PUDRSSyncHT."$RemoteHost`Info".Files.Add("RootDirItem",$StaticInfo.RootDirItem)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirItem = $StaticInfo.RootDirItem
                }
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Files (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            <#
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
    
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Files$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Files$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{RootFiles = Get-ChildItem -Path "$env:SystemDrive\" }
                            }
    
                            # Operations that you want to run once every second go here
                            @{RootFiles = Get-ChildItem -Path "$env:SystemDrive\"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Files$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo equal to
                # $RSSyncHash."Files$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Files.LiveDataRSInfo = $RSSyncHash."Files$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
    
            # Static Data Element Example
    
            New-UDCollapsible -Items {
                New-UDCollapsibleItem -Title "File System" -Icon laptop -Active -Endpoint {
                    <#
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 3 -Endpoint {}
                        New-UDColumn -Size 6 -Endpoint {
                            New-UDTextbox -Label "Full Path to Directory to Explore" -Id "NewRootDirTB" -Placeholder "Directory to Explore"
                            New-UDButton -Text "Explore" -Id "Button" -OnClick {
                                $NewRootDirTextBox = Get-UDElement -Id "NewRootDirTB"
                                $FullPathToExplore = $NewRootDirTextBox.Attributes['value']
    
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    $RootDirChildItems = Get-ChildItem -Path $using:FullPathToExplore
                        
                                    [pscustomobject]@{
                                        RootDirChildItems      = $RootDirChildItems
                                    }
                                }
                                $Session:RootDirChildItems = $NewPathInfo.RootDirChildItems
                                $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirChildItems = $Session:RootDirChildItems
                                Sync-UDElement -Id "RootDirChildItemsUDGrid"
                            }
                        }
                        New-UDColumn -Size 3 -Endpoint {}
                    }
                    #>
    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 3 -Endpoint {}
                        New-UDColumn -Size 6 -Endpoint {
                            New-UDElement -Id "CurrentRootDirTB" -Tag div -EndPoint {
                                #New-UDTextbox -Label "Current Directory" -Placeholder "Directory to Explore" -Value $Session:RootDirItem.FullName
                                New-UDHeading -Text "Current Directory: $($Session:RootDirItem.FullName)" -Size 5
                            }
                            New-UDElement -Id "NewRootDirTB" -Tag div -EndPoint {
                                New-UDTextbox -Id "NewRootDirTBProper" -Label "New Directory"
                            }
                            New-UDButton -Text "Explore" -OnClick {
                                $NewRootDirTextBox = Get-UDElement -Id "NewRootDirTBProper"
                                $FullPathToExplore = $NewRootDirTextBox.Attributes['value']
    
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    $RootDirChildItems = Get-ChildItem -Path $args[0]
                                    $RootDirItem = Get-Item -Path $args[0]
    
                                    [pscustomobject]@{
                                        RootDirItem            = $RootDirItem
                                        RootDirChildItems      = $RootDirChildItems
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:RootDirChildItems = $NewPathInfo.RootDirChildItems
                                $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirChildItems = $NewPathInfo.RootDirChildItems
                                $Session:RootDirItem = $NewPathInfo.RootDirItem
                                $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirItem = $NewPathInfo.RootDirItem
                                Sync-UDElement -Id "RootDirChildItemsUDGrid"
                                Sync-UDElement -Id "NewRootDirTB"
                                Sync-UDElement -Id "CurrentRootDirTB"
                            }
    
                            New-UDButton -Text "Parent Directory" -OnClick {
                                $FullPathToExplore = if ($($Session:RootDirItem.FullName | Split-Path -Parent) -eq "") {$Session:RootDirItem.FullName} else {$Session:RootDirItem.FullName | Split-Path -Parent}
    
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    $RootDirChildItems = Get-ChildItem -Path $args[0]
                                    $RootDirItem = Get-Item -Path $args[0]
    
                                    [pscustomobject]@{
                                        RootDirItem            = $RootDirItem
                                        RootDirChildItems      = $RootDirChildItems
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:RootDirChildItems = $NewPathInfo.RootDirChildItems
                                $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirChildItems = $NewPathInfo.RootDirChildItems
                                $Session:RootDirItem = $NewPathInfo.RootDirItem
                                $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirItem = $NewPathInfo.RootDirItem
                                Sync-UDElement -Id "RootDirChildItemsUDGrid"
                                Sync-UDElement -Id "NewRootDirTB"
                                Sync-UDElement -Id "CurrentRootDirTB"
                            }
                        }
                        New-UDColumn -Size 3 -Endpoint {}
                    }
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 12 -Endpoint {
                            $RootFilesProperties = @("Name","FullPath","DateModified","Type","Size","Explore")
                            $RootFilesUDGridSplatParams = @{
                                Id              = "RootDirChildItemsUDGrid"
                                Headers         = $RootFilesProperties
                                Properties      = $RootFilesProperties
                                PageSize        = 20
                            }
                            New-UDGrid @RootFilesUDGridSplatParams -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                $Session:RootDirChildItems | foreach {
                                    [pscustomobject]@{
                                        Name            = $_.Name
                                        FullPath        = $_.FullName
                                        DateModified    = Get-Date $_.LastWriteTime -Format MM/dd/yy_hh:mm:ss
                                        Type            = if ($_.PSIsContainer) {"Folder"} else {"File"}
                                        Size            = if ($_.PSIsContainer) {'-'} else {[Math]::Round($($_.Length / 1KB),2).toString() + 'KB'}
                                        Explore         = if (!$_.PSIsContainer) {'-'} else {
                                            New-UDButton -Text "Explore" -OnClick {
                                                #$NewRootDirTextBox = Get-UDElement -Id "NewRootDirTB"
                                                $FullPathToExplore = $_.FullName
                    
                                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                    $RootDirChildItems = Get-ChildItem -Path $args[0]
                                                    $RootDirItem = Get-Item -Path $args[0]
    
                                                    [pscustomobject]@{
                                                        RootDirItem            = $RootDirItem
                                                        RootDirChildItems      = $RootDirChildItems
                                                    }
                                                } -ArgumentList $FullPathToExplore
                                                $Session:RootDirChildItems = $NewPathInfo.RootDirChildItems
                                                $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirChildItems = $NewPathInfo.RootDirChildItems
                                                $Session:RootDirItem = $NewPathInfo.RootDirItem
                                                $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirItem = $NewPathInfo.RootDirItem
                                                Sync-UDElement -Id "RootDirChildItemsUDGrid"
                                                Sync-UDElement -Id "NewRootDirTB"
                                                Sync-UDElement -Id "CurrentRootDirTB"
                                            }
                                        }
                                    }
                                } | Out-UDGridData
                            }
                        }
                    }
                }
            }
    
            <#
            New-UDInput -Title "Explore Path" -SubmitText "Explore" -Content {
                New-UDInputField -Name "FullPathToExplore" -Type textbox
            } -Endpoint {
                param($FullPathToExplore)
    
                #region >> Check Connection
    
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                #endregion >> Check Connection
    
                #region >> SubMain
    
                if (!$FullPathToExplore) {
                    New-UDInputAction -Toast "You must fill out the 'FullPathToExplore' field!" -Duration 10000
                    return
                }
    
                try {
                    $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                        $RootDirChildItems = Get-ChildItem -Path $using:FullPathToExplore
            
                        [pscustomobject]@{
                            RootDirChildItems      = $RootDirChildItems
                        }
                    }
                    $Session:RootDirChildItems = $NewPathInfo.RootDirChildItems
                    $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirChildItems = $Session:RootDirChildItems
    
                    Sync-UDElement -Id "RootDirChildItemsUDGrid"
    
                    #Invoke-UDRedirect -Url "/Files/$RemoteHost"
                }
                catch {
                    New-UDInputAction -Toast $_.Exception.Message -Duration 2000
                
                    #Invoke-UDRedirect -Url "/Overview/$RemoteHost"
                }
            }
            #>
    
            <#
            # Static Data Element Example
            New-UDCollapsible -Id $CollapsibleId -Items {
                New-UDCollapsibleItem -Title "File System" -Icon laptop -Active -Endpoint {
                    #region >> Main
    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 12 -Endpoint {
                            $RootFilesProperties = @("Name","FullPath","DateModified","Type","Size")
                            $RootFilesUDGridSplatParams = @{
                                Id              = "RootDirChildItemsUDGrid"
                                Headers         = $RootFilesProperties
                                Properties      = $RootFilesProperties
                                PageSize        = 20
                            }
                            New-UDGrid @RootFilesUDGridSplatParams -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                $Session:RootDirChildItems | foreach {
                                    [pscustomobject]@{
                                        Name            = $_.Name
                                        FullPath        = $_.FullName
                                        DateModified    = Get-Date $_.LastWriteTime -Format MM/dd/yy_hh:mm:ss
                                        Type            = if ($_.PSIsContainer) {"Folder"} else {"File"}
                                        Size            = if ($_.PSIsContainer) {'-'} else {[Math]::Round($($_.Length / 1KB),2).toString() + 'KB'}
                                        #Inspect         = $Cache:InspectCell
                                    }
                                } | Out-UDGridData
                            }
                        }
                    }
                    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 4 -Endpoint {
                            New-UDInput -Title "Explore Path" -SubmitText "Explore" -Content {
                                New-UDInputField -Name "FullPathToExplore" -Type textbox
                            } -Endpoint {
                                param($FullPathToExplore)
    
                                #region >> Check Connection
    
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                #endregion >> Check Connection
    
                                #region >> SubMain
    
                                if (!$FullPathToExplore) {
                                    New-UDInputAction -Toast "You must fill out the 'FullPathToExplore' field!" -Duration 10000
                                    return
                                }
    
                                try {
                                    $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                        $RootDirChildItems = Get-ChildItem -Path $using:FullPathToExplore
                            
                                        [pscustomobject]@{
                                            RootDirChildItems      = $RootDirChildItems
                                        }
                                    }
                                    $Session:RootDirChildItems = $NewPathInfo.RootDirChildItems
                                    $PUDRSSyncHT."$RemoteHost`Info".Files.RootDirChildItems = $Session:RootDirChildItems
    
                                    Sync-UDElement -Id "RootDirChildItemsUDGrid"
    
                                    #Invoke-UDRedirect -Url "/Files/$RemoteHost"
                                }
                                catch {
                                    New-UDInputAction -Toast $_.Exception.Message -Duration 2000
                                
                                    #Invoke-UDRedirect -Url "/Overview/$RemoteHost"
                                }
    
                                #endregion >> SubMain
                            }
                        }
                    }
    
                    New-UDButton -Text "SyncFileGrid" -Id "Button" -OnClick {
                        Sync-UDElement -Id "RootDirChildItemsUDGrid"
                    }
    
                    #endregion >> Main
                }
            }
            #>
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:FilesPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Files/:RemoteHost" -Endpoint $FilesPageContent
    $null = $Pages.Add($Page)
    
    $FirewallPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:FirewallPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:FirewallPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $GetFirewallProfileFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-FirewallProfile" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetFirewallRulesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-FirewallRules" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $FunctionsToLoad = @($GetFirewallProfileFunc,$GetFirewallRulesFunc)
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                $using:FunctionsToLoad | foreach {Invoke-Expression $_}
                
                $FirewallSummary = Get-FirewallProfile -ErrorAction SilentlyContinue | foreach {
                    [pscustomobject]@{
                        Name                    = $_.Name
                        Status                  = if ($_.Enabled) {"Enabled"} else {"Disabled"}
                        DefaultInboundAction    = $_.DefaultInboundAction.ToString()
                        DefaultOutboundAction   = $_.DefaultOutboundAction.ToString()
                    }
                }
    
                $FirewallRulesPrep = Get-FirewallRules -ErrorAction SilentlyContinue
                $FirewallRules = foreach ($Rule in $FirewallRulesPrep) {
                    $Profiles = switch (@($Rule.profiles)) {
                        0 {"All"}
                        1 {"Domain"}
                        2 {"Private"}
                        3 {"Domain, Private"}
                        4 {"Public"}
                        5 {"Domain, Public"}
                        6 {"Private, Public"}
                    }
    
                    [pscustomobject]@{
                        DisplayName         = $Rule.DisplayName
                        Direction           = $Rule.Direction.ToString()
                        Action              = $Rule.Action.ToString()
                        DisplayGroup        = $Rule.DisplayGroup
                        Status              = if ($Rule.enabled) {"Enabled"} else {"Disabled"}
                        Profile             = $Profiles
                        Program             = @($Rule.applicationFilter.Program) -join ", "
                        Protocol            = @($Rule.portFilter.Protocol) -join ", "
                        LocalPort           = @($Rule.portFilter.LocalPort) -join ", "
                        RemotePort          = @($Rule.portFilter.RemotePort) -join ", "
                    }
                }
    
                [pscustomobject]@{
                    FirewallSummary     = $FirewallSummary
                    FirewallRules       = $FirewallRules
                }
            }
            $Session:FirewallSummaryStatic = $StaticInfo.FirewallSummary
            $Session:FirewallRulesStatic = $StaticInfo.FirewallRules
            if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.Keys -notcontains "FirewallSummary") {
                $PUDRSSyncHT."$RemoteHost`Info".Firewall.Add("FirewallSummary",$Session:FirewallSummaryStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Firewall.FirewallSummary = $Session:FirewallSummaryStatic
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.Keys -notcontains "FirewallRules") {
                $PUDRSSyncHT."$RemoteHost`Info".Firewall.Add("FirewallRules",$Session:FirewallRulesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Firewall.FirewallRules = $Session:FirewallRulesStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Firewall (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            <#
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetFirewallFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Firewall" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetFirewallFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Firewall$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Firewall$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllFirewall = Get-Firewall}
                            }
    
                            # Operations that you want to run once every second go here
                            @{FirewallSummary = Get-FirewallOverview -channel "Microsoft-Windows-FirewallervicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Firewall$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo equal to
                # $RSSyncHash."Firewall$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo = $RSSyncHash."Firewall$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            $FirewallOverviewProperties = @("Name","Status","DefaultInboundAction","DefaultOutboundAction")
            $FirewallOverviewUDGridSplatParams = @{
                Id              = "FirewallOverviewUDGrid"
                Headers         = $FirewallOverviewProperties
                Properties      = $FirewallOverviewProperties
            }
            New-UDGrid @FirewallOverviewUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetFirewallProfileFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-FirewallProfile" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetFirewallProfileFunc
                    
                    $FirewallSummary = Get-FirewallProfile -ErrorAction SilentlyContinue | foreach {
                        [pscustomobject]@{
                            Name                    = $_.Name
                            Status                  = if ($_.Enabled) {"Enabled"} else {"Disabled"}
                            DefaultInboundAction    = $_.DefaultInboundAction.ToString()
                            DefaultOutboundAction   = $_.DefaultOutboundAction.ToString()
                        }
                    }
    
                    [pscustomobject]@{
                        FirewallSummary     = $FirewallSummary
                    }
                }
                $Session:FirewallSummaryStatic = $StaticInfo.FirewallSummary
                if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.Keys -notcontains "FirewallSummary") {
                    $PUDRSSyncHT."$RemoteHost`Info".Firewall.Add("FirewallSummary",$Session:FirewallSummaryStatic)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Firewall.FirewallSummary = $Session:FirewallSummaryStatic
                }
    
                $Session:FirewallSummaryStatic | Out-UDGridData
            }
    
            $FirewallRulesProperties = @("DisplayName","Direction","Action","DisplayGroup","Status","Profile","Program","Protocol","LocalPort","RemotePort")
            $FirewallRulesUDGridSplatParams = @{
                Id              = "FirewallRulesUDGrid"
                Headers         = $FirewallRulesProperties
                Properties      = $FirewallRulesProperties
            }
            New-UDGrid @FirewallRulesUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetFirewallRulesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-FirewallRules" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetFirewallRulesFunc
                    
                    $FirewallRulesPrep = Get-FirewallRules -ErrorAction SilentlyContinue
    
                    $FirewallRules = foreach ($Rule in $FirewallRulesPrep) {
                        $Profiles = switch (@($Rule.profiles)) {
                            0 {"All"}
                            1 {"Domain"}
                            2 {"Private"}
                            3 {"Domain, Private"}
                            4 {"Public"}
                            5 {"Domain, Public"}
                            6 {"Private, Public"}
                        }
    
                        [pscustomobject]@{
                            DisplayName         = $Rule.DisplayName
                            Direction           = $Rule.Direction.ToString()
                            Action              = $Rule.Action.ToString()
                            DisplayGroup        = $Rule.DisplayGroup
                            Status              = if ($Rule.enabled) {"Enabled"} else {"Disabled"}
                            Profile             = $Profiles
                            Program             = @($Rule.applicationFilter.Program) -join ", "
                            Protocol            = @($Rule.portFilter.Protocol) -join ", "
                            LocalPort           = @($Rule.portFilter.LocalPort) -join ", "
                            RemotePort          = @($Rule.portFilter.RemotePort) -join ", "
                        }
                    }
    
                    [pscustomobject]@{
                        FirewallRules       = $FirewallRules
                    }
                }
                $Session:FirewallRulesStatic = $StaticInfo.FirewallRules
                if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.Keys -notcontains "FirewallRules") {
                    $PUDRSSyncHT."$RemoteHost`Info".Firewall.Add("FirewallRules",$Session:FirewallRulesStatic)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Firewall.FirewallRules = $Session:FirewallRulesStatic
                }
    
                $Session:FirewallRulesStatic | Out-UDGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:FirewallPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Firewall/:RemoteHost" -Endpoint $FirewallPageContent
    $null = $Pages.Add($Page)
    
    $NetworkPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:NetworkPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:NetworkPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $GetNetworksFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Networks" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $TestIsValidIPFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function TestIsValidIPAddress" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetNetworksFunc
                Invoke-Expression $using:TestIsValidIPFunc
                
                $Networks = Get-Networks | foreach {
                    $PrimaryIPv4AddressesUpdatedFormat = foreach ($ArrayObj in $_.PrimaryIPv4Address) {
                        foreach ($IPString in $ArrayObj) {
                            if (TestIsValidIPAddress -IPAddress $IPString) {
                                $IPString
                            }
                        }
                    }
                    $IPv4DNSServerAddressesUpdatedFormat = foreach ($ArrayObj in $_.IPv4DNSServer) {
                        foreach ($IPString in $ArrayObj) {
                            if (TestIsValidIPAddress -IPAddress $IPString) {
                                $IPString
                            }
                        }
                    }
    
                    [pscustomobject]@{
                        InterfaceAlias              = $_.InterfaceAlias
                        InterfaceIndex              = $_.InterfaceIndex
                        InterfaceDescription        = $_.InterfaceDescription
                        Status                      = $_.Status
                        MacAddress                  = $_.MacAddress
                        LinkSpeed                   = $_.LinkSpeed
                        PrimaryIPv6Address          = $_.PrimaryIPv6Address -join ", "
                        LinkLocalIPv6Address        = $_.LinkLocalIPv6Address -join ", "
                        PrimaryIPv4Address          = $PrimaryIPv4AddressesUpdatedFormat -join ", "
                        DhcpIPv4                    = if ($_.DhcpIPv4) {$_.DhcpIPv4.ToString()} else {$null}
                        IPv6Enabled                 = $_.IPv6Enabled.ToString()
                        IPv4DefaultGateway          = $_.IPv4DefaultGateway -join ", "
                        IPv4DNSServer               = $IPv4DNSServerAddressesUpdatedFormat -join ", "
                        IPv6DNSServer               = $_.IPv6DNSServer -join ", "
                        IPv4DnsManuallyConfigured   = $_.IPv4DnsManuallyConfigured.ToString()
                    }
                }
    
                [pscustomobject]@{
                    NetworksInfo    = $Networks
                }
            }
            $Session:NetworksInfoStatic = $StaticInfo.NetworksInfo
            if ($PUDRSSyncHT."$RemoteHost`Info".Network.Keys -notcontains "NetworksInfo") {
                $PUDRSSyncHT."$RemoteHost`Info".Network.Add("NetworksInfo",$Session:NetworksInfoStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Network.NetworksInfo = $Session:NetworksInfoStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Network (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            <#
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetNetworkificateOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-NetworkificateOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetNetworkFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Network" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetNetworkificateOverviewFunc,$GetNetworkFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Network$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Network$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllNetworks = Get-Network}
                            }
    
                            # Operations that you want to run once every second go here
                            @{NetworkSummary = Get-NetworkificateOverview -channel "Microsoft-Windows-NetworkervicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Network$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo equal to
                # $RSSyncHash."Network$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Network.LiveDataRSInfo = $RSSyncHash."Network$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            $NetworksInfoProperties = @(
                "InterfaceAlias"
                "InterfaceIndex"
                "InterfaceDescription"
                "Status"
                "MacAddress"
                "LinkSpeed"
                "PrimaryIPv6Address"
                "LinkLocalIPv6Address"
                "PrimaryIPv4Address"
                "DhcpIPv4"
                "IPv6Enabled"
                "IPv4DefaultGateway"
                "IPv4DNSServer"
                "IPv6DNSServer"
                "IPv4DnsManuallyConfigured"
            )
            $AllNetworksUDGridSplatParams = @{
                Headers         = $NetworksInfoProperties
                Properties      = $NetworksInfoProperties
                NoPaging        = $True
            }
            New-UDGrid @AllNetworksUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetNetworksFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Networks" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $TestIsValidIPFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function TestIsValidIPAddress" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetNetworksFunc
                    Invoke-Expression $using:TestIsValidIPFunc
                    
                    $Networks = Get-Networks | foreach {
                        $PrimaryIPv4AddressesUpdatedFormat = foreach ($ArrayObj in $_.PrimaryIPv4Address) {
                            foreach ($IPString in $ArrayObj) {
                                if (TestIsValidIPAddress -IPAddress $IPString) {
                                    $IPString
                                }
                            }
                        }
                        $IPv4DNSServerAddressesUpdatedFormat = foreach ($ArrayObj in $_.IPv4DNSServer) {
                            foreach ($IPString in $ArrayObj) {
                                if (TestIsValidIPAddress -IPAddress $IPString) {
                                    $IPString
                                }
                            }
                        }
    
                        [pscustomobject]@{
                            InterfaceAlias              = $_.InterfaceAlias
                            InterfaceIndex              = $_.InterfaceIndex
                            InterfaceDescription        = $_.InterfaceDescription
                            Status                      = $_.Status
                            MacAddress                  = $_.MacAddress
                            LinkSpeed                   = $_.LinkSpeed
                            PrimaryIPv6Address          = $_.PrimaryIPv6Address -join ", "
                            LinkLocalIPv6Address        = $_.LinkLocalIPv6Address -join ", "
                            PrimaryIPv4Address          = $PrimaryIPv4AddressesUpdatedFormat -join ", "
                            DhcpIPv4                    = if ($_.DhcpIPv4) {$_.DhcpIPv4.ToString()} else {$null}
                            IPv6Enabled                 = $_.IPv6Enabled.ToString()
                            IPv4DefaultGateway          = $_.IPv4DefaultGateway -join ", "
                            IPv4DNSServer               = $IPv4DNSServerAddressesUpdatedFormat -join ", "
                            IPv6DNSServer               = $_.IPv6DNSServer -join ", "
                            IPv4DnsManuallyConfigured   = $_.IPv4DnsManuallyConfigured.ToString()
                        }
                    }
    
                    [pscustomobject]@{
                        NetworksInfo    = $Networks
                    }
                }
                $Session:NetworksInfoStatic = $StaticInfo.NetworksInfo
                if ($PUDRSSyncHT."$RemoteHost`Info".Network.Keys -notcontains "NetworksInfo") {
                    $PUDRSSyncHT."$RemoteHost`Info".Network.Add("NetworksInfo",$Session:NetworksInfoStatic)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Network.NetworksInfo = $Session:NetworksInfoStatic
                }
    
                $Session:NetworksInfoStatic | Out-UDGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:NetworkPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Network/:RemoteHost" -Endpoint $NetworkPageContent
    $null = $Pages.Add($Page)
    
    #region >> Overview Page
    
    $OverviewPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:OverviewPageLoadingTracker = [System.Collections.ArrayList]::new()
                $Session:RestartingRemoteHost = $False
                $Session:ShutdownRemoteHost = $False
                $Session:EnableDiskPerf = $False
                $Session:DisableDiskPerf = $False
                $Session:EnableRemoteDesktop = $False
                $Session:DisableRemoteDesktop = $False
                $Session:EnableSSH = $False
                $Session:DisableSSH = $False
            }
            New-UDColumn -AutoRefresh -RefreshInterval 10 -Endpoint {
                if ($Session:OverviewPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","CredSSP","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                <#
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Disconnected"
                                }
                                #>
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                            }
                            
                            if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.Count -eq 0) {
                                if ($Session:ServerInventoryStatic.IsCredSSPEnabled) {
                                    $CredSSPStatus = "Enabled"
                                }
                                else {
                                    $CredSSPStatus = "Disabled"
                                }
                            }
                            elseif (@($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.ServerInventory).Count -gt 0) {
                                if (@($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.ServerInventory)[-1].IsCredSSPEnabled) {
                                    $CredSSPStatus = "Enabled"
                                }
                                else {
                                    $CredSSPStatus = "Disabled"
                                }
                            }
                            else {
                                $CredSSPStatus = "NotYetDetermined"
                            }
                            $TableData.Add("CredSSP",$CredSSPStatus)
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","CredSSP","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $GetServerInventoryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ServerInventory" -and $_ -notmatch "function Get-PUDAdminCenter"}
            #$GetEnvVarsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-EnvironmentVariables" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetServerInventoryFunc
                #Invoke-Expression $using:GetEnvVarsFunc
                
                $SrvInv = Get-ServerInventory
                #$EnvVars = Get-EnvironmentVariables
                $RelevantNetworkInterfacesPrep = [System.Net.NetworkInformation.Networkinterface]::GetAllNetworkInterfaces() | Where-Object {
                    $_.NetworkInterfaceType -eq "Ethernet" -or $_.NetworkInterfaceType -match "Wireless" -and $_.OperationalStatus -eq "Up"
                }
                $RelevantNetworkInterfaces = foreach ($NetInt in $RelevantNetworkInterfacesPrep) {
                    $IPv4Stats = $NetInt.GetIPv4Statistics()
                    [pscustomobject]@{
                        Name                = $NetInt.Name
                        Description         = $NetInt.Description
                        TotalSentBytes      = $IPv4Stats.BytesSent
                        TotalReceivedBytes  = $IPv4Stats.BytesReceived
                    }
                }
    
                [pscustomobject]@{
                    ServerInventoryStatic       = $SrvInv
                    RelevantNetworkInterfaces   = $RelevantNetworkInterfaces
                    #EnvironmentVariables        = [pscustomobject]$EnvVars
                }
            }
            $Session:ServerInventoryStatic = $StaticInfo.ServerInventoryStatic
            $Session:RelevantNetworkInterfacesStatic = $StaticInfo.RelevantNetworkInterfaces
            #$Session:EnvironmentVariablesStatic = $StaticInfo.EnvironmentVariables
            if ($PUDRSSyncHT."$RemoteHost`Info".Overview.Keys -notcontains "ServerInventoryStatic") {
                $PUDRSSyncHT."$RemoteHost`Info".Overview.Add("ServerInventoryStatic",$Session:ServerInventoryStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic = $Session:ServerInventoryStatic
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Overview.Keys -notcontains "RelevantNetworkInterfaces") {
                $PUDRSSyncHT."$RemoteHost`Info".Overview.Add("RelevantNetworkInterfaces",$Session:RelevantNetworkInterfacesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces = $Session:RelevantNetworkInterfacesStatic
            }
            <#
            if ($PUDRSSyncHT."$RemoteHost`Info".Overview.Keys -notcontains "EnvironmentVariablesStatic") {
                $PUDRSSyncHT."$RemoteHost`Info".Overview.Add("EnvironmentVariablesStatic",$Session:EnvironmentVariablesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvironmentVariablesStatic = $Session:EnvironmentVariablesStatic
            }
            #>
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Overview" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                <#
                if (!$Session:ServerInventoryStatic) {
                    # Gather Basic Info From $RemoteHost
                    $GetServerInventoryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ServerInventory" -and $_ -notmatch "function Get-PUDAdminCenter"}
                    $StaticInfoA = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                        Invoke-Expression $using:GetServerInventoryFunc
    
                        $SrvInv = Get-ServerInventory
    
                        [pscustomobject]@{
                            ServerInventoryStatic       = $SrvInv
                        }
                    }
                    $Session:ServerInventoryStatic = $StaticInfoA.ServerInventoryStatic
                    if ($PUDRSSyncHT."$RemoteHost`Info".Overview.Keys -notcontains "ServerInventoryStatic") {
                        $PUDRSSyncHT."$RemoteHost`Info".Overview.Add("ServerInventoryStatic",$Session:ServerInventoryStatic)
                    }
                    else {
                        $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic = $Session:ServerInventoryStatic
                    }
                }
                #>
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetEnvVarsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-EnvironmentVariables" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetServerInventoryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ServerInventory" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetEnvVarsFunc,$GetServerInventoryFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Overview$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Overview$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go withing this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                # Server Inventory
                                @{ServerInventory = Get-ServerInventory}
                                #Start-Sleep -Seconds 3
                            
                                # Processes
                                #@{Processes = [System.Diagnostics.Process]::GetProcesses()}
                                #Start-Sleep -Seconds 3
                            }
    
                            # Operations that you want to run once every second go here
    
                            # Processes
                            @{ProcessesCount = $(Get-Counter "\Process(*)\ID Process" -ErrorAction SilentlyContinue).CounterSamples.Count}
                            @{HandlesCount = $(Get-Counter "\Process(_total)\handle count").CounterSamples.CookedValue}
                            @{ThreadsCount = $(Get-Counter "\Process(_total)\thread count").CounterSamples.CookedValue}
    
                            # Environment Variables
                            #@{EnvVars = [pscustomobject]@{EnvVarsCollection = Get-EnvironmentVariables}}
    
                            # RAM Utilization
                            $OSInfo = Get-CimInstance Win32_OperatingSystem
                            $TotalMemoryInGB = [Math]::Round($($OSInfo.TotalVisibleMemorySize / 1MB),2)
                            @{RamTotalGB = $TotalMemoryInGB}
                            
                            $FreeMemoryInGB = [Math]::Round($($(Get-Counter -Counter "\Memory\available bytes").CounterSamples.CookedValue / 1GB),2)
                            @{RamFreeGB = $FreeMemoryInGB}
    
                            $RamPct = [Math]::Round($($(Get-Counter -Counter "\Memory\% committed bytes in use").CounterSamples.CookedValue),2)
                            @{RamPct = $RamPct}
                            
                            $RamCommittedGB = [Math]::Round($($(Get-Counter -Counter "\Memory\committed bytes").CounterSamples.CookedValue / 1GB),2)
                            @{RamCommittedGB = $RamCommittedGB}
    
                            $RamCachedGB = $RamCommitted + [Math]::Round($($(Get-Counter -Counter "\Memory\cache bytes").CounterSamples.CookedValue / 1GB),2)
                            @{RamCachedGB = $RamCachedGB}
    
                            $RamInUseGB = $TotalMemoryInGB - $FreeMemoryInGB
                            @{RamInUseGB = $RamInUseGB}
    
                            $RamPagedPoolMB = [Math]::Round($($(Get-Counter -Counter "\Memory\pool paged bytes").CounterSamples.CookedValue / 1MB),2)
                            @{RamPagedPoolMB = $RamPagedPoolMB}
    
                            $RamNonPagedPoolMB = [Math]::Round($($(Get-Counter -Counter "\Memory\pool nonpaged bytes").CounterSamples.CookedValue / 1MB),2)
                            @{RamNonPagedPoolMB = $RamNonPagedPoolMB}
    
                            # CPU
                            $CPUInfo = Get-CimInstance Win32_Processor
                            @{CPUPct = $CPUInfo.LoadPercentage}
                            @{ClockSpeed = [Math]::Round($($CPUInfo.CurrentClockSpeed / 1KB),2)}
    
                            @{Uptime = "{0:c}" -f $($(Get-Date) - $OSInfo.LastBootUpTime)}
    
                            # Network Stats
                            $RelevantNetworkInterfaces = [System.Net.NetworkInformation.Networkinterface]::GetAllNetworkInterfaces() | Where-Object {
                                $_.NetworkInterfaceType -eq "Ethernet" -or $_.NetworkInterfaceType -match "Wireless" -and $_.OperationalStatus -eq "Up"
                            }
                            [System.Collections.ArrayList]$NetStatsInfo = @()
                            foreach ($NetInt in $RelevantNetworkInterfaces) {
                                $IPv4Stats = $NetInt.GetIPv4Statistics()
                                $NetStatsPSObj = [pscustomobject]@{
                                    Name                = $NetInt.Name
                                    Description         = $NetInt.Description
                                    TotalSentBytes      = $IPv4Stats.BytesSent
                                    TotalReceivedBytes  = $IPv4Stats.BytesReceived
                                }
                                $null = $NetStatsInfo.Add($NetStatsPSObj)
                            }
                            @{NetStats = $NetStatsInfo}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Overview$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Certificates.LiveDataRSInfo equal to
                # $RSSyncHash."Overview$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo = $RSSyncHash."Overview$RemoteHost`LiveDataResult"
            }
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            New-UDRow -Endpoint {
                # Restart $RemoteHost
                New-UDColumn -Size 3 -Endpoint {
                    # Show-UDToast doesn't work in this context for some reason...
                    <#
                    New-UDElement -Id "RestartComputerToast" -Tag div -EndPoint {
                        Show-UDToast -Message "Restarting $RemoteHost..." -Duration 10
                    }
                    #>
    
                    $CollapsibleId = $RemoteHost + "RestartComputer"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "Restart" -Icon laptop -Endpoint {
                            New-UDElement -Id "RestartComputerMsg" -Tag div -EndPoint {
                                if ($Session:RestartingRemoteHost) {
                                    New-UDHeading -Text "Restarting $RemoteHost..." -Size 6
                                }
                            }
                            New-UDButton -Text "Restart $RemoteHost" -OnClick {
                                $Session:RestartingRemoteHost = $True
                                Sync-UDElement -Id "RestartComputerMsg"
    
                                Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Restart-Computer -Force
                                }
    
                                # Show-UDToast doesn't work in this context for some reason...
                                #Show-UDToast -Message "Restarting $RemoteHost..." -Duration 10
                                #Sync-UDElement -Id "RestartComputerToast"
                            }
    
                            <#
                            New-UDInput -SubmitText "Restart" -Id "RestartComputerForm" -Content {
                                $HName = $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic.ComputerSystem.Name
                                New-UDInputField -Name 'RestartComputer' -Type select -Values @($HName) -DefaultValue $HName
                            } -Endpoint {
                                #region >> Check Connection
    
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                #endregion >> Check Connection
    
                                #region >> Main
                                
                                Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Restart-Computer -Force
                                }
    
                                New-UDInputAction -Toast "Restarting $RemoteHost..." -Duration 10000
                                
                                New-UDInputAction -RedirectUrl "/Disconnected/$RemoteHost"
    
                                #endregion >> Main
                            }
                            #>
                        }
                    }
                }
    
                # Shutdown $RemoteHost
                New-UDColumn -Size 3 -Endpoint {
                    $CollapsibleId = $RemoteHost + "ShutdownComputer"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "Shutdown" -Icon laptop -Endpoint {
                            New-UDElement -Id "ShutdownComputerMsg" -Tag div -EndPoint {
                                if ($Session:ShutdownRemoteHost) {
                                    New-UDHeading -Text "Shutting down $RemoteHost..." -Size 6
                                }
                            }
                            New-UDButton -Text "Shutdown $RemoteHost" -OnClick {
                                $Session:ShutdownRemoteHost = $True
                                Sync-UDElement -Id "ShutdownComputerMsg"
    
                                Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Stop-Computer -Force
                                }
                            }
    
                            <#
                            New-UDInput -SubmitText "Shutdown" -Id "ShutdownComputerForm" -Content {
                                $HName = $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic.ComputerSystem.Name
                                New-UDInputField -Name "ShutdownComputer" -Type select -Values @($HName) -DefaultValue $HName
                            } -Endpoint {
                                #region >> Check Connection
    
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                #endregion >> Check Connection
    
                                #region >> Main
    
                                Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Stop-Computer -Force
                                }
    
                                New-UDInputAction -Toast "Shutting down $RemoteHost..." -Duration 10000
                                
                                New-UDInputAction -RedirectUrl "/Disconnected/$RemoteHost"
    
                                #endregion >> Main
                            }
                            #>
                        }
                    }
                }
                # Enable Disk Metrics
                New-UDColumn -Size 3 -Endpoint {
                    $CollapsibleId = $RemoteHost + "SetDiskMetrics"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "Set Disk Metrics" -Icon laptop -Endpoint {
                            New-UDRow -Endpoint {
                                New-UDColumn -Endpoint {
                                    New-UDElement -Id "EnableDiskPerfMsg" -Tag div -EndPoint {
                                        if ($Session:EnableDiskPerf) {
                                            New-UDHeading -Text $Session:EnableDiskPerfMsg -Size 6
                                            Show-UDToast -Message $Session:EnableDiskPerfMsg -Position 'topRight' -Title "DiskPerfToast" -Duration 5000
                                        }
                                    }
                                    New-UDElement -Id "DisableDiskPerfMsg" -Tag div -EndPoint {
                                        if ($Session:DisableDiskPerf) {
                                            New-UDHeading -Text $Session:DisableDiskPerfMsg -Size 6
                                            Show-UDToast -Message $Session:DisableDiskPerfMsg -Position 'topRight' -Title "DiskPerfToast" -Duration 5000
                                        }
                                    }
                                    New-UDElement -Id "DiskPerfState" -Tag div -EndPoint {
                                        # TODO: Figure out a way to check if the disk performance counters are actually enabled or disabled.
                                        # Can't get consistent results using the below method
                                        <#
                                        $DiskPerfState = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            try {
                                                $null = Get-Counter "\physicaldisk(0 c:)\disk writes/sec" -ErrorAction Stop
                                                $DiskPerfStatus = "Enabled"
                                            }
                                            catch {
                                                $DiskPerfStatus = "Disabled"
                                            }
    
                                            [pscustomobject]@{
                                                Status       = $DiskPerfStatus
                                            }
                                        }
                                        #>
    
                                        New-UDHeading -Text "Status: $Session:DiskPerfState" -Size 6
                                    }
                                }
                            }
                            New-UDRow -Endpoint {
                                New-UDColumn -EndPoint {
                                    New-UDButton -Text "Enable" -OnClick {
                                        $Session:EnableDiskPerfMsg = "Enabling Disk Performance Metrics for $RemoteHost..."
                                        $Session:EnableDiskPerf = $True
                                        Sync-UDElement -Id "EnableDiskPerfMsg"
    
                                        $StartDiskPerfFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Start-DiskPerf" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:StartDiskPerfFunc
                                            $null = Start-DiskPerf
                                        }
    
                                        $Session:DiskPerfState = "Enabled"
                                        Sync-UDElement -Id "DiskPerfState"
    
                                        $Session:EnableDiskPerf = $False
                                        Sync-UDElement -Id "EnableDiskPerfMsg"
                                    }
                                }
                                New-UDColumn -Endpoint {
                                    New-UDButton -Text "Disable" -OnClick {
                                        $Session:DisableDiskPerfMsg = "Disabling Disk Performance Metrics for $RemoteHost..."
                                        $Session:DisableDiskPerf = $True
                                        Sync-UDElement -Id "DisableDiskPerfMsg"
    
                                        $StopDiskPerfFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Stop-DiskPerf" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:StopDiskPerfFunc
                                            Stop-DiskPerf
                                        }
    
                                        $Session:DiskPerfState = "Disabled"
                                        Sync-UDElement -Id "DiskPerfState"
    
                                        $Session:DisableDiskPerf = $False
                                        Sync-UDElement -Id "DisableDiskPerfMsg"
                                    }
                                }
                            }
                        }
                    }
                }
    
                # Disable CredSSP
                New-UDColumn -Size 3 -Endpoint {
                    $CollapsibleId = $RemoteHost + "DisableCredSSP"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "Disable CredSSP*" -Icon laptop -Endpoint {
                            New-UDRow -Endpoint {
                                New-UDColumn -Endpoint {
                                    New-UDElement -Id "DisableCredSSPMsg" -Tag div -EndPoint {
                                        if ($Session:DisableCredSSP) {
                                            if (!$Session:DisableCredSSPMsg) {
                                                $Session:DisableCredSSPMsg = "Placeholder CredSSP Message"
                                            }
                                            New-UDHeading -Text $Session:DisableCredSSPMsg -Size 6
                                            Show-UDToast -Message $Session:DisableCredSSPMsg -Position 'topRight' -Title "CredSSPToast" -Duration 5000
                                        }
                                    }
                                    New-UDElement -Id "CredSSPState" -Tag div -EndPoint {
                                        if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.Count -eq 0) {
                                            if ($Session:ServerInventoryStatic.IsCredSSPEnabled) {
                                                $CredSSPStatus = "Enabled"
                                            }
                                            else {
                                                $CredSSPStatus = "Disabled"
                                            }
                                        }
                                        elseif (@($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.ServerInventory).Count -gt 0) {
                                            if (@($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.ServerInventory)[-1].IsCredSSPEnabled) {
                                                $CredSSPStatus = "Enabled"
                                            }
                                            else {
                                                $CredSSPStatus = "Disabled"
                                            }
                                        }
                                        else {
                                            $CredSSPStatus = "NotYetDetermined"
                                        }
                                        
                                        New-UDHeading -Text "Status: $CredSSPStatus" -Size 6
                                    }
                                }
                            }
                            New-UDRow -Endpoint {
                                New-UDColumn -Endpoint {
                                    New-UDButton -Text "Disable" -OnClick {
                                        if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.Count -eq 0) {
                                            if ($Session:ServerInventoryStatic.IsCredSSPEnabled) {
                                                $CredSSPStatus = "Enabled"
                                            }
                                            else {
                                                $CredSSPStatus = "Disabled"
                                            }
                                        }
                                        elseif (@($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.ServerInventory).Count -gt 0) {
                                            if (@($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.ServerInventory)[-1].IsCredSSPEnabled) {
                                                $CredSSPStatus = "Enabled"
                                            }
                                            else {
                                                $CredSSPStatus = "Disabled"
                                            }
                                        }
                                        else {
                                            $CredSSPStatus = "NotYetDetermined"
                                        }
    
                                        if ($CredSSPStatus -ne "Disabled") {
                                            $Session:DisableCredSSP = $True
    
                                            $CredSSPChanges = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                $Output = @{}
                                                $GetCredSSPStatus = Get-WSManCredSSP
                                                if ($GetCredSSPStatus -match "The machine is configured to allow delegating fresh credentials.") {
                                                    Disable-WSManCredSSP -Role Client
                                                    $Output.Add("CredSSPClientChange",$True)
                                                }
                                                else {
                                                    $Output.Add("CredSSPClientChange",$False)
                                                }
                                                if ($GetCredSSPStatus -match "This computer is configured to receive credentials from a remote client computer.") {
                                                    Disable-WSManCredSSP -Role Server
                                                    $Output.Add("CredSSPServerChange",$True)
                                                }
                                                else {
                                                    $Output.Add("CredSSPServerChange",$False)
                                                }
                                                [PSCustomObject]$Output
                                            }
    
                                            [System.Collections.ArrayList]$ToastMessage = @()
                                            if ($CredSSPChanges.CredSSPClientChange -eq $True) {
                                                $null = $ToastMessage.Add("Disabled CredSSP Client.")
                                            }
                                            else {
                                                $null = $ToastMessage.Add("CredSSP Client is already disabled.")
                                            }
                                            if ($CredSSPChanges.CredSSPServerChange -eq $True) {
                                                $null = $ToastMessage.Add("Disabled CredSSP Server.")
                                            }
                                            else {
                                                $null = $ToastMessage.Add("CredSSP Server is already disabled.")
                                            }
                                            $Session:DisableCredSSPMsg = $ToastMessage -join " "
    
                                            Sync-UDElement -Id "DisableCredSSPMsg"
                                        }
                                        else {
                                            $Session:DisableCredSSP = $True
    
                                            $Session:DisableCredSSPMsg = "CredSSP is already Disabled!"
    
                                            Sync-UDElement -Id "DisableCredSSPMsg"
                                        }
    
                                        Sync-UDElement -Id "CredSSPState"
    
                                        Start-Sleep -Seconds 5
                                        $Session:DisableCredSSP = $False
                                        Sync-UDElement -Id "DisableCredSSPMsg"
                                    }
    
                                    <#
                                    New-UDInput -SubmitText "Disable CredSSP" -Id "DisableCredSSPForm" -Content {
                                        $HName = $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic.ComputerSystem.Name
                                        New-UDInputField -Name "Disable_CredSSP" -Type select -Values @($HName) -DefaultValue $HName
                                    } -Endpoint {
                                        param($Disable_CredSSP)
    
                                        #region >> Check Connection
    
                                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                        #endregion >> Check Connection
    
                                        #region >> Main
    
                                        $CredSSPChanges = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            $Output = @{}
                                            $GetCredSSPStatus = Get-WSManCredSSP
                                            if ($GetCredSSPStatus -match "The machine is configured to allow delegating fresh credentials.") {
                                                Disable-WSManCredSSP -Role Client
                                                $Output.Add("CredSSPClientChange",$True)
                                            }
                                            else {
                                                $Output.Add("CredSSPClientChange",$False)
                                            }
                                            if ($GetCredSSPStatus -match "This computer is configured to receive credentials from a remote client computer.") {
                                                Disable-WSManCredSSP -Role Server
                                                $Output.Add("CredSSPServerChange",$True)
                                            }
                                            else {
                                                $Output.Add("CredSSPServerChange",$False)
                                            }
                                            [PSCustomObject]$Output
                                        }
    
                                        [System.Collections.ArrayList]$ToastMessage = @()
                                        if ($CredSSPChanges.CredSSPClientChange -eq $True) {
                                            $null = $ToastMessage.Add("Disabled CredSSP Client.")
                                        }
                                        else {
                                            $null = $ToastMessage.Add("CredSSP Client is already disabled.")
                                        }
                                        if ($CredSSPChanges.CredSSPServerChange -eq $True) {
                                            $null = $ToastMessage.Add("Disabled CredSSP Server.")
                                        }
                                        else {
                                            $null = $ToastMessage.Add("CredSSP Server is already disabled.")
                                        }
                                        $ToastMessageFinal = $ToastMessage -join " "
    
                                        New-UDInputAction -Toast $ToastMessageFinal -Duration 2000
                                        Start-Sleep -Seconds 2
    
                                        #Sync-UDElement -Id 'TrackingTable'
    
                                        #New-UDInputAction -RedirectUrl "/Overview/$RemoteHost"
    
                                        Invoke-UDRedirect -Url "/Overview/$RemoteHost"
    
                                        #endregion >> Main
                                    }
                                    #>
                                }
                            }
                        }
                    }
                }
            }
            New-UDRow -Endpoint {
                # Remote Desktop
                New-UDColumn -Size 3 -Endpoint {
                    $CollapsibleId = $RemoteHost + "RemoteDesktop"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "Remote Desktop*" -Icon laptop -Endpoint {
                            New-UDRow -Endpoint {
                                New-UDColumn -Endpoint {
                                    New-UDElement -Id "EnableRemoteDesktopMsg" -Tag div -EndPoint {
                                        if ($Session:EnableRemoteDesktop) {
                                            New-UDHeading -Text $Session:EnableRemoteDesktopMsg -Size 6
                                            Show-UDToast -Message $Session:EnableRemoteDesktopMsg -Position 'topRight' -Title "RDToast" -Duration 5000
                                        }
                                    }
                                    New-UDElement -Id "DisableRemoteDesktopMsg" -Tag div -EndPoint {
                                        if ($Session:DisableRemoteDesktop) {
                                            New-UDHeading -Text $Session:DisableRemoteDesktopMsg -Size 6
                                            Show-UDToast -Message $Session:DisableRemoteDesktopMsg -Position 'topRight' -Title "RDToast" -Duration 5000
                                        }
                                    }
                                    New-UDElement -Id "RDState" -Tag div -EndPoint {
                                        $GetRDFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RemoteDesktop" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $RemoteDesktopSettings = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:GetRDFunc
                                            Get-RemoteDesktop
                                        } -HideComputerName
                                        $RDState = if ($RemoteDesktopSettings.allowRemoteDesktop) {"Enabled"} else {"Disabled"}
                                        
                                        New-UDHeading -Text "Status: $RDState" -Size 6
                                    }
                                }
                            }
                            New-UDRow -Endpoint {
                                New-UDColumn -Endpoint {
                                    New-UDButton -Text "Enable" -OnClick {
                                        $Session:EnableRemoteDesktopMsg = "Enabling Remote Desktop on $($RemoteHost.ToUpper())..."
                                        $Session:EnableRemoteDesktop = $True
                                        Sync-UDElement -Id "EnableRemoteDesktopMsg"
    
                                        $SetRemoteDesktopSplatParams = @{
                                            AllowRemoteDesktop        = $True
                                            AllowRemoteDesktopWithNLA = $True
                                        }
                                        $SetRDFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Set-RemoteDesktop" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:SetRDFunc
    
                                            $SplatParams = $args[0]
                                            Set-RemoteDesktop @SplatParams
                                        } -ArgumentList $SetRemoteDesktopSplatParams
    
                                        Sync-UDElement -Id "RDState"
    
                                        $Session:EnableRemoteDesktop = $False
                                        Sync-UDElement -Id "EnableRemoteDesktopMsg"
                                    }
                                }
                                
                                New-UDColumn -Endpoint {
                                    New-UDButton -Text "Disable" -OnClick {
                                        $Session:DisableRemoteDesktopMsg = "Disabling Remote Desktop on $($RemoteHost.ToUpper())..."
                                        $Session:DisableRemoteDesktop = $True
                                        Sync-UDElement -Id "DisableRemoteDesktopMsg"
    
                                        $SetRemoteDesktopSplatParams = @{
                                            AllowRemoteDesktop        = $False
                                            AllowRemoteDesktopWithNLA = $False
                                        }
                                        $SetRDFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Set-RemoteDesktop" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:SetRDFunc
    
                                            $SplatParams = $args[0]
                                            Set-RemoteDesktop @SplatParams
                                        } -ArgumentList $SetRemoteDesktopSplatParams
    
                                        Sync-UDElement -Id "RDState"
    
                                        $Session:DisableRemoteDesktop = $False
                                        Sync-UDElement -Id "DisableRemoteDesktopMsg"
                                    }
    
                                    <#
                                    New-UDInput -SubmitText "Submit" -Id "RemoteDesktopForm" -Content {
                                        $GetRDFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RemoteDesktop" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $RemoteDesktopSettings = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:GetRDFunc
                                            Get-RemoteDesktop
                                        } -HideComputerName
                                        $DefaultValue = if ($RemoteDesktopSettings.allowRemoteDesktop) {"Enabled"} else {"Disabled"}
                                        New-UDInputField -Name "Remote_Desktop_Setting" -Type select -Values @("Enabled","Disabled") -DefaultValue $DefaultValue
                                    } -Endpoint {
                                        param($Remote_Desktop_Setting)
    
                                        #region >> Check Connection
    
                                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                        $SetRDFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Set-RemoteDesktop" -and $_ -notmatch "function Get-PUDAdminCenter"}
    
                                        #endregion >> Check Connection
    
                                        #region >> Main
    
                                        if ($Remote_Desktop_Setting -eq "Enabled") {
                                            $SetRemoteDesktopSplatParams = @{
                                                AllowRemoteDesktop        = $True
                                                AllowRemoteDesktopWithNLA = $True
                                            }
                                            $ToastMessage = "Remote Desktop Enabled for $RemoteHost!"
                                        }
                                        else {
                                            $SetRemoteDesktopSplatParams = @{
                                                AllowRemoteDesktop        = $False
                                                AllowRemoteDesktopWithNLA = $False
                                            }
                                            $ToastMessage = "Remote Desktop Disabled for $RemoteHost!"
                                        }
    
                                        try {
                                            $SetRemoteDesktopResult = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                Set-ItemProperty -Path "HKLM:\SYSTEM\Currentcontrolset\control\Terminal Server" -Name TSServerDrainMode -Value 1
                                            } -ArgumentList $SetRemoteDesktopSplatParams
    
                                            New-UDInputAction -Toast $ToastMessage -Duration 2000
                                        }
                                        catch {
                                            New-UDInputAction -Toast $_.Exception.Message -Duration 2000
                                        }
                                        Start-Sleep -Seconds 2
    
                                        Invoke-UDRedirect -Url "/Overview/$RemoteHost"
    
                                        #region >> Main
                                    }
                                    #>
                                }
                            }
                        }
                    }
                }
    
                # Enable SSH
                New-UDColumn -Size 3 -Endpoint {
                    $CollapsibleId = $RemoteHost + "SSH"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "SSH" -Icon laptop -Endpoint {
                            New-UDRow -Endpoint {
                                New-UDColumn -Endpoint {
                                    New-UDElement -Id "EnableSSHMsg" -Tag div -EndPoint {
                                        if ($Session:EnableSSH) {
                                            New-UDHeading -Text $Session:EnableSSHMsg -Size 6
                                            Show-UDToast -Message $Session:EnableSSHMsg -Position 'topRight' -Title "SSHToast" -Duration 5000
                                            New-UDColumn -AutoRefresh -RefreshInterval 10 -Endpoint {
                                                if ($Session:EnableSSH) {
                                                    New-UDPreloader -Size small
                                                }
                                            }
                                        }
                                    }
                                    New-UDElement -Id "DisableSSHMsg" -Tag div -EndPoint {
                                        if ($Session:DisableSSH) {
                                            New-UDHeading -Text $Session:DisableSSHMsg -Size 6
                                            Show-UDToast -Message $Session:DisableSSHMsg -Position 'topRight' -Title "SSHToast" -Duration 5000
                                        }
                                    }
                                    New-UDElement -Id "SSHState" -Tag div -EndPoint {
                                        $SSHStatusInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            $SSHState = if ($(Get-Command ssh -ErrorAction SilentlyContinue) -or $(Test-Path "$env:ProgramFiles\OpenSSH-Win64\ssh.exe")) {"Enabled"} else {"Disabled"}
                                            $SSHDState = if ($(Get-Service sshd -ErrorAction SilentlyContinue).Status -eq "Running") {"Enabled"} else {"Disabled"}
    
                                            [pscustomobject]@{
                                                SSHState    = $SSHState
                                                SSHDState   = $SSHDState
                                            }
                                        }
                                        
                                        New-UDHeading -Text "SSH Client is: $($SSHStatusInfo.SSHState)" -Size 6
                                        New-UDHeading -Text "SSHD Server is: $($SSHStatusInfo.SSHDState)" -Size 6
                                    }
                                }
                            }
                            New-UDRow -Endpoint {
                                New-UDColumn -Endpoint {
                                    New-UDButton -Text "Enable" -OnClick {
                                        $Session:EnableSSHMsg = "Enabling SSH and SSHD on $($RemoteHost.ToUpper())..."
                                        $Session:EnableSSH = $True
                                        Sync-UDElement -Id "EnableSSHMsg"
    
                                        $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            if ($(Get-Module -ListAvailable).Name -notcontains "WinSSH") {Install-Module WinSSH}
                                            if ($(Get-Module).Name -notcontains "WinSSH") {Import-Module WinSSH}
    
                                            Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh
                                        }
    
                                        Sync-UDElement -Id "SSHState"
    
                                        $Session:EnableSSH = $False
                                        Sync-UDElement -Id "EnableSSHMsg"
                                    }
                                }
                                
                                New-UDColumn -Endpoint {
                                    New-UDButton -Text "Disable" -OnClick {
                                        $Session:DisableSSHMsg = "Disabling SSH and SSHD on $($RemoteHost.ToUpper())..."
                                        $Session:DisableSSH = $True
                                        Sync-UDElement -Id "DisableSSHMsg"
    
                                        $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            if ($(Get-Module -ListAvailable).Name -notcontains "WinSSH") {Install-Module WinSSH}
                                            if ($(Get-Module).Name -notcontains "WinSSH") {Import-Module WinSSH}
    
                                            Uninstall-WinSSH
                                        }
    
                                        Sync-UDElement -Id "SSHState"
    
                                        $Session:DisableSSH = $False
                                        Sync-UDElement -Id "DisableSSHMsg"
                                    }
                                }
                            }
                        }
                    }
                }
    
                # Edit Computer ID
                New-UDColumn -Size 6 -Endpoint {
                    $CollapsibleId = $RemoteHost + "EditComputerIDMenu"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "Edit Computer ID" -Icon laptop -Endpoint {
                            New-UDInput -SubmitText "Edit Computer" -Id "ComputerIDForm" -Content {
                                $HName = $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic.ComputerSystem.Name
                                $DName = $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic.ComputerSystem.Domain
                                $WGName = $PUDRSSyncHT."$RemoteHost`Info".Overview.ServerInventoryStatic.ComputerSystem.Workgroup
    
                                New-UDInputField -Type textbox -Name 'Change_Host_Name' -DefaultValue $HName
                                New-UDInputField -Type textbox -Name 'Join_Domain' -DefaultValue $DName
                                New-UDInputField -Type textbox -Name 'NewDomain_UserName'
                                New-UDInputField -Type textbox -Name 'NewDomain_Password'
                                New-UDInputField -Type textbox -Name 'Join_Workgroup' -DefaultValue $WGName
                            } -Endpoint {
                                param($Change_Host_Name,$Join_Domain,$NewDomain_UserName,$NewDomain_Password,$Join_Workgroup)
    
                                #region >> Check Connection
    
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                #endregion >> Check Connection
    
                                #region >> Main
    
                                $HName = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.ServerInventory[-1].ComputerSystem.Name
                                $DName = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.ServerInventory[-1].ComputerSystem.Domain
                                $WGName = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.ServerInventory[-1].ComputerSystem.Workgroup
                                $PartOfDomainCheck = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.ServerInventory[-1].ComputerSystem.PartOfDomain
                                $SetComputerIdFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Set-ComputerIdentification" -and $_ -notmatch "function Get-PUDAdminCenter"}
    
                                # Make sure that $Join_Workgroup and $Join_Domain are NOT both filled out
                                if ($($Join_Domain -and $Join_Workgroup) -or $(!$Join_Domain -and !$Join_Workgroup)) {
                                    New-UDInputAction -Toast "Please ensure that either Join_Domain or Join_Workgroup are filled out!" -Duration 10000
                                    return
                                }
    
                                #region >> ONLY Change Host Name
    
                                if ($Change_Host_Name -ne $HName -and
                                $($Join_Domain -eq $null -or $Join_Domain -eq $DName) -and
                                $($Join_Workgroup -eq $null -or $Join_Workgroup -eq $WGName)
                                ) {
                                    $SetComputerIdSplatParams = @{
                                        NewComputerName     = $Change_Host_Name
                                        Restart             = $True
                                    }
    
                                    # If the computer is on a Domain, we need DomainCreds. If not, we need LocalCreds.
                                    if ($PartOfDomainCheck) {
                                        # If we don't have DomainCreds, prompt the user for them
                                        if ($Session:CredentialHT.$RemoteHost.DomainCreds -eq $null) {
                                            New-UDInputAction -Toast "Renaming '$RemoteHost' to '$Change_Host_Name' requires Domain Credentials!" -Duration 10000
                                            New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                            return
                                        }
    
                                        # Add the -Domain aprameter to SplatParams
                                        $SetComputerIdSplatParams.Add("Domain",$DName)
    
                                        # Authorization Credentials
                                        $AuthorizationUName = $Session:CredentialHT.$RemoteHost.DomainCreds.UserName
                                        $AuthorizationPwd = $Session:CredentialHT.$RemoteHost.DomainCreds.GetNetworkCredential().Password
                                    }
                                    else {
                                        # If we don't have LocalCreds, prompt the user for them
                                        if ($Session:CredentialHT.$RemoteHost.LocalCreds -eq $null) {
                                            New-UDInputAction -Toast "Renaming '$RemoteHost' to '$Change_Host_Name' requires Local Credentials!" -Duration 10000
                                            New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                            return
                                        }
    
                                        # Authorization Credentials
                                        $AuthorizationUName = $Session:CredentialHT.$RemoteHost.LocalCreds.UserName
                                        $AuthorizationPwd = $Session:CredentialHT.$RemoteHost.LocalCreds.GetNetworkCredential().Password
                                    }
    
                                    $SetComputerIdSplatParams.Add("UserName",$AuthorizationUName)
                                    $SetComputerIdSplatParams.Add("Password",$AuthorizationPwd)
    
                                    Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                        Invoke-Expression $using:SetComputerIdFunc
    
                                        $SplatParams = $args[0]
                                        Set-ComputerIdentification @SplatParams
                                    } -ArgumentList $SetComputerIdSplatParams
                                    
                                    New-UDInputAction -Toast "Renaming '$HName' to '$Change_Host_Name' and restarting..." -Duration 10000
    
                                    # Update $PUDRSSyncHT and Redirect to /Disconnected/$Change_Host_Name because the computer is restarting...
                                    $NetworkInfoPrep = $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo
                                    $UpdatedNetworkInfoHT = @{}
                                    $NetworkInfoPrep | Get-Member -MemberType NoteProperty | foreach {
                                        $key = $_.Name
                                        $value = $NetworkInfoPrep.$key
                                        $UpdatedNetworkInfoHT.Add($key,$value)
                                    }
                                    $UpdatedNetworkInfoHT.HostName = $Change_Host_Name
                                    $UpdatedNetworkInfoHT.FQDN = $Change_Host_Name + '.' + $UpdatedNetworkInfoHT.Domain
                                    # Add [pscustomobject]$UpdatedNetworkInfoHT to $PUDRSSyncHT.RemoteHostList and remove the old entry
                                    $EntryToRemove = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}
                                    $null = $PUDRSSyncHT.RemoteHostList.Remove($EntryToRemove)
                                    $null = $PUDRSSyncHT.RemoteHostList.Add([pscustomobject]$UpdatedNetworkInfoHT)
    
                                    if ($Session:CredentialHT.$RemoteHost.LocalCreds -ne $null) {
                                        $LocalUName = $Change_Host_Name + '\' + $($Session:CredentialHT.$RemoteHost.LocalCreds.UserName -split "\\")[-1]
                                        $UpdatedLocalCreds = [pscredential]::new($LocalUName,$Session:CredentialHT.$RemoteHost.LocalCreds.Password)
                                    }
                                    else {
                                        $UpdatedLocalCreds = $null
                                    }
    
                                    if ($Session:CredentialHT.$RemoteHost.PSRemotingCredType -eq "Local") {
                                        $UpdatedPSRemotingCreds = $UpdatedLocalCreds
                                    }
                                    else {
                                        $UpdatedPSRemotingCreds = $Session:CredentialHT.$RemoteHost.PSRemotingCreds
                                    }
    
                                    $UpdatedKey = $Change_Host_Name + "Info"
                                    $UpdatedValue = @{
                                        NetworkInfo         = [pscustomobject]$UpdatedNetworkInfoHT
                                        Overview            = @{
                                            LiveDataRSInfo      = $RSSyncHash."Overview$RemoteHost`LiveDataResult"
                                            LiveDataTracker     = @{Current = $null; Previous = $null}
                                        }
                                    }
                                    foreach ($DynPage in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                        $DynPageHT = @{
                                            LiveDataRSInfo      = $null
                                            LiveDataTracker     = @{Current = $null; Previous = $null}
                                        }
                                        $UpdatedValue.Add($DynPage,$DynPageHT)
                                    }
                                    $global:PUDRSSyncHT.Add($UpdatedKey,$UpdatedValue)
    
                                    $UpdatedValue = @{
                                        DomainCreds         = $Session:CredentialHT.$RemoteHost.DomainCreds
                                        LocalCreds          = $UpdatedLocalCreds
                                        SSHCertPath         = $Session:CredentialHT.$RemoteHost.SSHCertPath
                                        PSRemotingCredType  = $Session:CredentialHT.$RemoteHost.PSRemotingCredType
                                        PSRemotingMethod    = $Session:CredentialHT.$RemoteHost.PSRemotingMethod
                                        PSRemotingCreds     = $UpdatedPSRemotingCreds
                                    }
                                    $Session:CredentialHT.$RemoteHost.Add($UpdatedKey,$UpdatedValue)
    
                                    New-UDInputAction -RedirectUrl "/Disconnected/$Change_Host_Name"
                                    return
                                }
    
                                #endregion >> ONLY Change Host Name
    
                                #region >> ONLY Join Domain
    
                                if ($($Change_Host_Name -eq $HName -or !$Change_Host_Name) -and
                                $($Join_Domain -ne $null -and $Join_Domain -ne $DName) -and
                                $($Join_Workgroup -eq $null -or $Join_Workgroup -eq $WGName)
                                ) {
                                    # Check to make sure we have $NewDomain_UserName and $NewDomain_Password
                                    if (!$NewDomain_UserName -or !$NewDomain_Password) {
                                        if (!$NewDomain_UserName) {
                                            New-UDInputAction -Toast "Joining '$Join_Domain' requires NewDomain_UserName!" -Duration 10000
    
                                        }
                                        if (!$NewDomain_Password) {
                                            New-UDInputAction -Toast "Joining '$Join_Domain' requires NewDomain_Password!" -Duration 10000
                                        }
                                        return
                                    }
    
                                    $SetComputerIdSplatParams = @{
                                        NewDomain           = $Join_Domain
                                        Restart             = $True
                                    }
    
                                    # If the computer is on a Domain, we need DomainCreds. If not, we need LocalCreds.
                                    if ($PartOfDomainCheck) {
                                        # If we don't have DomainCreds, prompt the user for them
                                        if ($Session:CredentialHT.$RemoteHost.DomainCreds -eq $null) {
                                            New-UDInputAction -Toast "Joining '$Join_Domain' requires credentials from the current Domain ($DName)!" -Duration 10000
                                            New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                            return
                                        }
    
                                        # Add the -Domain aprameter to SplatParams
                                        $SetComputerIdSplatParams.Add("Domain",$DName)
                                        $SetComputerIdSplatParams.Add("UserNameNew",$NewDomain_UserName)
                                        $SetComputerIdSplatParams.Add("PasswordNew",$NewDomain_Password)
    
                                        # Authorization Credentials
                                        $AuthorizationUName = $Session:CredentialHT.$RemoteHost.DomainCreds.UserName
                                        $AuthorizationPwd = $Session:CredentialHT.$RemoteHost.DomainCreds.GetNetworkCredential().Password
                                        $SetComputerIdSplatParams.Add("UserName",$AuthorizationUName)
                                        $SetComputerIdSplatParams.Add("Password",$AuthorizationPwd)
                                    }
                                    else {
                                        # If the $RemoteHost is not part of Domain, then our PSRemoting Credentials must be Local Credentials
                                        # but we don't really need thm for anything in particular...
                                        #$AuthorizationUName = $Session:CredentialHT.$RemoteHost."$RemoteHost`Info".PSRemotingCreds.UserName
                                        #$AuthorizationPwd = $Session:CredentialHT.$RemoteHost."$RemoteHost`Info"..PSRemotingCreds.GetNetworkCredential().Password
    
                                        # In this situation, the Set-ComputerIdentification function interprets -UserName and -Password as
                                        # the New Domain Credentials
                                        $SetComputerIdSplatParams.Add("UserName",$NewDomain_UserName)
                                        $SetComputerIdSplatParams.Add("Password",$NewDomain_Password)
                                    }
    
                                    Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                        Invoke-Expression $using:SetComputerIdFunc
    
                                        $SplatParams = $args[0]
                                        Set-ComputerIdentification @SplatParams
                                    } -ArgumentList $SetComputerIdSplatParams
                                    
                                    New-UDInputAction -Toast "Joining $RemoteHost to $Join_Domain and restarting..." -Duration 10000
    
                                    # Update $PUDRSSyncHT and Redirect to /Disconnected/$RemoteHost because the computer is restarting...
                                    $NetworkInfoPrep = $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo
                                    $UpdatedNetworkInfoHT = @{}
                                    $NetworkInfoPrep | Get-Member -MemberType NoteProperty | foreach {
                                        $key = $_.Name
                                        $value = $NetworkInfoPrep.$key
                                        $UpdatedNetworkInfoHT.Add($key,$value)
                                    }
                                    $UpdatedNetworkInfoHT.FQDN = $RemoteHost + '.' + $Join_Domain
                                    $UpdatedNetworkInfoHT.Domain = $Join_Domain
                                    # Add [pscustomobject]$UpdatedNetworkInfoHT to $PUDRSSyncHT.RemoteHostList and remove the old entry
                                    $EntryToRemove = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}
                                    $null = $PUDRSSyncHT.RemoteHostList.Remove($EntryToRemove)
                                    $null = $PUDRSSyncHT.RemoteHostList.Add([pscustomobject]$UpdatedNetworkInfoHT)
                                    $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo = [pscustomobject]$UpdatedNetworkInfoHT
    
                                    $NewDomainPwdSecureString = ConvertTo-SecureString $NewDomain_Password -AsPlainText -Force
                                    $UpdatedDomainCreds = [pscredential]::new($NewDomain_UserName,$NewDomainPwdSecureString)
                                    $Session:CredentialHT.$RemoteHost.DomainCreds = $UpdatedDomainCreds
    
                                    New-UDInputAction -RedirectUrl "/Disconnected/$RemoteHost"
                                    return
                                }
    
                                #endregion >> ONLY Join Domain
    
                                #region >> ONLY Join Workgroup
    
                                if ($($Change_Host_Name -eq $HName -or !$Change_Host_Name) -and
                                $($Join_Workgroup -ne $null -and $Join_Workgroup -ne $WGName) -and
                                $Join_Domain -eq $null
                                ) {
                                    $SetComputerIdSplatParams = @{
                                        Workgroup           = $Join_Workgroup
                                        Restart             = $True
                                    }
    
                                    # We need LocalCreds to ensure we can reestablish a PSSession after leaving the Domain
                                    if ($Session:CredentialHT.$RemoteHost.LocalCreds -eq $null) {
                                        New-UDInputAction -Toast "Joining Workgroup $Join_Workgroup requires Local Credentials!" -Duration 10000
                                        New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                        return
                                    }
    
                                    # If the computer is on a Domain, we need DomainCreds.
                                    if ($PartOfDomainCheck) {
                                        # If we don't have DomainCreds, prompt the user for them
                                        if ($Session:CredentialHT.$RemoteHost.DomainCreds -eq $null) {
                                            New-UDInputAction -Toast "Leaving the Domain $DName requires credentials from $DName!" -Duration 10000
                                            New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                            return
                                        }
    
                                        $SetComputerIdSplatParams.Add("Domain",$DName)
                                        $SetComputerIdSplatParams.Add("UserName",$Session:CredentialHT.$RemoteHost.DomainCreds.UserName)
                                        $SetComputerIdSplatParams.Add("Password",$Session:CredentialHT.$RemoteHost.DomainCreds.GetNetworkCredential().Password)
                                    }
    
                                    Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                        Invoke-Expression $using:SetComputerIdFunc
    
                                        $SplatParams = $args[0]
                                        Set-ComputerIdentification @SplatParams
                                    } -ArgumentList $SetComputerIdSplatParams
                                    
                                    New-UDInputAction -Toast "Joining Workgroup $Join_Workgroup and restarting..." -Duration 10000
    
                                    # Update $PUDRSSyncHT and Redirect to /Disconnected/$RemoteHost because the computer is restarting...
                                    $NetworkInfoPrep = $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo
                                    $UpdatedNetworkInfoHT = @{}
                                    $NetworkInfoPrep | Get-Member -MemberType NoteProperty | foreach {
                                        $key = $_.Name
                                        $value = $NetworkInfoPrep.$key
                                        $UpdatedNetworkInfoHT.Add($key,$value)
                                    }
                                    $UpdatedNetworkInfoHT.FQDN = $RemoteHost
                                    $UpdatedNetworkInfoHT.Domain = $null
                                    # Add [pscustomobject]$UpdatedNetworkInfoHT to $PUDRSSyncHT.RemoteHostList and remove the old entry
                                    $EntryToRemove = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}
                                    $null = $PUDRSSyncHT.RemoteHostList.Remove($EntryToRemove)
                                    $null = $PUDRSSyncHT.RemoteHostList.Add([pscustomobject]$UpdatedNetworkInfoHT)
                                    $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo = [pscustomobject]$UpdatedNetworkInfoHT
    
                                    New-UDInputAction -RedirectUrl "/Disconnected/$RemoteHost"
                                    return
                                }
    
                                #endregion >> ONLY Join Workgroup
    
                                #region >> Join Domain AND Rename Computer
    
                                if ($Change_Host_Name -ne $HName -and
                                $($Join_Domain -ne $null -and $Join_Domain -ne $DName) -and
                                $($Join_Workgroup -eq $null -or $Join_Workgroup -eq $WGName)
                                ) {
                                    # Check to make sure we have $NewDomain_UserName and $NewDomain_Password
                                    if (!$NewDomain_UserName -or !$NewDomain_Password) {
                                        if (!$NewDomain_UserName) {
                                            New-UDInputAction -Toast "Joining '$Join_Domain' requires NewDomain_UserName!" -Duration 10000
    
                                        }
                                        if (!$NewDomain_Password) {
                                            New-UDInputAction -Toast "Joining '$Join_Domain' requires NewDomain_Password!" -Duration 10000
                                        }
                                        return
                                    }
    
                                    $SetComputerIdSplatParams = @{
                                        NewDomain           = $Join_Domain
                                        NewComputerName     = $Change_Host_Name
                                        Restart             = $True
                                    }
    
                                    # If the computer is on a Domain, we need DomainCreds. If not, we need LocalCreds.
                                    if ($PartOfDomainCheck) {
                                        # If we don't have DomainCreds, prompt the user for them
                                        if ($Session:CredentialHT.$RemoteHost.DomainCreds -eq $null) {
                                            New-UDInputAction -Toast "Joining '$Join_Domain' requires credentials from the current Domain ($DName)!" -Duration 10000
                                            New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                            return
                                        }
    
                                        # Add the -Domain parameter to SplatParams
                                        $SetComputerIdSplatParams.Add("Domain",$DName)
                                        $SetComputerIdSplatParams.Add("UserNameNew",$NewDomain_UserName)
                                        $SetComputerIdSplatParams.Add("PasswordNew",$NewDomain_Password)
    
                                        # Authorization Credentials
                                        $AuthorizationUName = $Session:CredentialHT.$RemoteHost.DomainCreds.UserName
                                        $AuthorizationPwd = $Session:CredentialHT.$RemoteHost.DomainCreds.GetNetworkCredential().Password
                                    }
                                    else {
                                        # If we don't have LocalCreds, prompt the user for them
                                        if ($Session:CredentialHT.$RemoteHost.LocalCreds -eq $null) {
                                            New-UDInputAction -Toast "Renaming '$RemoteHost' to '$Change_Host_Name' requires Local Credentials!" -Duration 10000
                                            New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                            return
                                        }
    
                                        # Authorization Credentials
                                        $AuthorizationUName = $Session:CredentialHT.$RemoteHost.LocalCreds.UserName
                                        $AuthorizationPwd = $Session:CredentialHT.$RemoteHost.LocalCreds.GetNetworkCredential().Password
                                    }
    
                                    $SetComputerIdSplatParams.Add("UserName",$AuthorizationUName)
                                    $SetComputerIdSplatParams.Add("Password",$AuthorizationPwd)
    
                                    Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                        Invoke-Expression $using:SetComputerIdFunc
    
                                        $SplatParams = $args[0]
                                        Set-ComputerIdentification @SplatParams
                                    } -ArgumentList $SetComputerIdSplatParams
                                    
                                    New-UDInputAction -Toast "Renaming $RemoteHost to $Change_Host_Name, joining Domain $Join_Domain, and restarting..." -Duration 10000
    
                                    # Update $PUDRSSyncHT and Redirect to /Disconnected/$RemoteHost because the computer is restarting...
                                    $NetworkInfoPrep = $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo
                                    $UpdatedNetworkInfoHT = @{}
                                    $NetworkInfoPrep | Get-Member -MemberType NoteProperty | foreach {
                                        $key = $_.Name
                                        $value = $NetworkInfoPrep.$key
                                        $UpdatedNetworkInfoHT.Add($key,$value)
                                    }
                                    $UpdatedNetworkInfoHT.HostName = $Change_Host_Name
                                    $UpdatedNetworkInfoHT.FQDN = $Change_Host_Name + '.' + $Join_Domain
                                    $UpdatedNetworkInfoHT.Domain = $Join_Domain
                                    # Add [pscustomobject]$UpdatedNetworkInfoHT to $PUDRSSyncHT.RemoteHostList and remove the old entry
                                    $EntryToRemove = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}
                                    $null = $PUDRSSyncHT.RemoteHostList.Remove($EntryToRemove)
                                    $null = $PUDRSSyncHT.RemoteHostList.Add([pscustomobject]$UpdatedNetworkInfoHT)
                                    $PUDRSSyncHT."$Change_Host_Name`Info".NetworkInfo = [pscustomobject]$UpdatedNetworkInfoHT
    
                                    $NewDomainPwdSecureString = ConvertTo-SecureString $NewDomain_Password -AsPlainText -Force
                                    $UpdatedDomainCreds = [pscredential]::new($NewDomain_UserName,$NewDomainPwdSecureString)
                                    $Session:CredentialHT.$RemoteHost.DomainCreds = $UpdatedDomainCreds
    
                                    New-UDInputAction -RedirectUrl "/Disconnected/$Change_Host_Name"
                                    return
                                }
    
                                #endregion >> Join Domain AND Rename Computer
    
                                #region >> Join Workgroup AND Rename Computer
    
                                if ($Change_Host_Name -ne $HName -and
                                $($Join_Workgroup -ne $null -and $Join_Workgroup -ne $WGName) -and
                                $Join_Domain -eq $null
                                ) {
                                    $SetComputerIdSplatParams = @{
                                        Workgroup           = $Join_Workgroup
                                        NewComputerName     = $Change_Host_Name
                                        Restart             = $True
                                    }
    
                                    # We need LocalCreds regardless
                                    if ($Session:CredentialHT.$RemoteHost.LocalCreds -eq $null) {
                                        New-UDInputAction -Toast "Renaming '$RemoteHost' to '$Change_Host_Name' requires Local Credentials!" -Duration 10000
                                        New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                        return
                                    }
    
                                    # If the computer is on a Domain, we need DomainCreds to leave it.
                                    if ($PartOfDomainCheck) {
                                        # If we don't have DomainCreds, prompt the user for them
                                        if ($Session:CredentialHT.$RemoteHost.DomainCreds -eq $null) {
                                            New-UDInputAction -Toast "Joining '$Join_Domain' requires credentials from the current Domain ($DName)!" -Duration 10000
                                            New-UDInputAction -RedirectUrl "/PSRemotingCreds/$RemoteHost"
                                            return
                                        }
    
                                        # Add the -Domain parameter to SplatParams
                                        $SetComputerIdSplatParams.Add("Domain",$DName)
    
                                        # Authorization Credentials
                                        $AuthorizationUName = $Session:CredentialHT.$RemoteHost.DomainCreds.UserName
                                        $AuthorizationPwd = $Session:CredentialHT.$RemoteHost.DomainCreds.GetNetworkCredential().Password
                                    }
                                    else {
                                        # Authorization Credentials
                                        $AuthorizationUName = $Session:CredentialHT.$RemoteHost.LocalCreds.UserName
                                        $AuthorizationPwd = $Session:CredentialHT.$RemoteHost.LocalCreds.GetNetworkCredential().Password
                                    }
    
                                    $SetComputerIdSplatParams.Add("UserName",$AuthorizationUName)
                                    $SetComputerIdSplatParams.Add("Password",$AuthorizationPwd)
    
                                    Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                        Invoke-Expression $using:SetComputerIdFunc
    
                                        $SplatParams = $args[0]
                                        Set-ComputerIdentification @SplatParams
                                    } -ArgumentList $SetComputerIdSplatParams
                                    
                                    New-UDInputAction -Toast "Renaming $RemoteHost to $Change_Host_Name, joining Workgroup $Join_Workgroup, and restarting..." -Duration 10000
    
                                    # Update $PUDRSSyncHT and Redirect to /Disconnected/$RemoteHost because the computer is restarting...
                                    $NetworkInfoPrep = $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo
                                    $UpdatedNetworkInfoHT = @{}
                                    $NetworkInfoPrep | Get-Member -MemberType NoteProperty | foreach {
                                        $key = $_.Name
                                        $value = $NetworkInfoPrep.$key
                                        $UpdatedNetworkInfoHT.Add($key,$value)
                                    }
                                    $UpdatedNetworkInfoHT.HostName = $Change_Host_Name
                                    $UpdatedNetworkInfoHT.FQDN = $Change_Host_Name
                                    $UpdatedNetworkInfoHT.Domain = $null
                                    # Add [pscustomobject]$UpdatedNetworkInfoHT to $PUDRSSyncHT.RemoteHostList and remove the old entry
                                    $EntryToRemove = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}
                                    $null = $PUDRSSyncHT.RemoteHostList.Remove($EntryToRemove)
                                    $null = $PUDRSSyncHT.RemoteHostList.Add([pscustomobject]$UpdatedNetworkInfoHT)
                                    $PUDRSSyncHT."$Change_Host_Name`Info".NetworkInfo = [pscustomobject]$UpdatedNetworkInfoHT
    
                                    New-UDInputAction -RedirectUrl "/Disconnected/$Change_Host_Name"
                                    return
                                }
    
                                #endregion >> Join Workgroup AND Rename Computer
    
                                #endregion >> Main
                            }
                        }
                    }
                }
            }
    
            New-UDRow -Endpoint {
                # Edit Environment Variables
                New-UDColumn -Size 12 -Endpoint {
                    $CollapsibleId = $RemoteHost + "Environment Variables"
                    New-UDCollapsible -Id $CollapsibleId -Items {
                        New-UDCollapsibleItem -Title "Environment Variables" -Icon laptop -Endpoint {
                            New-UDRow -Endpoint {
                                New-UDColumn -Size 12 -Endpoint {
                                    $EnvVarsUdGridSplatParams = @{
                                        Title           = "Environment Variables"
                                        Id              = "EnvVarsGrid"
                                        Headers         = @("Type","Name","Value")
                                        Properties      = @("Type","Name","Value")
                                        PageSize        = 10
                                    }
                                    New-UdGrid @EnvVarsUdGridSplatParams -Endpoint {
                                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                        $GetEnvVarsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-EnvironmentVariables" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:GetEnvVarsFunc
                                            
                                            $EnvVars = Get-EnvironmentVariables
                                            
                                            [pscustomobject]@{
                                                EnvironmentVariables        = [pscustomobject]$EnvVars
                                            }
                                        }
                                        $Session:EnvironmentVariablesStatic = $StaticInfo.EnvironmentVariables
                                        if ($PUDRSSyncHT."$RemoteHost`Info".Overview.Keys -notcontains "EnvironmentVariablesStatic") {
                                            $PUDRSSyncHT."$RemoteHost`Info".Overview.Add("EnvironmentVariablesStatic",$Session:EnvironmentVariablesStatic)
                                        }
                                        else {
                                            $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvironmentVariablesStatic = $Session:EnvironmentVariablesStatic
                                        }
    
                                        $Session:EnvironmentVariablesStatic | Out-UDGridData
                                    }
                                }
                            }
    
                            New-UDRow -Endpoint {
                                New-UDColumn -Size 4 -Endpoint {
                                    New-UDHeading -Text "New Environment Variable" -Size 5
                                    
                                    New-UDTextbox -Id "EnvVarNameA" -Label "Name"
                                    New-UDTextbox -Id "EnvVarValueA" -Label "Value"
                                    New-UDSelect -Id "EnvVarTypeA" -Label "Type" -Option {
                                        New-UDSelectOption -Name "User" -Value "User" -Selected
                                        New-UDSelectOption -Name "Machine" -Value "Machine"
                                    }
                                    
                                    New-UDButton -Text "New" -OnClick {
                                        $EnvVarNameTextBox = Get-UDElement -Id "EnvVarNameA"
                                        $EnvVarValueTextBox = Get-UDElement -Id "EnvVarValueA"
                                        $EnvVarTypeSelection = Get-UDElement -Id "EnvVarTypeA"
    
                                        $EnvVarName = $EnvVarNameTextBox.Attributes['value']
                                        $EnvVarValue = $EnvVarValueTextBox.Attributes['value']
                                        $EnvVarType = $($EnvVarTypeSelection.Content | foreach {
                                            $_.ToString() | ConvertFrom-Json
                                        } | Where-Object {$_.attributes.selected.isPresent}).attributes.value
    
                                        <#
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.Add("EnvVarInfo",@{})
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("EnvVarTypeObject",$EnvVarTypeSelection)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("EnvVarName",$EnvVarName)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("EnvVarNewName",$EnvVarNewName)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("EnvVarValue",$EnvVarValue)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("EnvVarType",$EnvVarType)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("RemoteHost",$RemoteHost)
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.EnvVarInfo.Add("CredsUserName",$($Session:CredentialHT.$RemoteHost.PSRemotingCreds.UserName))
                                        #>
    
                                        $NewEnvVarFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function New-EnvironmentVariable" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:NewEnvVarFunc
                                            New-EnvironmentVariable -name $using:EnvVarName -value $using:EnvVarValue -type $using:EnvVarType
                                        }
    
                                        Sync-UDElement -Id "EnvVarsGrid"
                                    }
                                }
                                New-UDColumn -Size 4 -Endpoint {
                                    New-UDHeading -Text "Edit Environment Variable" -Size 5
                                    
                                    New-UDTextbox -Id "EnvVarNameB" -Label "Name"
                                    New-UDTextbox -Id "EnvVarNewNameB" -Label "New Name"
                                    New-UDTextbox -Id "EnvVarValueB" -Label "Value"
                                    New-UDSelect -Id "EnvVarTypeB" -Label "Type" -Option {
                                        New-UDSelectOption -Name "User" -Value "User" -Selected
                                        New-UDSelectOption -Name "Machine" -Value "Machine"
                                    }
    
                                    New-UDButton -Text "Edit" -OnClick {
                                        $EnvVarNameTextBox = Get-UDElement -Id "EnvVarNameB"
                                        $EnvVarNewNameTextBox = Get-UDElement -Id "EnvVarNewNameB"
                                        $EnvVarValueTextBox = Get-UDElement -Id "EnvVarValueB"
                                        $EnvVarTypeSelection = Get-UDElement -Id "EnvVarTypeB"
    
                                        $EnvVarName = $EnvVarNameTextBox.Attributes['value']
                                        $EnvVarNewName = $EnvVarNewNameTextBox.Attributes['value']
                                        $EnvVarValue = $EnvVarValueTextBox.Attributes['value']
                                        $EnvVarType = $($EnvVarTypeSelection.Content | foreach {
                                            $_.ToString() | ConvertFrom-Json
                                        } | Where-Object {$_.attributes.selected.isPresent}).attributes.value
    
                                        $SetEnvVarFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Set-EnvironmentVariable" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $SetEnvVarSplatParams = @{
                                            oldName     = $EnvVarName
                                            type        = $EnvVarType
                                        }
                                        if ($EnvVarValue) {
                                            $SetEnvVarSplatParams.Add("value",$EnvVarValue)
                                        }
                                        if ($EnvVarNewName) {
                                            $SetEnvVarSplatParams.Add("newName",$EnvVarNewName)
                                        }
                                        else {
                                            $SetEnvVarSplatParams.Add("newName",$EnvVarName)
                                        }
    
                                        # NOTE: Set-EnvironmentVariable outputs @{Status = "Succcess"} otherwise, Error
                                        $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:SetEnvVarFunc
                                            $SplatParams = $args[0]
                                            Set-EnvironmentVariable @SplatParams
                                        } -ArgumentList $SetEnvVarSplatParams
                                        
                                        Sync-UDElement -Id "EnvVarsGrid"
                                    }
                                }
                                New-UDColumn -Size 4 -Endpoint {
                                    New-UDHeading -Text "Remove Environment Variable" -Size 5
                                    
                                    New-UDTextbox -Id "EnvVarNameC" -Label "Name"
                                    New-UDSelect -Id "EnvVarTypeC" -Label "Type" -Option {
                                        New-UDSelectOption -Name "User" -Value "User" -Selected
                                        New-UDSelectOption -Name "Machine" -Value "Machine"
                                    }
    
                                    New-UDButton -Text "Remove" -OnClick {
                                        $EnvVarNameTextBox = Get-UDElement -Id "EnvVarNameC"
                                        $EnvVarTypeSelection = Get-UDElement -Id "EnvVarTypeC"
    
                                        $EnvVarName = $EnvVarNameTextBox.Attributes['value']
                                        $EnvVarType = $($EnvVarTypeSelection.Content | foreach {
                                            $_.ToString() | ConvertFrom-Json
                                        } | Where-Object {$_.attributes.selected.isPresent}).attributes.value
    
                                        $RemoveEnvVarFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Remove-EnvironmentVariable" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                        $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                            Invoke-Expression $using:RemoveEnvVarFunc
                                            Remove-EnvironmentVariable -name $using:EnvVarName -type $using:EnvVarType
                                        }
                                        
                                        Sync-UDElement -Id "EnvVarsGrid"
                                    }
                                }
                            }
                            
                            <#
                            New-UDRow -Endpoint {
                                New-UDColumn -Size 4 -Endpoint {
                                    New-UDInput -Title "New Environment Variable" -SubmitText "Add" -Content {
                                        New-UDInputField -Name "Name" -Type textbox
                                        New-UDInputField -Name "Value" -Type textbox
                                        New-UDInputField -Name "Type" -Type select -Values @("User","Machine") -DefaultValue "User"
                                    } -Endpoint {
                                        param($Name,$Value,$Type)
    
                                        #region >> Check Connection
    
                                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                        $NewEnvVarFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function New-EnvironmentVariable" -and $_ -notmatch "function Get-PUDAdminCenter"}
    
                                        #endregion >> Check Connection
    
                                        #region >> SubMain
    
                                        if (!$Name) {
                                            New-UDInputAction -Toast "You must fill out the 'Name' field to indicate the name of the Environment Variable you would like to Add." -Duration 10000
                                            return
                                        }
    
                                        try {
                                            # NOTE: New-EnvironmentVariable does not output anything
                                            $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                $using:NewEnvVarFunc
    
                                                New-EnvironmentVariable -name $using:Name -value $using:Value -type $using:Type
                                            }
    
                                            New-UDInputAction -Toast "New $Type Environment Variable $Name was successfully created. Please refresh the page to view updates in the Environment Variable Grid." -Duration 2000
                                        }
                                        catch {
                                            New-UDInputAction -Toast $_.Exception.Message -Duration 2000
                                        }
                                        Start-Sleep -Seconds 2
    
                                        # Reload the page
                                        Invoke-UDRedirect -Url "/Overview/$RemoteHost"
    
                                        #endregion >> SubMain
                                    }
                                }
                                
                                New-UDColumn -Size 4 -Endpoint {
                                    New-UDInput -Title "Remove Environment Variable" -SubmitText "Remove" -Content {
                                        New-UDInputField -Name "Name" -Type textbox
                                        New-UDInputField -Name "Type" -Type select -Values @("User","Machine") -DefaultValue "User"
                                    } -Endpoint {
                                        param($Name,$Type)
    
                                        #region >> Check Connection
    
                                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                        $NewEnvVarFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function New-EnvironmentVariable" -and $_ -notmatch "function Get-PUDAdminCenter"}
    
                                        #endregion >> Check Connection
    
                                        #region >> SubMain
    
                                        if (!$Name) {
                                            New-UDInputAction -Toast "You must fill out the 'Name' field to indicate which existing Environment Variable you would like to Remove." -Duration 10000
                                            return
                                        }
    
                                        try {
                                            # NOTE: Remove-EnvironmentVariable does not output anything
                                            $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                Invoke-Expression $using:RemoveEnvVarFunc
    
                                                Remove-EnvironmentVariable -name $using:Name -type $using:Type
                                            }
    
                                            New-UDInputAction -Toast "Removed $Type Environment Variable $Name successfully. Please refresh the page to view updates in the Environment Variable Grid." -Duration 2000
                                        }
                                        catch {
                                            New-UDInputAction -Toast $_.Exception.Message -Duration 2000
                                        }
                                        Start-Sleep -Seconds 2
    
                                        # Reload the page
                                        Invoke-UDRedirect -Url "/Overview/$RemoteHost"
    
                                        #endregion >> SubMain
                                    }
                                }
    
                                New-UDColumn -Size 4 -Endpoint {
                                    New-UDInput -Title "Edit Environment Variable" -SubmitText "Edit" -Content {
                                        New-UDInputField -Name "Name" -Type textbox
                                        New-UDInputField -Name "NewName" -Type textbox
                                        New-UDInputField -Name "Value" -Type textbox
                                        New-UDInputField -Name "Type" -Type select -Values @("User","Machine") -DefaultValue "User"
                                    } -Endpoint {
                                        param($Name,$NewName,$Value,$Type)
    
                                        #region >> Check Connection
    
                                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                        $NewEnvVarFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function New-EnvironmentVariable" -and $_ -notmatch "function Get-PUDAdminCenter"}
    
                                        #endregion >> Check Connection
    
                                        #region >> SubMain
    
                                        if (!$Name) {
                                            New-UDInputAction -Toast "You must fill out the 'Name' field to indicate which existing Environment Variable you would like to Edit." -Duration 10000
                                            return
                                        }
    
                                        $SetEnvVarSplatParams = @{
                                            oldName     = $Name
                                            type        = $Type
                                        }
                                        if ($Value) {
                                            $SetEnvVarSplatParams.Add("value",$Value)
                                        }
                                        if ($NewName) {
                                            $SetEnvVarSplatParams.Add("newName",$NewName)
                                        }
                                        else {
                                            $SetEnvVarSplatParams.Add("newName",$Name)
                                        }
    
                                        try {
                                            # NOTE: Set-EnvironmentVariable outputs @{Status = "Succcess"} otherwise, Error
                                            $null = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                Invoke-Expression $using:SetEnvVarFunc
    
                                                $SplatParams = $args[0]
                                                Set-EnvironmentVariable @SplatParams
                                            } -ArgumentList $SetEnvVarSplatParams
    
                                            New-UDInputAction -Toast "Successfully edited Environment Variable. Please refresh the page to view updates in the Environment Variable Grid." -Duration 2000
                                            
                                        }
                                        catch {
                                            New-UDInputAction -Toast $_.Exception.Message -Duration 2000
                                        }
                                        Start-Sleep -Seconds 2
    
                                        # Reload the page
                                        Invoke-UDRedirect -Url "/Overview/$RemoteHost"
    
                                        #endregion >> SubMain
                                    }
                                }
                            }
                            #>
                            #endregion >> Main
                        }
                    }
                }
            }
    
            #endregion >> Controls
    
            #region >> Summary Info
    
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Endpoint {
                    #region >> Check Connection
    
                    $PUDRSSyncHT = $global:PUDRSSyncHT
    
                    # Load PUDAdminCenter Module Functions Within ScriptBlock
                    $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                    $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                    #endregion >> Check Connection
    
                    New-UDHeading -Text "Summary" -Size 4
    
                    # Summary A
                    $SummaryInfoAGridProperties = @("Computer_Name","Domain","Operating_System","Version","Installed_Memory")
    
                    $SummaryInfoAGridEndpoint = {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $SrvInv = $Session:ServerInventoryStatic
    
                        [pscustomobject]@{
                            Computer_Name       = $SrvInv.ComputerSystem.Name
                            Domain              = $SrvInv.ComputerSystem.Domain
                            Operating_System    = $SrvInv.OperatingSystem.Caption
                            Version             = $SrvInv.OperatingSystem.Version
                            Installed_Memory    = [Math]::Round($SrvInv.ComputerSystem.TotalPhysicalMemory / 1GB).ToString() + " GB"
                        } | Out-UDTableData -Property $SummaryInfoAGridProperties
                    }
                    $SummaryInfoAUdGridSplatParams = @{
                        Id              = "SummaryInfoA"
                        Headers         = $SummaryInfoAGridProperties
                        Endpoint        = $SummaryInfoAGridEndpoint
                    }
                    New-UdTable @SummaryInfoAUdGridSplatParams
    
                    # Summary B
                    $SummaryInfoBGridProperties = @("C_DiskSpace_FreeVsTotal","Processors","Manufacturer","Model","Logical_Processors")
                    
                    $SummaryBInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                        $CimDiskResult = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
                        $CimDiskOutput = [Math]::Round($CimDiskResult.FreeSpace / 1GB).ToString() + "GB" +
                        ' / ' + [Math]::Round($CimDiskResult.Size / 1GB).ToString() + "GB"
    
                        $ProcessorsPrep = $($(
                            Get-CimInstance Win32_Processor | foreach {
                                $_.Name.Trim() + $_.Caption.Trim()
                            }
                        ) -replace "[\s]+"," ") | foreach {
                            $($_ -split "[0-9]GHz")[0] + "GHz"
                        }
                        $Processors = $ProcessorsPrep -join " | "
    
                        [pscustomobject]@{
                            ProcessorInfo       = $Processors
                            CimDiskInfo         = $CimDiskOutput
                        }
                    }
    
                    $SummaryInfoBGridEndpoint = {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $SrvInv = $Session:ServerInventoryStatic
    
                        [pscustomobject]@{
                            C_DiskSpace_FreeVsTotal     = $SummaryBInfo.CimDiskInfo
                            Processors                  = $SummaryBInfo.ProcessorInfo
                            Manufacturer                = $SrvInv.ComputerSystem.Manufacturer
                            Model                       = $SrvInv.ComputerSystem.Model
                            Logical_Processors          = $SrvInv.ComputerSystem.NumberOfLogicalProcessors.ToString()
                        } | Out-UDTableData -Property $SummaryInfoBGridProperties
                    }
                    $SummaryInfoBUdGridSplatParams = @{
                        Id              = "SummaryInfoB"
                        Headers         = $SummaryInfoBGridProperties
                        Endpoint        = $SummaryInfoBGridEndpoint
                    }
                    New-UdTable @SummaryInfoBUdGridSplatParams
    
                    # Summary C
                    $SummaryCInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                        $using:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                        
                        $DefenderInfo = Get-MpComputerStatus
                        $NicCount = $([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() | Where-Object {
                            $_.NetworkInterfaceType -eq "Ethernet"
                        }).Count
                        $GetLocalUsersInfo = Get-LocalUsers
    
                        [pscustomobject]@{
                            RealTimeProtectionStatus    = $DefenderInfo.RealTimeProtectionEnabled
                            NicCount                    = $NicCount
                            LocalUserCount              = $GetLocalUsersInfo.Count
                        }
                    }
                    
                    $SummaryInfoCGridProperties = @("Windows_Defender","NICs","Uptime","LocalUserCount")
    
                    $SummaryInfoCGridEndpoint = {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $UptimeLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                        if ($UptimeLiveOutputCount -gt 0) {
                            # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                            # being added/removed from the ArrayList, things break
                            #$UptimeLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
    
                            $ArrayOfUptimeEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.Uptime
                            ) | Where-Object {$_ -ne $null}
                        }
    
                        if ($ArrayOfUptimeEntries.Count -eq 0) {
                            $FinalUptime = "00:00:00:00"
                        }
                        else {
                            $FinalUptime = $ArrayOfUptimeEntries[-1]
    
                            if ($($FinalUptime | Get-Member -Type Method).Name -contains "LastIndexOf" -and $FinalUptime -match "\.") {
                                $FinalUptime = $FinalUptime.Substring(0,$FinalUptime.LastIndexOf('.'))
                            }
                            else {
                                $FinalUptime = "00:00:00:00"
                            }
                        }
    
                        [pscustomobject]@{
                            Windows_Defender    = if ($SummaryCInfo.RealTimeProtectionStatus) {"Real-time protection: On"} else {"Real-time protection: Off"}
                            NICs                = $SummaryCInfo.NicCount
                            Uptime              = $FinalUptime
                            LocalUserCount      = $SummaryCInfo.LocalUserCount
                        } | Out-UDTableData -Property $SummaryInfoCGridProperties
                    }
                    $SummaryInfoCUdGridSplatParams = @{
                        Id              = "SummaryInfoC"
                        Headers         = $SummaryInfoCGridProperties
                        AutoRefresh     = $True
                        RefreshInterval = 2
                        Endpoint        = $SummaryInfoCGridEndpoint
                    }
                    New-UdTable @SummaryInfoCUdGridSplatParams
                }
            }
    
            #endregion >> Summary Info
    
            #region >> Monitors
    
            # CPU Utilization and Memory Usage
            New-UDRow -Columns {
                New-UDHeading -Text "Processor (CPU) and Memory (RAM) Info" -Size 4
                New-UDColumn -Size 6 -Endpoint {
                    $CPUTableProperties =@("CPU_Utilization","ClockSpeed","Processes","Threads","Handles")
                    New-UDTable -Id "CPUTable" -Headers $CPUTableProperties -AutoRefresh -RefreshInterval 5 -Endpoint {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $CPULiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                        if ($CPULiveOutputCount -gt 0) {
                            # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                            # being added/removed from the ArrayList, things break
                            #$CPULiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
    
                            $ArrayOfCPUPctEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.CPUPct
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfCPUPctEntries.Count -gt 0) {
                                $LatestCPUPctEntry = $ArrayOfCPUPctEntries[-1]
                            }
    
                            $ArrayOfClockSpeedEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.ClockSpeed
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfClockSpeedEntries.Count -gt 0) {
                                $LatestClockSpeedEntry = $ArrayOfClockSpeedEntries[-1]
                            }
    
                            $ArrayOfProcessesCountEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.ProcessesCount
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfProcessesCountEntries.Count -gt 0) {
                                $LatestProcessesEntry = $ArrayOfProcessesCountEntries[-1]
                            }
    
                            $ArrayOfHandlesCountEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.HandlesCount
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfHandlesCountEntries.Count -gt 0) {
                                $LatestHandlesEntry = $ArrayOfHandlesCountEntries[-1]
                            }
    
                            $ArrayOfThreadsCountEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.ThreadsCount
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfThreadsCountEntries.Count -gt 0) {
                                $LatestThreadsEntry = $ArrayOfThreadsCountEntries[-1]
                            }
                        }
    
                        $FinalCPUPct = if (!$LatestCPUPctEntry) {"0"} else {$LatestCPUPctEntry.ToString() + '%'}
                        $FinalSpeed = if (!$LatestClockSpeedEntry) {"0"} else {$LatestClockSpeedEntry.ToString() + 'GHz'}
                        $FinalProcesses = if (!$LatestProcessesEntry) {"0"} else {$LatestProcessesEntry}
                        $FinalHandles = if (!$LatestHandlesEntry) {"0"} else {$LatestHandlesEntry}
                        $FinalThreads = if (!$LatestThreadsEntry) {"0"} else {$LatestThreadsEntry}
    
                        [pscustomobject]@{
                            CPU_Utilization     = $FinalCPUPct
                            ClockSpeed          = $FinalSpeed
                            Processes           = $FinalProcesses
                            Threads             = $FinalThreads
                            Handles             = $FinalHandles
                        } | Out-UDTableData -Property $CPUTableProperties
                    }
    
                    $CPUMonitorEndpoint = {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $CPULiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                        if ($CPULiveOutputCount -gt 0) {
                            # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                            # being added/removed from the ArrayList, things break
                            #$CPULiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
    
                            $ArrayOfCPUPctEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.CPUPct
                                ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfCPUPctEntries.Count -gt 0) {
                                $LatestCPUPctEntry = $ArrayOfCPUPctEntries[-1]
                            }
                        }
    
                        $FinalCPUPct = if (!$LatestCPUPctEntry) {"0"} else {$LatestCPUPctEntry}
    
                        $FinalCPUPct | Out-UDMonitorData
                    }
    
                    $CPUMonitorSplatParams = @{
                        Title                   = "CPU Utilization %"
                        Type                    = "Line"
                        DataPointHistory        = 20
                        ChartBackgroundColor    = "#80FF6B63"
                        ChartBorderColor        = "#FFFF6B63"
                        AutoRefresh             = $True
                        RefreshInterval         = 5
                        Endpoint                = $CPUMonitorEndpoint
                    }
                    New-UdMonitor @CPUMonitorSplatParams
                }
                New-UDColumn -Size 6 -Endpoint {
                    #New-UDHeading -Text "Memory (RAM) Info" -Size 4
                    #$RamTableProperties = @("RAM_Utilization","Total","InUse","Available","Committed","Cached","PagedPool","NonPagedPool")
                    $RamTableProperties = @("RAM_Utilization","Total","InUse","Available","Committed","Cached")
                    New-UDTable -Id "RamTable" -Headers $RamTableProperties -AutoRefresh -RefreshInterval 5 -Endpoint {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $RamLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                        if ($RamLiveOutputCount -gt 0) {
                            # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                            # being added/removed from the ArrayList, things break
                            #$RamLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
    
                            $ArrayOfRamPctEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamPct
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamPctEntries.Count -gt 0) {
                                $LatestRamPctEntry = $ArrayOfRamPctEntries[-1]
                            }
    
                            $ArrayOfRamTotalGBEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamTotalGB
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamTotalGBEntries.Count -gt 0) {
                                $LatestRamTotalGBEntry = $ArrayOfRamTotalGBEntries[-1]
                            }
                            
                            $ArrayOfRamInUseGBEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamInUseGB
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamInUseGBEntries.Count -gt 0) {
                                $LatestRamInUseGBEntry = $ArrayOfRamInUseGBEntries[-1]
                            }
    
                            $ArrayOfRamFreeGBEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamFreeGB
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamFreeGBEntries.Count -gt 0) {
                                $LatestRamFreeGBEntry = $ArrayOfRamFreeGBEntries[-1]
                            }
    
                            $ArrayOfRamCommittedGBEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamCommittedGB
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamCommittedGBEntries.Count -gt 0) {
                                $LatestRamCommittedGBEntry = $ArrayOfRamCommittedGBEntries[-1]
                            }
    
                            $ArrayOfRamCachedGBEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamCachedGB
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamCachedGBEntries.Count -gt 0) {
                                $LatestRamCachedGBEntry = $ArrayOfRamCachedGBEntries[-1]
                            }
    
                            $ArrayOfRamPagedPoolMBEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamPagedPoolMB
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamPagedPoolMBEntries.Count -gt 0) {
                                $LatestRamPagedPoolMBEntry = $ArrayOfRamPagedPoolMBEntries[-1]
                            }
    
                            $ArrayOfRamNonPagedPoolMBEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamNonPagedPoolMB
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamNonPagedPoolMBEntries.Count -gt 0) {
                                $LatestRamNonPagedPoolMBEntry = $ArrayOfRamNonPagedPoolMBEntries[-1]
                            }
                        }
    
                        $FinalRamPct = if (!$LatestRamPctEntry) {"0"} else {$LatestRamPctEntry.ToString() + '%'}
                        $FinalRamTotalGB = if (!$LatestRamTotalGBEntry) {"0"} else {$LatestRamTotalGBEntry.ToString() + 'GB'}
                        $FinalRamInUseGB = if (!$LatestRamInUseGBEntry) {"0"} else {$LatestRamInUseGBEntry.ToString() + 'GB'}
                        $FinalRamFreeGB = if (!$LatestRamFreeGBEntry) {"0"} else {$LatestRamFreeGBEntry.ToString() + 'GB'}
                        $FinalRamCommittedGB = if (!$LatestRamCommittedGBEntry) {"0"} else {$LatestRamCommittedGBEntry.ToString() + 'GB'}
                        $FinalRamCachedGB = if (!$LatestRamCachedGBEntry) {"0"} else {$LatestRamCachedGBEntry.ToString() + 'GB'}
                        $FinalRamPagedPoolMB = if (!$LatestRamPagedPoolMBEntry) {"0"} else {$LatestRamPagedPoolMBEntry.ToString() + 'MB'}
                        $FinalRamNonPagedPoolMB = if (!$LatestRamNonPagedPoolMBEntry) {"0"} else {$LatestRamNonPagedPoolMBEntry.ToString() + 'MB'}
                        
                        [pscustomobject]@{
                            RAM_Utilization     = $FinalRamPct
                            Total               = $FinalRamTotalGB
                            InUse               = $FinalRamInUseGB
                            Available           = $FinalRamFreeGB
                            Committed           = $FinalRamCommittedGB
                            Cached              = $FinalRamCachedGB
                            #PagedPool           = $FinalRamPagedPoolMB
                            #NonPagedPool        = $FinalRamNonPagedPoolMB
                        } | Out-UDTableData -Property $RamTableProperties
                    }
    
                    $RamMonitorEndpoint = {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $RamLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                        if ($RamLiveOutputCount -gt 0) {
                            # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                            # being added/removed from the ArrayList, things break
                            #$RamLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                            
                            $ArrayOfRamPctEntries = @(
                                $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.RamPct
                            ) | Where-Object {$_ -ne $null}
                            if ($ArrayOfRamPctEntries.Count -gt 0) {
                                $LatestRamPctEntry = $ArrayOfRamPctEntries[-1]
                            }
                        }
    
                        $FinalRamPct = if (!$LatestRamPctEntry) {"0"} else {$LatestRamPctEntry}
    
                        $FinalRamPct | Out-UDMonitorData
                    }
    
                    $RAMMonitorSplatParams = @{
                        Title                   = "Memory (RAM) Utilization %"
                        Type                    = "Line"
                        DataPointHistory        = 20
                        ChartBackgroundColor    = "#80FF6B63"
                        ChartBorderColor        = "#FFFF6B63"
                        AutoRefresh             = $True
                        RefreshInterval         = 5
                        Endpoint                = $RamMonitorEndpoint
                    }
                    New-UdMonitor @RAMMonitorSplatParams
                }
            }
    
            # Network Statistics
    
            if (@($PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces).Count -eq 1) {
                New-UDRow -Columns {
                    New-UDHeading -Text "Network Interface Info" -Size 4
                    New-UDColumn -Size 6 -Endpoint {
                        $NetworkTableProperties = @("Name","Description","Sent","Received","DeltaSent","DeltaReceived")
                        New-UDTable -Headers $NetworkTableProperties -AutoRefresh -RefreshInterval 5 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
                            #$ThisNetworkInterfaceStaticInfo = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces
    
                            #$NetworkLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                            if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                                # being added/removed from the ArrayList, things break
                                #$NetworkLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                                
                                # NOTE: Each element in the below $ArrayOfNetworkEntries is an ArrayList of PSCustomObjects.
                                # Each PSCustomObject contains:
                                
                                #[pscustomobject]@{
                                #    Name                = $NetInt.Name
                                #    Description         = $NetInt.Description
                                #    TotalSentBytes      = $IPv4Stats.BytesSent
                                #    TotalReceivedBytes  = $IPv4Stats.BytesReceived
                                #}
                                
                                $ArrayOfNetworkEntriesA = @(
                                    $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.NetStats
                                ) | Where-Object {$_ -ne $null}
                                if ($ArrayOfNetworkEntriesA.Count -gt 0) {
                                    $PreviousNetworkEntryA = $ArrayOfNetworkEntriesA[-2]
                                    $LatestNetworkEntryA = $ArrayOfNetworkEntriesA[-1]
                                }
                            }
    
                            #$PreviousSentBytesTotalA = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalSentBytes
                            $PreviousSentBytesTotalA = $PreviousNetworkEntryA.TotalSentBytes
                            $NewSentBytesTotalA = $LatestNetworkEntryA.TotalSentBytes
                            $DifferenceSentBytesA = $NewSentBytesTotalA - $PreviousSentBytesTotalA
                            if ($DifferenceSentBytesA -le 0) {
                                $FinalKBSentA = 0
                            }
                            else {
                                $FinalKBSentA = [Math]::Round($($DifferenceSentBytesA / 1KB),2).ToString() + 'KB'
                            }
                            #$FinalKBSentA = [Math]::Round($($DifferenceSentBytesA / 1KB),2).ToString() + 'KB'
    
                            #$PreviousReceivedBytesTotalA = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalReceivedBytes
                            $PreviousReceivedBytesTotalA = $PreviousNetworkEntryA.TotalReceivedBytes
                            $NewReceivedBytesTotalA = $LatestNetworkEntryA.TotalReceivedBytes
                            $DifferenceReceivedBytesA = $NewReceivedBytesTotalA - $PreviousReceivedBytesTotalA
                            if ($DifferenceReceivedBytesA -le 0) {
                                $FinalKBReceivedA = 0
                            }
                            else {
                                $FinalKBReceivedA = [Math]::Round($($DifferenceReceivedBytesA / 1KB),2).ToString() + 'KB'
                            }
                            #$FinalKBReceivedA = [Math]::Round($($DifferenceReceivedBytesA / 1KB),2).ToString() + 'KB'
    
                            [pscustomobject]@{
                                Name                        = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces.Name
                                Description                 = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces.Description
                                Sent                        = [Math]::Round($($NewSentBytesTotalA / 1GB),2).ToString() + 'GB'
                                Received                    = [Math]::Round($($NewReceivedBytesTotalA / 1GB),2).ToString() + 'GB'
                                DeltaSent                   = $FinalKBSentA
                                DeltaReceived               = $FinalKBReceivedA
    
                            } | Out-UDTableData -Property $NetworkTableProperties
                        }
                        New-Variable -Name "NetworkMonitorEndpoint" -Force -Value $({
                            $PUDRSSyncHT = $global:PUDRSSyncHT
                            #$ThisNetworkInterfaceStaticInfo = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces
    
                            #$NetworkLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                            if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                                # being added/removed from the ArrayList, things break
                                #$NetworkLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                                
                                # NOTE: Each element in the below $ArrayOfNetworkEntries is an ArrayList of PSCustomObjects.
                                # Each PSCustomObject contains:
                                <#
                                    [pscustomobject]@{
                                        Name                = $NetInt.Name
                                        Description         = $NetInt.Description
                                        TotalSentBytes      = $IPv4Stats.BytesSent
                                        TotalReceivedBytes  = $IPv4Stats.BytesReceived
                                    }
                                #>
                                $ArrayOfNetworkEntries = @(
                                    $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.NetStats
                                ) | Where-Object {$_ -ne $null}
                                if ($ArrayOfNetworkEntries.Count -gt 0) {
                                    $PreviousNetworkEntry = $ArrayOfNetworkEntries[-2]
                                    $LatestNetworkEntry = $ArrayOfNetworkEntries[-1]
                                }
                            }
    
                            #$PreviousSentBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalSentBytes
                            $PreviousSentBytesTotal = $PreviousNetworkEntry.TotalSentBytes
                            $NewSentBytesTotal = $LatestNetworkEntry.TotalSentBytes
                            $DifferenceSentBytes = $NewSentBytesTotal - $PreviousSentBytesTotal
                            if ($DifferenceSentBytes -le 0) {
                                $FinalKBSent = 0
                            }
                            else {
                                $FinalKBSent = [Math]::Round($($DifferenceSentBytes / 1KB),2)
                            }
                            #$FinalKBSent = [Math]::Round($($DifferenceSentBytes / 1KB)).ToString() + 'KB'
    
                            #$PreviousReceivedBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalReceivedBytes
                            $PreviousReceivedBytesTotal = $PreviousNetworkEntry.TotalReceivedBytes
                            $NewReceivedBytesTotal = $LatestNetworkEntry.TotalReceivedBytes
                            $DifferenceReceivedBytes = $NewReceivedBytesTotal - $PreviousReceivedBytesTotal
                            if ($DifferenceReceivedBytes -le 0) {
                                $FinalKBReceived = 0
                            }
                            else {
                                $FinalKBReceived = [Math]::Round($($DifferenceReceivedBytes / 1KB),2)
                            }
                            #$FinalKBReceived = [Math]::Round($($DifferenceReceivedBytes / 1KB)).ToString() + 'KB'
    
                            # Update the SyncHash so we have a record of the previous total
                            #$PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)" = $LatestNetworkEntry
    
                            $FinalKBSent | Out-UDMonitorData
                        })
    
                        $NetworkMonitorSplatParams = @{
                            Title                   = '"' + $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces.Name + '"' + ' Interface' + " Delta Sent KB"
                            Type                    = "Line"
                            DataPointHistory        = 20
                            ChartBackgroundColor    = "#80FF6B63"
                            ChartBorderColor        = "#FFFF6B63"
                            AutoRefresh             = $True
                            RefreshInterval         = 5
                            Endpoint                = $(Get-Variable -Name "NetworkMonitorEndpoint" -ValueOnly)
                        }
                        New-UdMonitor @NetworkMonitorSplatParams
                    }
                    New-UDColumn -Endpoint {
                        $null = $Session:OverviewPageLoadingTracker.Add("FinishedLoading")
                    }
                }
            }
            else {
                New-UDRow -EndPoint {
                    New-UDHeading -Text "Network Interface Info" -Size 4
                }
                for ($i=0; $i -lt @($PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces).Count; $i = $i+2) {
                    New-UDRow -Columns {
                        New-UDColumn -Size 6 -Endpoint {
                            $NetworkTableProperties = @("Name","Description","Sent","Received","DeltaSent","DeltaReceived")
                            New-UDTable -Headers $NetworkTableProperties -AutoRefresh -RefreshInterval 5 -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
                                #$ThisNetworkInterfaceStaticInfo = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$i]
    
                                #$NetworkLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                                if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                    # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                                    # being added/removed from the ArrayList, things break
                                    #$NetworkLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                                    
                                    # NOTE: Each element in the below $ArrayOfNetworkEntries is an ArrayList of PSCustomObjects.
                                    # Each PSCustomObject contains:
                                    <#
                                        [pscustomobject]@{
                                            Name                = $NetInt.Name
                                            Description         = $NetInt.Description
                                            TotalSentBytes      = $IPv4Stats.BytesSent
                                            TotalReceivedBytes  = $IPv4Stats.BytesReceived
                                        }
                                    #>
                                    $ArrayOfNetworkEntries = @(
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.NetStats | Where-Object {
                                            $_.Name -eq $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$i].Name
                                        }
                                    ) | Where-Object {$_ -ne $null}
                                    if ($ArrayOfNetworkEntries.Count -gt 0) {
                                        $PreviousNetworkEntry = $ArrayOfNetworkEntries[-2]
                                        $LatestNetworkEntry = $ArrayOfNetworkEntries[-1]
                                    }
                                }
            
                                #$PreviousSentBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalSentBytes
                                $PreviousSentBytesTotal = $PreviousNetworkEntry.TotalSentBytes
                                $NewSentBytesTotal = $LatestNetworkEntry.TotalSentBytes
                                $DifferenceSentBytes = $NewSentBytesTotal - $PreviousSentBytesTotal
                                if ($DifferenceSentBytes -le 0) {
                                    $FinalKBSent = 0
                                }
                                else {
                                    $FinalKBSent = [Math]::Round($($DifferenceSentBytes / 1KB),2).ToString() + 'KB'
                                }
                                #$FinalKBSent = [Math]::Round($($DifferenceSentBytes / 1KB),2).ToString() + 'KB'
    
                                #$PreviousReceivedBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalReceivedBytes
                                $PreviousReceivedBytesTotal = $PreviousNetworkEntry.TotalReceivedBytes
                                $NewReceivedBytesTotal = $LatestNetworkEntry.TotalReceivedBytes
                                $DifferenceReceivedBytes = $NewReceivedBytesTotal - $PreviousReceivedBytesTotal
                                if ($DifferenceReceivedBytes -le 0) {
                                    $FinalKBReceived = 0
                                }
                                else {
                                    $FinalKBReceived = [Math]::Round($($DifferenceReceivedBytes / 1KB),2).ToString() + 'KB'
                                }
                                #$FinalKBReceived = [Math]::Round($($DifferenceReceivedBytes / 1KB),2).ToString() + 'KB'
    
                                [pscustomobject]@{
                                    Name                        = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$i].Name
                                    Description                 = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$i].Description
                                    Sent                        = [Math]::Round($($NewSentBytesTotal / 1GB),2).ToString() + 'GB'
                                    Received                    = [Math]::Round($($NewReceivedBytesTotal / 1GB),2).ToString() + 'GB'
                                    DeltaSent                   = $FinalKBSent
                                    DeltaReceived               = $FinalKBReceived
                                } | Out-UDTableData -Property $NetworkTableProperties
                            }
    
                            New-Variable -Name "NetworkMonitorEndpoint$i" -Force -Value $({
                                $PUDRSSyncHT = $global:PUDRSSyncHT
                                #$ThisNetworkInterfaceStaticInfo = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$i]
            
                                #$NetworkLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                                if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                    # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                                    # being added/removed from the ArrayList, things break
                                    #$NetworkLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                                    
                                    # NOTE: Each element in the below $ArrayOfNetworkEntries is an ArrayList of PSCustomObjects.
                                    # Each PSCustomObject contains:
                                    <#
                                        [pscustomobject]@{
                                            Name                = $NetInt.Name
                                            Description         = $NetInt.Description
                                            TotalSentBytes      = $IPv4Stats.BytesSent
                                            TotalReceivedBytes  = $IPv4Stats.BytesReceived
                                        }
                                    #>
                                    $ArrayOfNetworkEntriesA = @(
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.NetStats | Where-Object {
                                            $_.Name -eq $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$i].Name
                                        }
                                    ) | Where-Object {$_ -ne $null}
                                    if ($ArrayOfNetworkEntriesA.Count -gt 0) {
                                        $PreviousNetworkEntryA = $ArrayOfNetworkEntriesA[-2]
                                        $LatestNetworkEntryA = $ArrayOfNetworkEntriesA[-1]
                                    }
                                }
            
                                #$PreviousSentBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalSentBytes
                                $PreviousSentBytesTotalA = $PreviousNetworkEntryA.TotalSentBytes
                                $NewSentBytesTotalA = $LatestNetworkEntryA.TotalSentBytes
                                $DifferenceSentBytesA = $NewSentBytesTotalA - $PreviousSentBytesTotalA
                                if ($DifferenceSentBytesA -le 0) {
                                    $FinalKBSentA = 0
                                }
                                else {
                                    $FinalKBSentA = [Math]::Round($($DifferenceSentBytesA / 1KB),2)
                                }
                                #$FinalKBSent = [Math]::Round($($DifferenceSentBytes / 1KB),2).ToString() + 'KB'
    
                                #$PreviousReceivedBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalReceivedBytes
                                $PreviousReceivedBytesTotalA = $PreviousNetworkEntryA.TotalReceivedBytes
                                $NewReceivedBytesTotalA = $LatestNetworkEntryA.TotalReceivedBytes
                                $DifferenceReceivedBytesA = $NewReceivedBytesTotalA - $PreviousReceivedBytesTotalA
                                if ($DifferenceReceivedBytesA -le 0) {
                                    $FinalKBReceivedA = 0
                                }
                                else {
                                    $FinalKBReceivedA = [Math]::Round($($DifferenceReceivedBytesA / 1KB),2)
                                }
                                #$FinalKBReceived = [Math]::Round($($DifferenceReceivedBytes / 1KB),2).ToString() + 'KB'
    
                                # Update the SyncHash so we have a record of the previous total
                                #$PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)" = $LatestNetworkEntry
            
                                $FinalKBSentA | Out-UDMonitorData
                            })
            
                            $NetworkMonitorSplatParamsA = @{
                                Title                   = '"' + $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$i].Name + '"' + ' Interface' + " Delta Sent KB"
                                Type                    = "Line"
                                DataPointHistory        = 20
                                ChartBackgroundColor    = "#80FF6B63"
                                ChartBorderColor        = "#FFFF6B63"
                                AutoRefresh             = $True
                                RefreshInterval         = 5
                                Endpoint                = $(Get-Variable -Name "NetworkMonitorEndpoint$i" -ValueOnly)
                            }
                            New-UdMonitor @NetworkMonitorSplatParamsA
                        }
                        New-UDColumn -Size 6 -Endpoint {
                            $NetworkTableProperties = @("Name","Description","Sent","Received","DeltaSent","DeltaReceived")
                            New-UDTable -Headers $NetworkTableProperties -AutoRefresh -RefreshInterval 5 -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
                                #$ThisNetworkInterfaceStaticInfo = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$($i+1)]
    
                                #$NetworkLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                                if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                    # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                                    # being added/removed from the ArrayList, things break
                                    #$NetworkLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                                    
                                    # NOTE: Each element in the below $ArrayOfNetworkEntries is an ArrayList of PSCustomObjects.
                                    # Each PSCustomObject contains:
                                    <#
                                        [pscustomobject]@{
                                            Name                = $NetInt.Name
                                            Description         = $NetInt.Description
                                            TotalSentBytes      = $IPv4Stats.BytesSent
                                            TotalReceivedBytes  = $IPv4Stats.BytesReceived
                                        }
                                    #>
                                    $ArrayOfNetworkEntriesB = @(
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.NetStats | Where-Object {
                                            $_.Name -eq $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$($i+1)].Name
                                        }
                                    ) | Where-Object {$_ -ne $null}
                                    if ($ArrayOfNetworkEntriesB.Count -gt 0) {
                                        $PreviousNetworkEntryB = $ArrayOfNetworkEntriesB[-2]
                                        $LatestNetworkEntryB = $ArrayOfNetworkEntriesB[-1]
                                    }
                                }
            
                                #$PreviousSentBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalSentBytes
                                $PreviousSentBytesTotalB = $PreviousNetworkEntryB.TotalSentBytes
                                $NewSentBytesTotalB = $LatestNetworkEntryB.TotalSentBytes
                                $DifferenceSentBytesB = $NewSentBytesTotalB - $PreviousSentBytesTotalB
                                if ($DifferenceSentBytesB -le 0) {
                                    $FinalKBSentB = 0
                                }
                                else {
                                    $FinalKBSentB = [Math]::Round($($DifferenceSentBytesB / 1KB),2).ToString() + 'KB'
                                }
                                #$FinalKBSent = [Math]::Round($($DifferenceSentBytes / 1KB),2).ToString() + 'KB'
    
                                #$PreviousReceivedBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalReceivedBytes
                                $PreviousReceivedBytesTotalB = $PreviousNetworkEntryB.TotalReceivedBytes
                                $NewReceivedBytesTotalB = $LatestNetworkEntryB.TotalReceivedBytes
                                $DifferenceReceivedBytesB = $NewReceivedBytesTotalB - $PreviousReceivedBytesTotalB
                                if ($DifferenceReceivedBytesB -le 0) {
                                    $FinalKBReceivedB = 0
                                }
                                else {
                                    $FinalKBReceivedB = [Math]::Round($($DifferenceReceivedBytesB / 1KB),2).ToString() + 'KB'
                                }
                                #$FinalKBReceived = [Math]::Round($($DifferenceReceivedBytes / 1KB),2).ToString() + 'KB'
    
                                [pscustomobject]@{
                                    Name                        = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$($i+1)].Name
                                    Description                 = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$($i+1)].Description
                                    Sent                        = [Math]::Round($($NewSentBytesTotalB / 1GB),2).ToString() + 'GB'
                                    Received                    = [Math]::Round($($NewReceivedBytesTotalB / 1GB),2).ToString() + 'GB'
                                    DeltaSent                   = $FinalKBSentB
                                    DeltaReceived               = $FinalKBReceivedB
                                } | Out-UDTableData -Property $NetworkTableProperties
                            }
    
                            New-Variable -Name "NetworkMonitorEndpoint$($i+1)" -Force -Value $({
                                $PUDRSSyncHT = $global:PUDRSSyncHT
                                #$ThisNetworkInterfaceStaticInfo = $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$($i+1)]
            
                                #$NetworkLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count
                                if ($PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                    # Clone the LiveOutput ArrayList Object because if we try to Enumerate (using Where-Object or other method) while elements are
                                    # being added/removed from the ArrayList, things break
                                    #$NetworkLiveOutputClone = $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataRSInfo.LiveOutput.Clone()
                                    
                                    # NOTE: Each element in the below $ArrayOfNetworkEntries is an ArrayList of PSCustomObjects.
                                    # Each PSCustomObject contains:
                                    <#
                                        [pscustomobject]@{
                                            Name                = $NetInt.Name
                                            Description         = $NetInt.Description
                                            TotalSentBytes      = $IPv4Stats.BytesSent
                                            TotalReceivedBytes  = $IPv4Stats.BytesReceived
                                        }
                                    #>
                                    $ArrayOfNetworkEntriesC = @(
                                        $PUDRSSyncHT."$RemoteHost`Info".Overview.LiveDataTracker.Previous.NetStats | Where-Object {
                                            $_.Name -eq $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$($i+1)].Name
                                        }
                                    ) | Where-Object {$_ -ne $null}
                                    if ($ArrayOfNetworkEntriesC.Count -gt 0) {
                                        $PreviousNetworkEntryC = $ArrayOfNetworkEntriesC[-2]
                                        $LatestNetworkEntryC = $ArrayOfNetworkEntriesC[-1]
                                    }
                                }
            
                                #$PreviousSentBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalSentBytes
                                $PreviousSentBytesTotalC = $PreviousNetworkEntryC.TotalSentBytes
                                $NewSentBytesTotalC = $LatestNetworkEntryC.TotalSentBytes
                                $DifferenceSentBytesC = $NewSentBytesTotalC - $PreviousSentBytesTotalC
                                if ($DifferenceSentBytesC -le 0) {
                                    $FinalKBSentC = 0
                                }
                                else {
                                    $FinalKBSentC = [Math]::Round($($DifferenceSentBytesC / 1KB),2)
                                }
                                #$FinalKBSent = [Math]::Round($($DifferenceSentBytes / 1KB),2).ToString() + 'KB'
    
                                #$PreviousReceivedBytesTotal = @($PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)")[-1].TotalReceivedBytes
                                $PreviousReceivedBytesTotalC = $PreviousNetworkEntryC.TotalReceivedBytes
                                $NewReceivedBytesTotalC = $LatestNetworkEntryC.TotalReceivedBytes
                                $DifferenceReceivedBytesC = $NewReceivedBytesTotalC - $PreviousReceivedBytesTotalC
                                if ($DifferenceReceivedBytesC -le 0) {
                                    $FinalKBReceivedC = 0
                                }
                                else {
                                    $FinalKBReceivedC = [Math]::Round($($DifferenceReceivedBytesC / 1KB),2)
                                }
                                #$FinalKBReceived = [Math]::Round($($DifferenceReceivedBytes / 1KB),2).ToString() + 'KB'
    
                                # Update the SyncHash so we have a record of the previous total
                                #$PUDRSSyncHT."$RemoteHost`Info".NetworkSendReceiveInfo."$($ThisNetworkInterfaceStaticInfo.Name)" = $LatestNetworkEntry
            
                                $FinalKBSentC | Out-UDMonitorData
                            })
            
                            $NetworkMonitorSplatParamsC = @{
                                Title                   = '"' + $PUDRSSyncHT."$RemoteHost`Info".Overview.RelevantNetworkInterfaces[$($i+1)].Name + '"' + ' Interface' + " Delta Sent KB"
                                Type                    = "Line"
                                DataPointHistory        = 20
                                ChartBackgroundColor    = "#80FF6B63"
                                ChartBorderColor        = "#FFFF6B63"
                                AutoRefresh             = $True
                                RefreshInterval         = 5
                                Endpoint                = $(Get-Variable -Name "NetworkMonitorEndpoint$($i+1)" -ValueOnly)
                            }
                            New-UdMonitor @NetworkMonitorSplatParamsC
                        }
                    }
                }
                New-UDColumn -Endpoint {
                    $null = $Session:OverviewPageLoadingTracker.Add("FinishedLoading")
                }
            }
    
            #endregion >> Monitors
        }
    }
    $Page = New-UDPage -Url "/Overview/:RemoteHost" -Endpoint $OverviewPageContent
    $null = $Pages.Add($Page)
    
    #endregion >> Overview Page
    
    $ProcessesPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:ProcessesPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:ProcessesPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $GetProcessesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Processes" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetProcessesFunc
    
                # Returns an array of CimInstance Objects
                $AllProcesses = Get-Processes -isLocal $True
    
                [pscustomobject]@{
                    AllProcesses = $AllProcesses
                }
            }
            $Session:AllProcessesStatic = $StaticInfo.AllProcesses
            if ($PUDRSSyncHT."$RemoteHost`Info".Processes.Keys -notcontains "AllProcesses") {
                $PUDRSSyncHT."$RemoteHost`Info".Processes.Add("AllProcesses",$Session:AllProcessesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Processes.AllProcesses = $Session:AllProcessesStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Processes (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetProcessesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Processes" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetProcessesFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Processes$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Processes$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 5 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 5) -eq 0) {
                                @{AllProcesses = [pscustomobject]@{ProcessesCollection = Get-Processes -isLocal $True}}
                            }
    
                            # Operations that you want to run once every second go here
                            # @{AllProcesses = Get-Processes -isLocal $True}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Processes$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo equal to
                # $RSSyncHash."Processes$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo = $RSSyncHash."Processes$RemoteHost`LiveDataResult"
            }
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            # Live Data Element Example
            # For ProcessStatus, 2 = Suspended, 1 = Running
            # WorkingSetSize is in KB
            $AllProcessesProperties = @("Name","ProcessId","ProcessStatus","CPUPercent","UserName","WorkingSetSize")
            $AllProcessesUDGridSplatParams = @{
                Headers                 = $AllProcessesProperties
                Properties              = $AllProcessesProperties
                DefaultSortColumn       = "CPUPercent"
                DefaultSortDescending   = $True
                AutoRefresh             = $True 
                RefreshInterval         = 5
                NoPaging                = $True
            }
            New-UDGrid @AllProcessesUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $AllProcessesLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataRSInfo.LiveOutput.Count
                if ($AllProcessesLiveOutputCount -gt 0) {
                    $ArrayOfAllProcessesEntries = @(
                        $PUDRSSyncHT."$RemoteHost`Info".Processes.LiveDataTracker.Previous.AllProcesses
                    ) | Where-Object {$_ -ne $null}
                    if ($ArrayOfAllProcessesEntries.Count -gt 0) {
                        $AllProcessesGridData = $ArrayOfAllProcessesEntries[-1].ProcessesCollection | foreach {
                            [pscustomobject]@{
                                Name            = $_.Name
                                ProcessId       = $_.ProcessId
                                ProcessStatus   = if ($_.ProcessStatus -eq 2) {"Suspended"} else {"Running"}
                                CPUPercent      = [Math]::Round($_.CPUPercent,2).ToString() + '%'
                                UserName        = $_.UserName
                                WorkingSetSize  = [Math]::Round($($_.WorkingSetSize / 1KB),2).ToString() + 'KB'
                            }
                        } | Out-UDGridData
                    }
                }
                if (!$AllProcessesGridData) {
                    $AllProcessesGridData = [pscustomobject]@{
                        Name            = "Collecting Info"
                        ProcessId       = "Collecting Info"
                        ProcessStatus   = "Collecting Info"
                        CPUPercent      = "CollectingInfo"
                        UserName        = "Collecting Info"
                        WorkingSetSize  = "Collecting Info"
                    } | Out-UDGridData
                }
    
                $AllProcessesGridData
            }
    
            # Remove the Loading  Indicator
            $null = $Session:ProcessesPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Processes/:RemoteHost" -Endpoint $ProcessesPageContent
    $null = $Pages.Add($Page)
    
    #region >> PSRemoting Creds Page
    
    $PSRemotingCredsPageContent = {
        param($RemoteHost)
    
        New-UDColumn -Endpoint {$Session:ThisRemoteHost = $RemoteHost}
    
        # Add the SyncHash to the Page so that we can pass output to other pages
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else 
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:PSRemotingPageLoadingTracker = [System.Collections.ArrayList]::new()
                #$PUDRSSyncHT.PSRemotingPageLoadingTracker = $Session:HomePageLoadingTracker
                $Session:NoCredsEntered = $False
                $Session:InvalidSSHPubCert = $False
                $Session:SSHRemotingMethodNoCert = $False
                $Session:DomainRemotingMethodNoCreds = $False
                $Session:LocalRemotingMethodNoCreds = $False
                $Session:UserNameAndPasswordRequired = $False
                $Session:BadFormatDomainUserName = $False
                $Session:EnableWinRMFailure = $False
                $Session:GetWorkingCredsFailure = $False
                $Session:InvalidCreds = $False
                $Session:CheckingCredentials = $False
            }
            New-UDHeading -Text "Set Credentials for $($RemoteHost.ToUpper())" -Size 4
        }
    
        New-UDRow -Columns {
            New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                if ($Session:PSRemotingPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
    
            New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                New-UDElement -Id "CheckingCredentials" -Tag div -EndPoint {
                    if ($Session:CheckingCredentials) {
                        New-UDHeading -Text "Checking Credentials for $Session:ThisRemoteHost...Please wait..." -Size 5
                        New-UDPreloader -Size small
                    }
                }
            }
    
            New-UDColumn -EndPoint {
                New-UDElement -Id "ValidateCredsMsg" -Tag div -EndPoint {
                    #New-UDHeading -Text "RemoteHost is $Session:ThisRemoteHost!" -Size 6 -Color red
    
                    if ($Session:NoCredsEntered) {
                        New-UDHeading -Text "You MUST enter UserName/Password for either a Local User or Domain User with access to $Session:ThisRemoteHost!" -Size 6 -Color red
                        $Session:NoCredsEntered = $False
                    }
                    if ($Session:InvalidSSHPubCert) {
                        New-UDHeading -Text "The string provided is not a valid SSH Public Certificate!" -Size 6 -Color red
                        $Session:InvalidSSHPubCert = $False
                    }
                    if ($Session:SSHRemotingMethodNoCert) {
                        New-UDHeading -Text "You indicated that SSH is your Preferred_PSRemotingMethod, however, you did not provide a value for Path_To_SSH_Public_Cert!" -Size 6 -Color red
                        $Session:SSHRemotingMethodNoCert = $False
                    }
                    if ($Session:DomainRemotingMethodNoCreds) {
                        New-UDHeading -Text "You indicated that 'Domain' was your Preferred_PSRemotingCredType, however, you did not provide Domain Credentials!" -Size 6 -Color red
                        $Session:DomainRemotingMethodNoCreds = $False
                    }
                    if ($Session:LocalRemotingMethodNoCreds) {
                        New-UDHeading -Text "You indicated that 'Local' was your Preferred_PSRemotingCredType, however, you did not provide Local Credentials!" -Size 6 -Color red
                        $Session:LocalRemotingMethodNoCreds = $False
                    }
                    if ($Session:UserNameAndPasswordRequired) {
                        New-UDHeading -Text "Please enter both a UserName and a Password!" -Size 6 -Color red
                        $Session:UserNameAndPasswordRequired = $False
                    }
                    if ($Session:BadFormatDomainUserName) {
                        New-UDHeading -Text "Domain_UserName must be in format 'Domain\DomainUser'!" -Size 6 -Color red
                        $Session:BadFormatDomainUserName = $False
                    }
                    if ($Session:EnableWinRMFailure) {
                        New-UDHeading -Text "Unable to Enable WinRM on $Session:ThisRemoteHost via Invoke-WmiMethod over RPC! Please check your credentials." -Size 6 -Color red
                        $Session:EnableWinRMFailure = $False
                    }
                    if ($Session:GetWorkingCredsFailure) {
                        New-UDHeading -Text "Unable to test Credentials! Please try again." -Size 6 -Color red
                        $Session:GetWorkingCredsFailure = $False
                    }
                    if ($Session:InvalidCreds) {
                        New-UDHeading -Text "Invalud Credentials! Please try again." -Size 6 -Color red
                        $Session:InvalidCreds = $False
                    }
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        <#
        New-UDRow -Endpoint {
            New-UDColumn -Size 2 -Content {}
            New-UDColumn -Size 8 -Endpoint {
                New-UDRow -Endpoint {
                    New-UDTextbox -Id "LocalUserName" -Label "Local UserName" -Type text
                    New-UDTextbox -Id "LocalPassword" -Label "Local Password" -Type password
                    New-UDTextbox -Id "DomainUserName" -Label "Domain UserName" -Type text
                    New-UDTextbox -Id "DomainPassword" -Label "Domain Password" -Type password
                    New-UDTextbox -Id "SSHPublicCert" -Label "SSH Public Certificate" -Type text
                    New-UDSelect -Id "PreferredPSRemotingCredType" -Label "Credential Type" -Option {
                        New-UDSelectOption -Name "Domain" -Value "Domain" -Selected
                        New-UDSelectOption -Name "Local" -Value "Local"
                    }
                    New-UDSelect -Id "PreferredPSRemotingMethod" -Label "PSRemoting Method" -Option {
                        New-UDSelectOption -Name "WinRM" -Value "WinRM" -Selected
                        New-UDSelectOption -Name "SSH" -Value "SSH"
                    }
                }
                New-UDRow -EndPoint {
                    New-UDButton -Text "Set Credentials" -OnClick {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $Session:CheckingCredentials = $True
                        Sync-UDElement -Id "CheckingCredentials"
    
                        $LocalUserNameTextBox = Get-UDElement -Id "LocalUserName"
                        $LocalPasswordTextBox = Get-UDElement -Id "LocalPassword"
                        $DomainUserNameTextBox = Get-UDElement -Id "DomainUserName"
                        $DomainPasswordTextBox = Get-UDElement -Id "DomainPassword"
                        $SSHPublicCertTextBox = Get-UDElement -Id "SSHPublicCert"
                        $PrefCredTypeSelection = Get-UDElement -Id "PreferredPSRemotingCredType"
                        $PrefRemotingMethodSelection = Get-UDElement -Id "PreferredPSRemotingMethod"
                        
                        $Local_UserName = $LocalUserNameTextBox.Attributes['value']
                        $Local_Password = $LocalPasswordTextBox.Attributes['value']
                        $Domain_UserName = $DomainUserNameTextBox.Attributes['value']
                        $Domain_Password = $DomainPasswordTextBox.Attributes['value']
                        $VaultServerUrl = $SSHPublicCertTextBox.Attributes['value']
                        $Preferred_PSRemotingCredType = $($PrefCredTypeSelection.Content | foreach {
                            $_.ToString() | ConvertFrom-Json
                        } | Where-Object {$_.attributes.selected.isPresent}).attributes.value
                        $Preferred_PSRemotingMethod = $($PrefRemotingMethodSelection.Content | foreach {
                            $_.ToString() | ConvertFrom-Json
                        } | Where-Object {$_.attributes.selected.isPresent}).attributes.value
    
                        $TestingCredsObj = [pscustomobject]@{
                            LocalUserNameTextBox            = $LocalUserNameTextBox
                            LocalPasswordTextBox            = $LocalPasswordTextBox
                            DomainUserNameTextBox           = $DomainUserNameTextBox
                            DomainPasswordTextBox           = $DomainPasswordTextBox
                            SSHPublicCertTextBox            = $SSHPublicCertTextBox
                            PrefCredTypeSelection           = $PrefCredTypeSelection
                            PrefRemotingMethodSelection     = $PrefRemotingMethodSelection
                            Local_UserName                  = $Local_UserName
                            Local_Password                  = $Local_Password
                            Domain_UserName                 = $Domain_UserName
                            Domain_Password                 = $Domain_Password
                            VaultServerUrl             = $VaultServerUrl
                            Preferred_PSRemotingCredType    = $Preferred_PSRemotingCredType
                            Preferred_PSRemotingMethod      = $Preferred_PSRemotingMethod
                            RemoteHost                      = $Session:ThisRemoteHost
                        }
    
                        if ($Session:CredentialHT.Keys -notcontains $Session:ThisRemoteHost) {
                            #New-UDInputAction -Toast "`$Session:CredentialHT is not defined!" -Duration 10000
                            $Session:CredentialHT = @{}
                            $RHostCredHT = @{
                                DomainCreds         = $null
                                LocalCreds          = $null
                                VaultServerUrl      = $null
                                PSRemotingCredType  = $null
                                PSRemotingMethod    = $null
                                PSRemotingCreds     = $null
                            }
                            $Session:CredentialHT.Add($Session:ThisRemoteHost,$RHostCredHT)
    
                            # TODO: Need to remove this when finished testing
                            $PUDRSSyncHT."$Session:ThisRemoteHost`Info".CredHT = $Session:CredentialHT
    
                            #New-UDInputAction -Toast "`$Session:CredentialHT was null" -Duration 10000
                        }
    
                        # In case this page was refreshed or redirected to from itself, check $Session:CredentialHT for existing values
                        if (!$Local_UserName -and $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds -ne $null) {
                            $Local_UserName = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds.UserName
                        }
                        if (!$Local_Password -and $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds -ne $null) {
                            $Local_Password = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds.GetNetworkCredential().Password
                        }
                        if (!$Domain_UserName -and $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds -ne $null) {
                            $Domain_UserName = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds.UserName
                        }
                        if (!$Domain_Password -and $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds -ne $null) {
                            $Domain_Password = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds.GetNetworkCredential().Password
                        }
                        if (!$VaultServerUrl -and $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl -ne $null) {
                            $VaultServerUrl = $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl
                        }
                        if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType -ne $null) {
                            $Preferred_PSRemotingCredType = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType
                        }
                        if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod -ne $null) {
                            $Preferred_PSRemotingMethod = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod
                        }
    
                        if (!$Local_UserName -and !$Local_Password -and !$Domain_UserName -and !$Domain_Password -and !$VaultServerUrl) {
                            $Session:NoCredsEntered = $True
                            Sync-UDElement -Id "ValidateCredsMsg"
                            $Session:CheckingCredentials = $False
                            Sync-UDElement -Id "CheckingCredentials"
                            return
                        }
    
                        if ($VaultServerUrl) {
                            # TODO: Validate the provided string is a SSH Public Cert
                            if ($BadSSHPubCert) {
                                $Session:InvalidSSHPubCert = $True
                                Sync-UDElement -Id "ValidateCredsMsg"
                                $Session:CheckingCredentials = $False
                                Sync-UDElement -Id "CheckingCredentials"
                                return
                            }
                        }
    
                        if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod) {
                            $Preferred_PSRemotingMethod = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod
                        }
                        if ($Preferred_PSRemotingMethod -eq "SSH" -and !$VaultServerUrl) {
                            $Session:SSHRemotingMethodNoCert = $True
                            Sync-UDElement -Id "ValidateCredsMsg"
                            $Session:CheckingCredentials = $False
                            Sync-UDElement -Id "CheckingCredentials"
                            return
                        }
    
                        if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType) {
                            $Preferred_PSRemotingCredType = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType
                        }
                        if ($Preferred_PSRemotingCredType -eq "Domain" -and $(!$Domain_UserName -or !$Domain_Password)) {
                            $Session:DomainRemotingMethodNoCreds = $True
                            Sync-UDElement -Id "ValidateCredsMsg"
                            $Session:CheckingCredentials = $False
                            Sync-UDElement -Id "CheckingCredentials"
                            return
                        }
    
                        if ($Preferred_PSRemotingCredType -eq "Local" -and $(!$Local_UserName -or !$Local_Password)) {
                            $Session:LocalRemotingMethodNoCreds = $True
                            Sync-UDElement -Id "ValidateCredsMsg"
                            $Session:CheckingCredentials = $False
                            Sync-UDElement -Id "CheckingCredentials"
                            return
                        }
    
                        if ($($Local_UserName -and !$Local_Password) -or $(!$Local_UserName -and $Local_Password) -or
                        $($Domain_UserName -and !$Domain_Password) -or $(!$Domain_UserName -and $Domain_Password)
                        ) {
                            $Session:UserNameAndPasswordRequired = $True
                            Sync-UDElement -Id "ValidateCredsMsg"
                            $Session:CheckingCredentials = $False
                            Sync-UDElement -Id "CheckingCredentials"
                            return
                        }
    
                        if ($Local_UserName -and $Local_Password) {
                            # Make sure the $Local_UserName is in format $Session:ThisRemoteHost\$Local_UserName
                            if ($Local_UserName -notmatch "^$Session:ThisRemoteHost\\[a-zA-Z0-9]+$") {
                                $Local_UserName = "$Session:ThisRemoteHost\$Local_UserName"
                            }
    
                            $LocalPwdSecureString = ConvertTo-SecureString $Local_Password -AsPlainText -Force
                            $LocalAdminCreds = [pscredential]::new($Local_UserName,$LocalPwdSecureString)
                        }
    
                        if ($Domain_UserName -and $Domain_Password) {
                            $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                            # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                            if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                                $Session:BadFormatDomainUserName = $True
                                Sync-UDElement -Id "ValidateCredsMsg"
                                $Session:CheckingCredentials = $False
                                Sync-UDElement -Id "CheckingCredentials"
                                return
                            }
    
                            $DomainPwdSecureString = ConvertTo-SecureString $Domain_Password -AsPlainText -Force
                            $DomainAdminCreds = [pscredential]::new($Domain_UserName,$DomainPwdSecureString)
                        }
    
                        # Test the Credentials
                        [System.Collections.ArrayList]$CredentialsToTest = @()
                        if ($LocalAdminCreds) {
                            $PSObj = [pscustomobject]@{CredType = "LocalUser"; PSCredential = $LocalAdminCreds}
                            $null = $CredentialsToTest.Add($PSObj)
                        }
                        if ($DomainAdminCreds) {
                            $PSObj = [pscustomobject]@{CredType = "DomainUser"; PSCredential = $DomainAdminCreds}
                            $null = $CredentialsToTest.Add($PSObj)
                        }
    
                        [System.Collections.ArrayList]$FailedCredentialsA = @()
                        foreach ($CredObj in $CredentialsToTest) {
                            try {
                                $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $Session:ThisRemoteHost -AltCredentials $CredObj.PSCredential -ErrorAction Stop
                
                                if ($GetWorkingCredsResult.DeterminedCredsThatWorkedOnRemoteHost) {
                                    if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                                        $null = $FailedCredentialsA.Add($CredObj)
                                    }
                                }
                                else {
                                    $null = $FailedCredentialsA.Add($CredObj)
                                }
                            }
                            catch {}
                        }
    
                        if ($($CredentialsToTest.Count -eq 2 -and $FailedCredentialsA.Count -eq 2) -or 
                        $($CredentialsToTest.Count -eq 1 -and $FailedCredentialsA.Count -eq 1)
                        ) {
                            # Since WinRM failed, try and enable WinRM Remotely via Invoke-WmiMethod over RPC Port 135 (if it's open)
                            $RPCPortOpen = $(TestPort -HostName $Session:ThisRemoteHost -Port 135).Open
    
                            [System.Collections.ArrayList]$EnableWinRMSuccess = @()
                            foreach ($CredObj in $CredentialsToTest) {
                                if ($RPCPortOpen) {
                                    try {
                                        $null = EnableWinRMViaRPC -RemoteHostNameOrIP $Session:ThisRemoteHost -Credential $CredObj.PSCredential
                                        $null = $EnableWinRMSuccess.Add($CredObj)
                                        break
                                    }
                                    catch {
                                        #New-UDInputAction -Toast "Failed to enable WinRM Remotely using Credentials $($CredObj.PSCredential.UserName)" -Duration 10000
                                    }
                                }
                            }
    
                            if ($EnableWinRMSuccess.Count -eq 0) {
                                $Session:EnableWinRMFailure = $True
                                Sync-UDElement -Id "ValidateCredsMsg"
                                $Session:CheckingCredentials = $False
                                Sync-UDElement -Id "CheckingCredentials"
                                return
                            }
                            else {
                                [System.Collections.ArrayList]$FailedCredentialsB = @()
                                foreach ($CredObj in $CredentialsToTest) {
                                    try {
                                        $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $Session:ThisRemoteHost -AltCredentials $CredObj.PSCredential -ErrorAction Stop
                        
                                        if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                                            #New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                            $null = $FailedCredentialsB.Add($CredObj)
                                        }
                                    }
                                    catch {
                                        $Session:GetWorkingCredsFailure = $True
                                        Sync-UDElement -Id "ValidateCredsMsg"
                                        $Session:CheckingCredentials = $False
                                        Sync-UDElement -Id "CheckingCredentials"
                                        return
                                        
                                        #Show-UDToast -Message $_.Exception.Message -Duration 10
                                    }
                                }
                            }
                        }
    
                        if ($FailedCredentialsA.Count -gt 0 -or $FailedCredentialsB.Count -gt 0) {
                            if ($FailedCredentialsB.Count -gt 0) {
                                foreach ($CredObj in $FailedCredentialsB) {
                                    $Session:GetWorkingCredsFailure = $True
                                    Sync-UDElement -Id "ValidateCredsMsg"
                                    #$Session:CredentialHT.$Session:ThisRemoteHost."$CredType`Creds" = $null
                                }
                                $Session:CheckingCredentials = $False
                                Sync-UDElement -Id "CheckingCredentials"
                                return
                            }
                            if ($FailedCredentialsA.Count -gt 0 -and $FailedCredentialsB.Count -eq 0) {
                                foreach ($CredObj in $FailedCredentialsA) {
                                    $Session:GetWorkingCredsFailure = $True
                                    Sync-UDElement -Id "ValidateCredsMsg"
                                }
                                $Session:CheckingCredentials = $False
                                Sync-UDElement -Id "CheckingCredentials"
                                return
                            }
                        }
    
                        if ($DomainAdminCreds) {
                            $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds = $DomainAdminCreds
                        }
                        if ($LocalAdminCreds) {
                            $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds = $LocalAdminCreds
                        }
                        if ($VaultServerUrl) {
                            $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl = $VaultServerUrl
                        }
                        if ($Preferred_PSRemotingCredType) {
                            $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType = $Preferred_PSRemotingCredType
                        }
                        if ($Preferred_PSRemotingMethod) {
                            $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod = $Preferred_PSRemotingMethod
                        }
    
                        # Determine $PSRemotingCreds
                        if ($Preferred_PSRemotingCredType -eq "Local") {
                            $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds
                        }
                        if ($Preferred_PSRemotingCredType -eq "Domain") {
                            $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds
                        }
    
                        Invoke-UDRedirect -Url "/ToolSelect/$Session:ThisRemoteHost"
                    }
                }
                New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                    try {
                        $null = $Session:PSRemotingPageLoadingTracker.Add("FinishedLoading")
                    }
                    catch {
                        Write-Verbose "`$Session:PSRemotingPageLoadingTracker hasn't been set yet..."
                    }
                }
            }
            New-UDColumn -Size 2 -Content {}
        }
        #>
    
        New-UDRow -Endpoint {
            New-UDColumn -Size 2 -EndPoint {}
            New-UDColumn -Size 8 -EndPoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:CredsForm = New-UDInput -SubmitText "Set Credentials" -Id "CredsForm" -Content {
                    New-UDInputField -Type textbox -Name 'Local_UserName' -Value $null
                    New-UDInputField -Type password -Name 'Local_Password' -Value $null
                    New-UDInputField -Type textbox -Name 'Domain_UserName' -Value $null
                    New-UDInputField -Type password -Name 'Domain_Password' -Value $null
                    New-UDInputField -Type textbox -Name 'VaultServerUrl' -Value $null
                    New-UDInputField -Type select -Name 'Preferred_PSRemotingCredType' -Values @("Local","Domain","SSHCertificate") -DefaultValue "Domain"
    
                    [System.Collections.ArrayList]$PSRemotingMethodValues = @("WinRM")
                    if ($PUDRSSyncHT."$Session:ThisRemoteHost`Info".RHostTableData.SSH -eq "Available") {
                        $null = $PSRemotingMethodValues.Add("SSH")
                    }
                    New-UDInputField -Type select -Name 'Preferred_PSRemotingMethod' -Values @("WinRM","SSH") -DefaultValue "WinRM"
                } -Endpoint {
                    param(
                        [string]$Local_UserName,
                        [string]$Local_Password,
                        [string]$Domain_UserName,
                        [string]$Domain_Password,
                        [string]$VaultServerUrl,
                        [string]$Preferred_PSRemotingCredType,
                        [string]$Preferred_PSRemotingMethod
                    )
    
                    # Add the SyncHash to the Page so that we can pass output to other pages
                    $PUDRSSyncHT = $global:PUDRSSyncHT
    
                    # Load PUDAdminCenter Module Functions Within ScriptBlock
                    $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                    try {
                        if ($Session:CredentialHT.GetType().FullName -ne "System.Collections.Hashtable") {
                            $Session:CredentialHT = @{}
                        }
                    }
                    catch {
                        $Session:CredentialHT = @{}
                    }
    
                    if ($Session:CredentialHT.Keys -notcontains $Session:ThisRemoteHost) {
                        $RHostCredHT = @{
                            DomainCreds         = $null
                            LocalCreds          = $null
                            VaultServerUrl      = $null
                            PSRemotingCredType  = $null
                            PSRemotingMethod    = $null
                            PSRemotingCreds     = $null
                        }
                        $Session:CredentialHT.Add($Session:ThisRemoteHost,$RHostCredHT)
                    }
    
                    # TODO: Need to remove this when finished testing
                    $PUDRSSyncHT."$Session:ThisRemoteHost`Info".CredHT = $Session:CredentialHT
    
                    # In case this page was refreshed or redirected to from itself, check $Session:CredentialHT for existing values
                    if (!$Local_UserName -and $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds -ne $null) {
                        $Local_UserName = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds.UserName
                    }
                    if (!$Local_Password -and $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds -ne $null) {
                        $Local_Password = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds.GetNetworkCredential().Password
                    }
                    if (!$Domain_UserName -and $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds -ne $null) {
                        $Domain_UserName = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds.UserName
                    }
                    if (!$Domain_Password -and $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds -ne $null) {
                        $Domain_Password = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds.GetNetworkCredential().Password
                    }
                    if (!$VaultServerUrl -and $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl -ne $null) {
                        $VaultServerUrl = $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl
                    }
                    if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType -ne $null) {
                        $Preferred_PSRemotingCredType = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType
                    }
                    if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod -ne $null) {
                        $Preferred_PSRemotingMethod = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod
                    }
    
                    # Make sure *Something* is filled out...
                    if (!$Local_UserName -and !$Local_Password -and !$Domain_UserName -and !$Domain_Password -and !$VaultServerUrl) {
                        New-UDInputAction -Toast "You MUST enter UserName/Password for either a Local User or Domain User with access to $Session:ThisRemoteHost!" -Duration 10000
                        Sync-UDElement -Id "CredsForm"
                        return
                    }
    
                    <#
                    # Set/Check $Preferred_PSRemotingCredType...
                    if (!$Preferred_PSRemotingCredType -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType) {
                        $Preferred_PSRemotingCredType = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType
                    }
                    # Set/Check $Preferred_PSRemotingMethod...
                    if (!$Preferred_PSRemotingMethod -and $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod) {
                        $Preferred_PSRemotingMethod = $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod
                    }
                    #>
                    
                    if ($Preferred_PSRemotingMethod -eq "SSH") {
                        if ($Preferred_PSRemotingCredType -ne "SSHCertificate") {
                            $Preferred_PSRemotingCredType = "SSHUserNameAndPassword"
                        }
                        
                        if ($Preferred_PSRemotingCredType -eq "Domain") {
                            if ($Local_UserName -or $Local_Password) {
                                New-UDInputAction -Toast "You specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', but you provided Local_UserName or Local_Password!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                            if ($VaultServerUrl) {
                                New-UDInputAction -Toast "You specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', but you provided VaultServerUrl!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            if (!$Domain_UserName -or !$Domain_Password) {
                                New-UDInputAction -Toast "You must provide a Domain_UserName AND Domain_Password in order to use PowerShell Remoting over SSH!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                            if ($Domain_UserName -and $Domain_Password) {
                                $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                                if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                                    New-UDInputAction -Toast "Domain_UserName must be in format 'Domain\DomainUser'!" -Duration 10000
                                    Sync-UDElement -Id "CredsForm"
                                    return
                                }
            
                                $DomainPwdSecureString = ConvertTo-SecureString $Domain_Password -AsPlainText -Force
                                $DomainAdminCreds = [pscredential]::new($Domain_UserName,$DomainPwdSecureString)
                            }
                        }
                        if ($Preferred_PSRemotingCredType -eq "Local") {
                            if ($Domain_UserName -or $Domain_Password) {
                                New-UDInputAction -Toast "You specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', but you provided Domain_UserName or Domain_Password!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                            if ($VaultServerUrl) {
                                New-UDInputAction -Toast "You specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', but you provided VaultServerUrl!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            if (!$Local_UserName -or !$Local_Password) {
                                New-UDInputAction -Toast "You must provide a Local_UserName AND Local_Password in order to use PowerShell Remoting over SSH!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            # Make sure the $Local_UserName is in format $Session:ThisRemoteHost\$Local_UserName
                            if ($Local_UserName -and $Local_Password) {
                                if ($Local_UserName -notmatch "^$Session:ThisRemoteHost\\[a-zA-Z0-9]+$") {
                                    $Local_UserName = "$Session:ThisRemoteHost\$Local_UserName"
                                }
            
                                $LocalPwdSecureString = ConvertTo-SecureString $Local_Password -AsPlainText -Force
                                $LocalAdminCreds = [pscredential]::new($Local_UserName,$LocalPwdSecureString)
                            }
                        }
                        if ($Preferred_PSRemotingCredType -eq "SSHUserNameAndPassword") {
                            if (!$($Domain_UserName -and $Domain_Password) -and !$($Local_UserName -and $Local_Password)) {
                                New-UDInputAction -Toast "Since you specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', you MUST provide a Domain_UserName and Domain_Password or Local_UserName and Local_Password!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            # Make sure the $Local_UserName is in format $Session:ThisRemoteHost\$Local_UserName
                            if ($Local_UserName -and $Local_Password) {
                                if ($Local_UserName -notmatch "^$Session:ThisRemoteHost\\[a-zA-Z0-9]+$") {
                                    $Local_UserName = "$Session:ThisRemoteHost\$Local_UserName"
                                }
            
                                $LocalPwdSecureString = ConvertTo-SecureString $Local_Password -AsPlainText -Force
                                $LocalAdminCreds = [pscredential]::new($Local_UserName,$LocalPwdSecureString)
                            }
    
                            # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                            if ($Domain_UserName -and $Domain_Password) {
                                $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                                if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                                    New-UDInputAction -Toast "Domain_UserName must be in format 'Domain\DomainUser'!" -Duration 10000
                                    Sync-UDElement -Id "CredsForm"
                                    return
                                }
            
                                $DomainPwdSecureString = ConvertTo-SecureString $Domain_Password -AsPlainText -Force
                                $DomainAdminCreds = [pscredential]::new($Domain_UserName,$DomainPwdSecureString)
                            }
                        }
                        if ($Preferred_PSRemotingCredType -eq "SSHCertificate") {
                            if (!$Domain_UserName -or !$Domain_Password) {
                                New-UDInputAction -Toast "You specifed your Preferred_PSRemotingCredType as '$Preferred_PSRemotingCredType', which means you must provide Domain_UserName and Domain_Password!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                            if (!$VaultServerUrl) {
                                New-UDInputAction -Toast "You must provide the VaultServerUrl in order to generate/request/receive a new SSH Certificate!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                            if ($Domain_UserName -and $Domain_Password) {
                                $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                                if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                                    New-UDInputAction -Toast "Domain_UserName must be in format 'Domain\DomainUser'!" -Duration 10000
                                    Sync-UDElement -Id "CredsForm"
                                    return
                                }
            
                                $DomainPwdSecureString = ConvertTo-SecureString $Domain_Password -AsPlainText -Force
                                $DomainAdminCreds = [pscredential]::new($Domain_UserName,$DomainPwdSecureString)
                            }
    
                            if ($VaultServerUrl) {
                                [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
    
                                # Make sure we can reach the Vault Server and that is in a state where we can actually use it.
                                try {
                                    $VaultServerUpAndUnsealedCheck = Invoke-RestMethod "$VaultServerUrl/sys/health"
                                    if (!$VaultServerUpAndUnsealedCheck -or $VaultServerUpAndUnsealedCheck.initialized -ne $True -or
                                    $VaultServerUpAndUnsealedCheck.sealed -ne $False -or $VaultServerUpAndUnsealedCheck.standby -ne $False) {
                                        throw "The Vault Server is either not reachable or in a state where it cannot be used! Halting!"
                                    }
                                }
                                catch {
                                    New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                                    Sync-UDElement -Id "CredsForm"
                                    return
                                }
                            }
                        }
    
                        try {
                            # Make sure we have the WinSSH Module Available
                            if ($(Get-Module -ListAvailable).Name -notcontains "WinSSH") {$null = Install-Module WinSSH -ErrorAction Stop}
                            if ($(Get-Module).Name -notcontains "WinSSH") {$null = Import-Module WinSSH -ErrorAction Stop}
    
                            # Make sure we have the VaultServer Module Available
                            if ($(Get-Module -ListAvailable).Name -notcontains "VaultServer") {$null = Install-Module VaultServer -ErrorAction Stop}
                            if ($(Get-Module).Name -notcontains "VaultServer") {$null = Import-Module VaultServer -ErrorAction Stop}
                        }
                        catch {
                            New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
    
                        if ($(Get-Module).Name -notcontains "WinSSH") {
                            New-UDInputAction -Toast "The WinSSH Module is not available! Halting!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
                        if ($(Get-Module).Name -notcontains "VaultServer") {
                            New-UDInputAction -Toast "The VaultServer Module is not available! Halting!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
    
                        # Install OpenSSH-Win64 if it isn't already
                        if (!$(Test-Path "$env:ProgramFiles\OpenSSH-Win64\ssh.exe")) {
                            Install-WinSSH -GiveWinSSHBinariesPathPriority -ConfigureSSHDOnLocalHost -DefaultShell pwsh
                        }
                        else {
                            if (!$(Get-Command ssh -ErrorAction SilentlyContinue)) {
                                $OpenSSHDir ="$env:ProgramFiles\OpenSSH-Win64"
                                # Update PowerShell $env:Path
                                [System.Collections.Arraylist][array]$CurrentEnvPathArray = $env:Path -split ';' | Where-Object {![System.String]::IsNullOrWhiteSpace($_)} | Sort-Object | Get-Unique
                                if ($CurrentEnvPathArray -notcontains $OpenSSHDir) {
                                    $CurrentEnvPathArray.Insert(0,$OpenSSHDir)
                                    $env:Path = $CurrentEnvPathArray -join ';'
                                }
                                
                                # Update SYSTEM Path
                                $RegistrySystemPath = 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment'
                                $CurrentSystemPath = $(Get-ItemProperty -Path $RegistrySystemPath -Name PATH).Path
                                [System.Collections.Arraylist][array]$CurrentSystemPathArray = $CurrentSystemPath -split ";" | Where-Object {![System.String]::IsNullOrWhiteSpace($_)} | Sort-Object | Get-Unique
                                if ($CurrentSystemPathArray -notcontains $OpenSSHDir) {
                                    $CurrentSystemPathArray.Insert(0,$OpenSSHDir)
                                    $UpdatedSystemPath = $CurrentSystemPathArray -join ";"
                                    Set-ItemProperty -Path $RegistrySystemPath -Name PATH -Value $UpdatedSystemPath
                                }
                            }
                            if (!$(Get-Command ssh -ErrorAction SilentlyContinue)) {
                                New-UDInputAction -Toast "Unable to find ssh.exe on $env:ComputerName!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                        }
    
                        if ($Preferred_PSRemotingCredType -eq "SSHCertificate") {
                            # Use Domain Credentials to get a new Vault Server Authentication Token, generate new SSH Keys on the PUDAdminCenter Server,
                            # have the Vault Server sign them, add the new private key to the ssh-agent, and output an SSH Public Certificate to $HOME\.ssh
                            # NOTE: The SSH Keys will expire in 24 hours
                            $NewSSHKeyName = $($DomainAdminCreds.UserName -split "\\")[-1] + "_" + $(Get-Date -Format MM-dd-yy_hhmmsstt)
                            $NewSSHCredentialsSplatParams = @{
                                VaultServerBaseUri                  = $VaultServerUrl
                                DomainCredentialsWithAccessToVault  = $DomainAdminCreds
                                NewSSHKeyName                       = $NewSSHKeyName
                                BlankSSHPrivateKeyPwd               = $True
                                AddToSSHAgent                       = $True
                                RemovePrivateKey                    = $True # Removes the Private Key from the filesystem
                                #SSHAgentExpiry                      = 86400 # 24 hours in seconds # Don't use because this makes ALL keys in ssh-agent expire in 24 hours
                            }
    
                            try {
                                $NewSSHCredsResult = New-SSHCredentials @NewSSHCredentialsSplatParams -ErrorAction Stop
                                $NewSSHCredsResult | Add-Member -Name "PrivateKeyPath" -Value $($NewSSHCredsResult.PublicKeyPath -replace "\.pub","") -MemberType NoteProperty
                            }
                            catch {
                                New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
    
                            if ($PUDRSSyncHT.Keys -contains "NewSSHCredsResult") {
                                $PUDRSSyncHT.NewSSHCredsResult = $NewSSHCredsResult
                            }
                            else {
                                $PUDRSSyncHT.Add("NewSSHCredsResult",$NewSSHCredsResult)
                            }
    
                            # $NewSSHCredsResult (and $GetSSHAuthSanity later on) is a pscustomobject with the following content:
                            <#
                                PublicKeyCertificateAuthShouldWork : True
                                FinalSSHExeCommand                 : ssh zeroadmin@zero@<RemoteHost>
                                PublicKeyPath                      : C:\Users\zeroadmin\.ssh\zeroadmin_071918.pub
                                PublicCertPath                     : C:\Users\zeroadmin\.ssh\zeroadmin_071918-cert.pub
                            #>
    
                            # If $NewSSHCredsResult.FinalSSHExeCommand looks like...
                            #     ssh -o "IdentitiesOnly=true" -i "C:\Users\zeroadmin\.ssh\zeroadmin_071718" -i "C:\Users\zeroadmin\.ssh\zeroadmin_071718-cert.pub" zeroadmin@zero@<RemoteHost>
                            # ...or...
                            #     ssh <user>@<RemoteHost>
                            # ...then there are too many identities loaded in the ssh-agent service, which means we need to get the private key from the registry and write it to a file
                            # See: https://blog.ropnop.com/extracting-ssh-private-keys-from-windows-10-ssh-agent/
                            if (!$NewSSHCredsResult.PublicKeyCertificateAuthShouldWork -or 
                            $NewSSHCredsResult.FinalSSHExeCommand -eq "ssh <user>@<RemoteHost>" -or
                            $NewSSHCredsResult.FinalSSHExeCommand -match "IdentitiesOnly=true"
                            ) {
                                # NOTE: Extract-SSHPrivateKeysFromRegistry is from the WinSSH Module and provides output like:
                                <#
                                    OriginalPrivateKeyFilePath      = $OriginalPrivateKeyFilePath
                                    PrivateKeyContent               = $PrivateKeyContent
                                #>
                                # This should only really be necessary if the ssh-agent has more than 5 entries in it (and the needed key isn't within one of the first 5) and
                                # the RSA Private Key isn't on the filesystem under "$HOME\.ssh". The Get-SSHClientAuthSanity function figures that out for us.
                                $ExtractedPrivateKeys = Extract-SSHPrivateKeysFromRegistry
                                $OriginalPrivateKeyPath = $NewSSHCredsResult.PublicKeyPath -replace "\.pub",""
                                $PrivateKeyContent = $($ExtractedPrivateKeys | Where-Object {$_.OriginalPrivateKeyFilePath -eq $OriginalPrivateKeyPath}).PrivateKeyContent
    
                                if ($PrivateKeyContent.Count -gt 0) {
                                    Set-Content -Path $OriginalPrivateKeyPath -Value $PrivateKeyContent
                                    $NeedToRemovePrivateKey = $True
                                    $GetSSHAuthSanityCheck = Get-SSHClientAuthSanity -SSHPublicKeyFilePath $NewSSHCredsResult.PublicKeyPath
                                    if ($GetSSHAuthSanityCheck.PublicKeyCertificateAuthShouldWork) {
                                        $GetSSHAuthSanity = [pscustomobject]@{
                                            PublicKeyCertificateAuthShouldWork  = $True
                                            FinalSSHExeCommand                  = $GetSSHAuthSanityCheck.FinalSSHExeCommand
                                            PrivateKeyPath                      = $OriginalPrivateKeyPath
                                            PublicKeyPath                       = $NewSSHCredsResult.PublicKeyPath
                                            PublicCertPath                      = $NewSSHCredsResult.PublicKeyPath + '-cert.pub'
                                        }
                                    }
                                    
                                    # The below $FinalSSHExeCommand string should look like:
                                    #     ssh -o "IdentitiesOnly=true" -i "$OriginalPrivateKeyPath" -i "$($NewSSHCredsResult.PublicCertPath)" zeroadmin@zero@<RemoteHost>
                                    $FinalSSHExeCommand = $GetSSHAuthSanity.FinalSSHExeCommand
    
                                    if (!$GetSSHAuthSanity.PublicKeyCertificateAuthShouldWork) {
                                        $UserNamePasswordRequired = $True
                                        $ToastMsg = "Unable to use SSH Certificate Authentication because the user ssh private key is not available on the " +
                                        "filesystem or in the ssh-agent. Trying UserName/Password SSH Authentication..."
                                        New-UDInputAction -Toast $ToastMsg -Duration 10000
                                        #Sync-UDElement -Id "CredsForm"
                                        #return
                                    }
                                }
                                else {
                                    $UserNamePasswordRequired = $True
                                    $ToastMsg = "Unable to use SSH Certificate Authentication because the user ssh keys and/or " +
                                    "ssh cert and/or ssh-agent is not configured properly! Trying UserName/Password SSH Authentication..."
                                    New-UDInputAction -Toast $ToastMsg -Duration 10000
                                    #Sync-UDElement -Id "CredsForm"
                                    #return
                                }
                            }
                            else {
                                $GetSSHAuthSanity = $NewSSHCredsResult
                                
                                # The below $FinalSSHExeCommand string should look like:
                                #     ssh zeroadmin@zero@<RemoteHost>
                                $FinalSSHExeCommand = $GetSSHAuthSanity.FinalSSHExeCommand
                            }
    
                            $SSHCertificate = Get-Content $GetSSHAuthSanity.PublicCertPath
    
                            if ($PUDRSSyncHT.Keys -contains "GetSSHAuthSanity") {
                                $PUDRSSyncHT.GetSSHAuthSanity = $GetSSHAuthSanity
                            }
                            else {
                                $PUDRSSyncHT.Add("GetSSHAuthSanity",$GetSSHAuthSanity)
                            }
                        }
                    }
                    if ($Preferred_PSRemotingMethod -eq "WinRM") {
                        if ($VaultServerUrl) {
                            New-UDInputAction -Toast "You provided a Vault Server Url, however, your Preferred_PSRemotingMethod is not SSH!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
    
                        if ($($Local_UserName -and !$Local_Password) -or $(!$Local_UserName -and $Local_Password) -or
                        $($Domain_UserName -and !$Domain_Password) -or $(!$Domain_UserName -and $Domain_Password)
                        ) {
                            New-UDInputAction -Toast "Please enter both a UserName and a Password!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
    
                        # Make sure the $Local_UserName is in format $Session:ThisRemoteHost\$Local_UserName
                        if ($Local_UserName -and $Local_Password) {
                            if ($Local_UserName -notmatch "^$Session:ThisRemoteHost\\[a-zA-Z0-9]+$") {
                                $Local_UserName = "$Session:ThisRemoteHost\$Local_UserName"
                            }
        
                            $LocalPwdSecureString = ConvertTo-SecureString $Local_Password -AsPlainText -Force
                            $LocalAdminCreds = [pscredential]::new($Local_UserName,$LocalPwdSecureString)
                        }
    
                        # Make sure the $Domain_UserName is in format $Session:ThisRemoteHost\$Domain_UserName
                        if ($Domain_UserName -and $Domain_Password) {
                            $DomainShortName = $($PUDRSSyncHT."$Session:ThisRemoteHost`Info".NetworkInfo.Domain -split "\.")[0]
                            if ($Domain_UserName -notmatch "^$DomainShortName\\[a-zA-Z0-9]+$") {
                                New-UDInputAction -Toast "Domain_UserName must be in format 'Domain\DomainUser'!" -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
        
                            $DomainPwdSecureString = ConvertTo-SecureString $Domain_Password -AsPlainText -Force
                            $DomainAdminCreds = [pscredential]::new($Domain_UserName,$DomainPwdSecureString)
                        }
                    }
    
                    ##### Test the Credentials #####
    
                    # IMPORTANT NOTE: OpenSSH-Win64's implementation of 'ssh.exe -t' does not work properly...If it did, the TestSSH Private function would be a lot simpler
                                
                    # NOTE: The Principal(s) on the SSH Certificate do NOT determine who you are on the Remote Host. What DOES determine who you are on the Remote Host is
                    # 1) The UserName specified via -UserName with *-PSSession cmdlets
                    # 2) The UserName specified via <UserName>@<DomainShortName>@<RemoteHost> with ssh.exe
    
                    if ($Preferred_PSRemotingMethod -eq "SSH") {
                        # Make sure we have pwsh
                        if (!$(Get-Command pwsh -ErrorAction SilentlyContinue)) {
                            $InstallPwshResult = Install-Program -ProgramName powershell-core -CommandName pwsh.exe -ExpectedInstallLocation "C:\Program Files\PowerShell"
                        }
                        
                        # NOTE: The Await Module comes with the WinSSH Module that we made sure was installed/imported earlier
                        try {
                            Import-Module "$($(Get-Module WinSSH).ModuleBase)\Await\Await.psd1" -ErrorAction Stop
                        }
                        catch {
                            New-UDInputAction -Toast "Unable to load the Await Module! Halting!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
    
                        if ($Preferred_PSRemotingCredType -eq "SSHCertificate") {
                            # Determine if we're going to do UserName/Password Auth or SSH Certificate Auth
                            if (!$UserNamePasswordRequired) {
                                # We need to get the UserName from the SSHCertificate
                                [System.Collections.ArrayList][array]$SSHCertInfo = ssh-keygen -L -f $GetSSHAuthSanity.PublicCertPath
                                $PrincipalsLine = $SSHCertInfo | Where-Object {$_ -match "Principals:"}
                                $PrincipalsLineIndex = $SSHCertInfo.IndexOf($PrincipalsLine)
                                $CriticalOptionsLine = $SSHCertInfo | Where-Object {$_ -match "Critical Options:"}
                                $CriticalOptionsLineIndex = $SSHCertInfo.IndexOf($CriticalOptionsLine)
                                [array]$PrincipalsList = @($SSHCertInfo[$PrincipalsLineIndex..$CriticalOptionsLineIndex] | Where-Object {$_ -notmatch "Principals:|Critical Options:"} | foreach {$_.Trim()})
                                $SSHCertUser = $($PrincipalsList[0] -split '@')[0].Trim()
                                $ShortUserName = $SSHCertUser
                                $DomainShortName = $($($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $Session:ThisRemoteHost}).Domain -split "\.")[0]
                                $Domain_UserName = "$DomainShortName\$ShortUserName"
                            }
                        }
    
                        $OSGuess = $PUDRSSyncHT."$Session:ThisRemoteHost`Info".RHostTableData.OS_Guess
                        if ($OSGuess) {
                            if ($OSGuess -match "Windows|Microsoft") {
                                $UpdatedOSGuess = "Windows"
                            }
                            elseif ($OSGuess -match "Linux") {
                                $UpdatedOSGuess = "Linux"
                            }
                            else {
                                $UpdatedOSGuess = "Windows"
                            }
                        }
                        if (!$OSGuess) {
                            $UpdatedOSGuess = "Windows"
                        }
    
                        $SSHTestSplatParams = @{
                            OSGuess                 = $UpdatedOSGuess
                            RemoteHostNetworkInfo   = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $Session:ThisRemoteHost}
                            OutputTracker           = $PUDRSSyncHT
                        }
                        if ($Local_UserName -and $Local_Password) {
                            $SSHTestSplatParams.Add("LocalUserName",$Local_UserName)
                            $SSHTestSplatParams.Add("LocalPassword",$Local_Password)
                        }
                        if ($Domain_UserName -and $DOmain_Password) {
                            $SSHTestSplatParams.Add("DomainUserName",$Domain_UserName)
                            $SSHTestSplatParams.Add("DomainPassword",$Domain_Password)
                        }
                        if ($GetSSHAuthSanity.PublicCertPath) {
                            $SSHTestSplatParams.Add("PublicCertPath",$GetSSHAuthSanity.PublicCertPath)
                        }
                        # IMPORTANT NOTE: The SSHTest function outputs some UDDashboard objects and sets $script:SSHCheckAsJson as well as $script:SSHOutputPrep
                        # For these reasons, we are assigning SSHTest output to a variable
                        TestSSH @SSHTestSplatParams
    
                        if ($SSHCheckAsJson.Output -ne "ConnectionSuccessful" -and ![bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful")) {
                            New-UDInputAction -Toast "SSH attempts via PowerShell Core 'Invoke-Command' and ssh.exe have failed!" -Duration 10000
                            Sync-UDElement -Id "CredsForm"
                            return
                        }
                    }
                    if ($Preferred_PSRemotingMethod -eq "WinRM") {
                        [System.Collections.ArrayList]$CredentialsToTest = @()
                        if ($LocalAdminCreds) {
                            $PSObj = [pscustomobject]@{CredType = "LocalUser"; PSCredential = $LocalAdminCreds}
                            $null = $CredentialsToTest.Add($PSObj)
                        }
                        if ($DomainAdminCreds) {
                            $PSObj = [pscustomobject]@{CredType = "DomainUser"; PSCredential = $DomainAdminCreds}
                            $null = $CredentialsToTest.Add($PSObj)
                        }
    
                        [System.Collections.ArrayList]$FailedCredentialsA = @()
                        foreach ($CredObj in $CredentialsToTest) {
                            try {
                                $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $Session:ThisRemoteHost -AltCredentials $CredObj.PSCredential -ErrorAction Stop
                
                                if ($GetWorkingCredsResult.DeterminedCredsThatWorkedOnRemoteHost) {
                                    if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                                        #New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                        $null = $FailedCredentialsA.Add($CredObj)
                                    }
                                }
                                else {
                                    $null = $FailedCredentialsA.Add($CredObj)
                                }
                            }
                            catch {
                                #New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                                #New-UDInputAction -Toast "Unable to test $($CredObj.CredType) Credentials! Refreshing page..." -Duration 10000
                                #New-UDInputAction -RedirectUrl "/PSRemotingCreds/$Session:ThisRemoteHost"
                            }
                        }
    
                        if ($($CredentialsToTest.Count -eq 2 -and $FailedCredentialsA.Count -eq 2) -or 
                        $($CredentialsToTest.Count -eq 1 -and $FailedCredentialsA.Count -eq 1)
                        ) {
                            # Since WinRM failed, try and enable WinRM Remotely via Invoke-WmiMethod over RPC Port 135 (if it's open)
                            $RPCPortOpen = $(TestPort -HostName $Session:ThisRemoteHost -Port 135).Open
    
                            [System.Collections.ArrayList]$EnableWinRMSuccess = @()
                            foreach ($CredObj in $CredentialsToTest) {
                                if ($RPCPortOpen) {
                                    try {
                                        $null = EnableWinRMViaRPC -RemoteHostNameOrIP $Session:ThisRemoteHost -Credential $CredObj.PSCredential
                                        $null = $EnableWinRMSuccess.Add($CredObj)
                                        break
                                    }
                                    catch {
                                        #New-UDInputAction -Toast "Failed to enable WinRM Remotely using Credentials $($CredObj.PSCredential.UserName)" -Duration 10000
                                    }
                                }
                            }
    
                            if ($EnableWinRMSuccess.Count -eq 0) {
                                New-UDInputAction -Toast "Unable to Enable WinRM on $Session:ThisRemoteHost via Invoke-WmiMethod over RPC! Please check your credentials." -Duration 10000
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                            else {
                                [System.Collections.ArrayList]$FailedCredentialsB = @()
                                foreach ($CredObj in $CredentialsToTest) {
                                    try {
                                        $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $Session:ThisRemoteHost -AltCredentials $CredObj.PSCredential -ErrorAction Stop
                        
                                        if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                                            #New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                            $null = $FailedCredentialsB.Add($CredObj)
                                        }
                                    }
                                    catch {
                                        New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                                        New-UDInputAction -Toast "Unable to test $($CredObj.CredType) Credentials! Please try again." -Duration 10000
                                        Sync-UDElement -Id "CredsForm"
                                        return
                                    }
                                }
                            }
                        }
    
                        if ($FailedCredentialsA.Count -gt 0 -or $FailedCredentialsB.Count -gt 0) {
                            if ($FailedCredentialsB.Count -gt 0) {
                                foreach ($CredObj in $FailedCredentialsB) {
                                    New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                    $Session:CredentialHT.$Session:ThisRemoteHost."$CredType`Creds" = $null
                                }
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                            if ($FailedCredentialsA.Count -gt 0 -and $FailedCredentialsB.Count -eq 0) {
                                foreach ($CredObj in $FailedCredentialsA) {
                                    New-UDInputAction -Toast "$($CredObj.CredType) Credentials are not valid! Please try again." -Duration 10000
                                    $Session:CredentialHT.$Session:ThisRemoteHost."$CredType`Creds" = $null
                                }
                                Sync-UDElement -Id "CredsForm"
                                return
                            }
                        }
                    }
    
                    if ($DomainAdminCreds) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds = $DomainAdminCreds
                    }
                    if ($LocalAdminCreds) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds = $LocalAdminCreds
                    }
                    if ($VaultServerUrl) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.VaultServerUrl = $VaultServerUrl
                    }
                    if ($Preferred_PSRemotingCredType) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCredType = $Preferred_PSRemotingCredType
                    }
                    if ($Preferred_PSRemotingMethod) {
                        $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingMethod = $Preferred_PSRemotingMethod
                    }
    
                    # Determine $PSRemotingCreds
                    if ($Preferred_PSRemotingCredType -eq "Local") {
                        $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds = $Session:CredentialHT.$Session:ThisRemoteHost.LocalCreds
                    }
                    if ($Preferred_PSRemotingCredType -eq "Domain") {
                        $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds = $Session:CredentialHT.$Session:ThisRemoteHost.DomainCreds
                    }
    
                    if ($Preferred_PSRemotingMethod -eq "SSH") {
                        New-UDInputAction -Toast "SSH was SUCCESSFUL, however, ssh functionality has not been fully implemented yet. Please use WinRM instead." -Duration 10000
                        Sync-UDElement -Id "CredsForm"
                        return
                    }
    
                    New-UDInputAction -RedirectUrl "/ToolSelect/$Session:ThisRemoteHost"
                }
                $Cache:CredsForm
    
                New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                    try {
                        $null = $Session:PSRemotingPageLoadingTracker.Add("FinishedLoading")
                    }
                    catch {
                        Write-Verbose "`$Session:PSRemotingPageLoadingTracker hasn't been set yet..."
                    }
                }
            }
            New-UDColumn -Size 2 -EndPoint {}
        }
    }
    $Page = New-UDPage -Url "/PSRemotingCreds/:RemoteHost" -Endpoint $PSRemotingCredsPageContent
    $null = $Pages.Add($Page)
    
    $RegistryPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:RegistryPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:RegistryPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
            if (!$Session:HKLMChildKeys -or !$Session:HKCUChildKeys -or !$Session:HKCRChildKeys -or !$Session:HKUChildKeys -or !$Session:HKCCChildKeys) {
                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    $null = Invoke-Expression $using:GetRegistrySubKeysFunc
                    $null = Invoke-Expression $using:GetRegistryValuesFunc
    
                    # HKLM and HKCU are already defined by default...
                    $null = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
                    $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
                    $null = New-PSDrive -Name HKCC -PSProvider Registry -Root HKEY_CURRENT_CONFIG
    
                    <#
                    'Get-RegistryValues -path HKLM:\SYSTEM\CurrentControlSet\Control\Network\Connections' Output Example
                    Name                 type data
                    ----                 ---- ----
                    ClassManagers MultiString {{B4C8DF59-D16F-4042-80B7-3557A254B7C5}, {BA126AD3-2166-11D1-B1D0-00805FC1270E}, {BA126AD5-2166-11D1-B1D0-00805FC1270E}, {BA126ADD-2166-11D1-B1D0-00805FC1270E}}
    
    
                    'Get-RegistrySubKeys -path HKLM:\SYSTEM\CurrentControlSet\Control\Network' Output Example
                    Name                                   Path                                                                                                                                   childCount
                    ----                                   ----                                                                                                                                   ----------
                    {4D36E972-E325-11CE-BFC1-08002BE10318} Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}          8
                    {4d36e973-e325-11ce-bfc1-08002be10318} Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4d36e973-e325-11ce-bfc1-08002be10318}          1
                    {4d36e974-e325-11ce-bfc1-08002be10318} Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4d36e974-e325-11ce-bfc1-08002be10318}          9
                    {4d36e975-e325-11ce-bfc1-08002be10318} Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4d36e975-e325-11ce-bfc1-08002be10318}         19
                    Connections                            Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\Connections                                     0
                    LightweightCallHandlers                Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\LightweightCallHandlers                         2
                    NetworkLocationWizard                  Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\NetworkLocationWizard                           0
                    SharedAccessConnection                 Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\SharedAccessConnection                          0
                    #>
    
                    $HKLMChildKeys = Get-RegistrySubKeys -path "HKLM:\" -ErrorAction SilentlyContinue
                    $HKLMValues = Get-RegistryValues -path "HKLM:\" -ErrorAction SilentlyContinue
                    $HKLMCurrentDir = "HKLM:\"
    
                    $HKCUChildKeys = Get-RegistrySubKeys -path "HKCU:\" -ErrorAction SilentlyContinue
                    $HKCUValues = Get-RegistryValues -path "HKCU:\" -ErrorAction SilentlyContinue
                    $HKCUCurrentDir = "HKCU:\"
    
                    $HKCRChildKeys = Get-RegistrySubKeys -path "HKCR:\" -ErrorAction SilentlyContinue
                    $HKCRValues = Get-RegistryValues -path "HKCR:\" -ErrorAction SilentlyContinue
                    $HKCRCurrentDir = "HKCR:\"
                    
                    $HKUChildKeys = Get-RegistrySubKeys -path "HKU:\" -ErrorAction SilentlyContinue
                    $HKUValues = Get-RegistryValues -path "HKU:\" -ErrorAction SilentlyContinue
                    $HKUCurrentDir = "HKU:\"
                    
                    $HKCCChildKeys = Get-RegistrySubKeys -path "HKCC:\" -ErrorAction SilentlyContinue
                    $HKCCValues = Get-RegistryValues -path "HKCC:\" -ErrorAction SilentlyContinue
                    $HKCCCurrentDir = "HKCC:\"
    
                    [pscustomobject]@{
                        HKLMChildKeys   = $HKLMChildKeys
                        HKLMValues      = $HKLMValues
                        HKLMCurrentDir  = $HKLMCurrentDir
                        HKCUChildKeys   = $HKCUChildKeys
                        HKCUValues      = $HKCUValues
                        HKCUCurrentDir  = $HKCUCurrentDir
                        HKCRChildKeys   = $HKCRChildKeys
                        HKCRValues      = $HKCRValues
                        HKCRCurrentDir  = $HKCRCurrentDir
                        HKUChildKeys    = $HKUChildKeys
                        HKUValues       = $HKUValues
                        HKUCurrentDir   = $HKUCurrentDir
                        HKCCChildKeys   = $HKCCChildKeys
                        HKCCValues      = $HKCCValues
                        HKCCCurrentDir  = $HKCCCurrentDir
                    }
                }
                $Session:HKLMChildKeys = $StaticInfo.HKLMChildKeys
                $Session:HKLMValues = $StaticInfo.HKLMValues
                $Session:HKLMCurrentDir = $StaticInfo.HKLMCurrentDir
                [System.Collections.ArrayList]$HKLMObjectsForGridPrep = @()
                if (@($Session:HKLMChildKeys).Count -gt 0) {
                    foreach ($obj in $Session:HKLMChildKeys) {
                        if ($obj.Name) {
                            $null = $HKLMObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                if (@($Session:HKLMValues).Count -gt 0) {
                    foreach ($Obj in $Session:HKLMValues) {
                        if ($obj.Name) {
                            $null = $HKLMObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                $Session:HKLMObjectsForGrid = $HKLMObjectsForGridPrep
    
                $Session:HKCUChildKeys = $StaticInfo.HKCUChildKeys
                $Session:HKCUValues = $StaticInfo.HKCUValues
                $Session:HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
                [System.Collections.ArrayList]$HKCUObjectsForGridPrep = @()
                if (@($Session:HKCUChildKeys).Count -gt 0) {
                    foreach ($obj in $Session:HKCUChildKeys) {
                        if ($obj.Name) {
                            $null = $HKCUObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                if (@($Session:HKCUValues).Count -gt 0) {
                    foreach ($obj in $Session:HKCUValues) {
                        if ($obj.Name) {
                            $null = $HKCUObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                $Session:HKCUObjectsForGrid = $HKCUObjectsForGridPrep
    
                $Session:HKCRChildKeys = $StaticInfo.HKCRChildKeys
                $Session:HKCRValues = $StaticInfo.HKCRValues
                $Session:HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
                [System.Collections.ArrayList]$HKCRObjectsForGridPrep = @()
                if (@($Session:HKCRChildKeys).Count -gt 0) {
                    foreach ($obj in $Session:HKCRChildKeys) {
                        if ($obj.Name) {
                            $null = $HKCRObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                if (@($Session:HKCRValues).Count -gt 0) {
                    foreach ($obj in $Session:HKCRValues) {
                        if ($obj.Name) {
                            $null = $HKCRObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                $Session:HKCRObjectsForGrid = $HKCRObjectsForGridPrep
                
                $Session:HKUChildKeys = $StaticInfo.HKUChildKeys
                $Session:HKUValues = $StaticInfo.HKUValues
                $Session:HKUCurrentDir = $StaticInfo.HKUCurrentDir
                [System.Collections.ArrayList]$HKUObjectsForGridPrep = @()
                if (@($Session:HKUChildKeys).Count -gt 0) {
                    foreach ($obj in $Session:HKCUChildKeys) {
                        if ($obj.Name) {
                            $null = $HKUObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                if (@($Session:HKUValues).Count -gt 0) {
                    foreach ($obj in $Session:HKUValues) {
                        if ($obj.Name) {
                            $null = $HKUObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                $Session:HKUObjectsForGrid = $HKUObjectsForGridPrep
                
                $Session:HKCCChildKeys  = $StaticInfo.HKCCChildKeys
                $Session:HKCCValues = $StaticInfo.HKCCValues
                $Session:HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
                [System.Collections.ArrayList]$HKCCObjectsForGridPrep = @()
                if (@($Session:HKCCChildKeys).Count -gt 0) {
                    foreach ($obj in $Session:HKCCChildKeys) {
                        if ($obj.Name) {
                            $null = $HKCCObjectsForGridPrep.Add($Session:HKCCChildKeys)
                        }
                    }
                }
                if (@($Session:HKCCValues).Count -gt 0) {
                    foreach ($obj in $Session:HKCCValues) {
                        if ($obj.Name) {
                            $null = $HKCCObjectsForGridPrep.Add($obj)
                        }
                    }
                }
                $Session:HKCCObjectsForGrid = $HKCCObjectsForGridPrep
    
    
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKLMChildKeys") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKLMChildKeys",$StaticInfo.HKLMChildKeys)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMChildKeys = $StaticInfo.HKLMChildKeys
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKLMValues") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKLMValues",$StaticInfo.HKLMValues)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMValues = $StaticInfo.HKLMValues
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKLMCurrentDir") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKLMCurrentDir",$StaticInfo.HKLMCurrentDir)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMCurrentDir = $StaticInfo.HKLMCurrentDir
                }
    
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCUChildKeys") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCUChildKeys",$StaticInfo.HKCUChildKeys)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUChildKeys = $StaticInfo.HKCUChildKeys
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCUValues") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCUValues",$StaticInfo.HKCUValues)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUValues = $StaticInfo.HKCUValues
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCUCurrentDir") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCUCurrentDir",$StaticInfo.HKCUCurrentDir)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
                }
    
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCRChildKeys") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCRChildKeys",$StaticInfo.HKCRChildKeys)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRChildKeys = $StaticInfo.HKCRChildKeys
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCRValues") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCRValues",$StaticInfo.HKCRValues)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRValues = $StaticInfo.HKCRValues
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCRCurrentDir") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCRCurrentDir",$StaticInfo.HKCRCurrentDir)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
                }
    
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKUChildKeys") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKUChildKeys",$StaticInfo.HKUChildKeys)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUChildKeys = $StaticInfo.HKUChildKeys
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKUValues") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKUValues",$StaticInfo.HKUValues)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUValues = $StaticInfo.HKUValues
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKUCurrentDir") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKUCurrentDir",$StaticInfo.HKUCurrentDir)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUCurrentDir = $StaticInfo.HKUCurrentDir
                }
    
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCCChildKeys") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCCChildKeys",$StaticInfo.HKCCChildKeys)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCChildKeys = $StaticInfo.HKCCChildKeys
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCCValues") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCCValues",$StaticInfo.HKCCValues)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCValues = $StaticInfo.HKCCValues
                }
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCCCurrentDir") {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCCCurrentDir",$StaticInfo.HKCCCurrentDir)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
                }
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Registry (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            <#
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
    
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Registry$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Registry$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{RootRegistry = Get-ChildItem -Path "$env:SystemDrive\" }
                            }
    
                            # Operations that you want to run once every second go here
                            @{RootRegistry = Get-ChildItem -Path "$env:SystemDrive\"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Registry$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo equal to
                # $RSSyncHash."Registry$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Registry.LiveDataRSInfo = $RSSyncHash."Registry$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
    
            # Static Data Element Example
    
            New-UDCollapsible -Items {
                New-UDCollapsibleItem -Title "HKEY_LOCAL_MACHINE" -Icon laptop -Endpoint {
                    New-UDElement -Id "UpdateHKLMGridObjects" -Tag div -EndPoint {
                        $Session:HKLMGridItemsRefreshed = $False
    
                        [System.Collections.ArrayList]$HKLMObjectsForGridPrep = @()
                        if (@($Session:HKLMChildKeys).Count -gt 0) {
                            foreach ($obj in $Session:HKLMChildKeys) {
                                if ($obj.Name) {
                                    $null = $HKLMObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        if (@($Session:HKLMValues).Count -gt 0) {
                            foreach ($obj in $Session:HKLMValues) {
                                if ($obj.Name) {
                                    $null = $HKLMObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        $Session:HKLMObjectsForGrid = $HKLMObjectsForGridPrep
    
                        $Session:HKLMGridItemsRefreshed = $True
                    }
    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 3 -Endpoint {}
                        New-UDColumn -Size 6 -Endpoint {
                            New-UDElement -Id "CurrentHKLMRootDirTB" -Tag div -EndPoint {
                                <#
                                $RootDirSlashCheck = $Session:HKLMChildKeys[0].Path -split "HKEY_LOCAL_MACHINE\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKLM:"} else {"HKLM:\"}
                                $CurrentDirectory = $Session:HKLMChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                New-UDHeading -Text "Current Directory: $($Session:HKLMCurrentDir)" -Size 5
                            }
                            New-UDElement -Id "NewHKLMRootDirTB" -Tag div -EndPoint {
                                New-UDTextbox -Id "NewHKLMRootDirTBProper" -Label "New Directory"
                            }
                            New-UDButton -Text "Explore" -OnClick {
                                $Session:HKLMUDGridLoadingTracker = "Loading"
                                $NewRootDirTextBox = Get-UDElement -Id "NewHKLMRootDirTBProper"
                                $FullPathToExplore = $NewRootDirTextBox.Attributes['value']
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $HKLMChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKLMValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKLMCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKLMChildKeys   = $HKLMChildKeys
                                        HKLMValues      = $HKLMValues
                                        HKLMCurrentDir  = $HKLMCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKLMChildKeys = $NewPathInfo.HKLMChildKeys
                                $Session:HKLMValues = $NewPathInfo.HKLMValues
                                $Session:HKLMCurrentDir = $NewPathInfo.HKLMCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMChildKeys = $NewPathInfo.HKLMChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMValues = $NewPathInfo.HKLMValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMCurrentDir = $NewPathInfo.HKLMCurrentDir
    
                                $Session:HKLMGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKLMRootDirTB"
                                Sync-UDElement -Id "CurrentHKLMRootDirTB"
                                Sync-UDElement -Id "UpdateHKLMGridObjects"
                                while (!$Session:HKLMGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKLMChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Parent Directory" -OnClick {
                                $Session:HKLMUDGridLoadingTracker = "Loading"
                                <#
                                $RootDirSlashCheck = $Session:HKLMChildKeys[0].Path -split "HKEY_LOCAL_MACHINE\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKLM:"} else {"HKLM:\"}
                                $FullPathToExplorePrep = $Session:HKLMChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                $FullPathToExplore = if ($($Session:HKLMCurrentDir | Split-Path -Parent) -eq "") {
                                    $Session:HKLMCurrentDir
                                }
                                else {
                                    $Session:HKLMCurrentDir | Split-Path -Parent
                                }
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $HKLMChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKLMValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKLMCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKLMChildKeys   = $HKLMChildKeys
                                        HKLMValues      = $HKLMValues
                                        HKLMCurrentDir  = $HKLMCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKLMChildKeys = $NewPathInfo.HKLMChildKeys
                                $Session:HKLMValues = $NewPathInfo.HKLMValues
                                $Session:HKLMCurrentDir = $NewPathInfo.HKLMCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMChildKeys = $NewPathInfo.HKLMChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMValues = $NewPathInfo.HKLMValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMCurrentDir = $NewPathInfo.HKLMCurrentDir
    
                                $Session:HKLMGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKLMRootDirTB"
                                Sync-UDElement -Id "CurrentHKLMRootDirTB"
                                Sync-UDElement -Id "UpdateHKLMGridObjects"
                                while (!$Session:HKLMGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKLMChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Force Refresh" -OnClick {
                                $Session:HKLMUDGridLoadingTracker = "Loading"
                                $Session:HKLMGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKLMRootDirTB"
                                Sync-UDElement -Id "CurrentHKLMRootDirTB"
                                Sync-UDElement -Id "UpdateHKLMGridObjects"
                                while (!$Session:HKLMGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKLMChildItemsUDGrid"
                            }
                        }
                        New-UDColumn -Size 3 -Endpoint {}
                    }
                    New-UDRow -Endpoint {
                        New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                            if ($Session:HKLMUDGridLoadingTracker -eq "Loading") {
                                New-UDHeading -Text "Loading...Please wait..." -Size 6
                                New-UDPreloader -Size small
                            }
                        }
    
                        New-UDColumn -Size 12 -Endpoint {
                            $RootRegistryProperties = @("Name","Path","Type","Data","ChildCount","Explore")
                            $RootRegistryUDGridSplatParams = @{
                                Id              = "HKLMChildItemsUDGrid"
                                Headers         = $RootRegistryProperties
                                Properties      = $RootRegistryProperties
                                PageSize        = 10
                            }
                            New-UDGrid @RootRegistryUDGridSplatParams -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
                                
                                $HKLMGridRefreshed = $False
                                try {
                                    $Session:HKLMObjectsForGrid | foreach {
                                        if ($_.Path) {
                                            $RootDirSlashCheck = $_.Path -split "HKEY_LOCAL_MACHINE\\"
                                            $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKLM:"} else {"HKLM:\"}
                                            $PathUpdatedFormat = $_.Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                        }
    
                                        #elseif ($_.ChildCount -eq 0 -and $($PathUpdatedFormat -split "\\").Count -gt 2) {'Empty'}
                                        [pscustomobject]@{
                                            Name            = $_.Name
                                            Path            = if ($_.Path) {$PathUpdatedFormat} else {$null}
                                            Type            = if ($_.Type) {$_.Type.ToString()} else {"Key"}
                                            Data            = if ($_.Data) {$_.Data -join ", "} else {$null}
                                            ChildCount      = if ($_.ChildCount) {$_.ChildCount} else {$null}
                                            Explore         = if (!$_.Path) {'-'} else {
                                                New-UDButton -Text "Explore" -OnClick {
                                                    $Session:HKLMUDGridLoadingTracker = "Loading"
                                                    #$NewRootDirTextBox = Get-UDElement -Id "NewRootDirTB"
                                                    $FullPathToExplore = $PathUpdatedFormat
    
                                                    $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                    $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                    $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                        Invoke-Expression $using:GetRegistrySubKeysFunc
                                                        Invoke-Expression $using:GetRegistryValuesFunc
    
                                                        $HKLMChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                                        $HKLMValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                                        $HKLMCurrentDir = $args[0]
    
                                                        [pscustomobject]@{
                                                            HKLMChildKeys   = $HKLMChildKeys
                                                            HKLMValues      = $HKLMValues
                                                            HKLMCurrentDir  = $HKLMCurrentDir
                                                        }
                                                    } -ArgumentList $FullPathToExplore
                                                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMChildKeys = $NewPathInfo.HKLMChildKeys
                                                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMValues = $NewPathInfo.HKLMValues
                                                    $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMCurrentDir = $NewPathInfo.HKLMCurrentDir
                                                    $Session:HKLMChildKeys = $NewPathInfo.HKLMChildKeys
                                                    $Session:HKLMValues = $NewPathInfo.HKLMValues
                                                    $Session:HKLMCurrentDir = $NewPathInfo.HKLMCurrentDir
                                                    
                                                    $Session:HKLMGridItemsRefreshed = $False
                                                    Sync-UDElement -Id "NewHKLMRootDirTB"
                                                    Sync-UDElement -Id "CurrentHKLMRootDirTB"
                                                    Sync-UDElement -Id "UpdateHKLMGridObjects"
                                                    while (!$Session:HKLMGridItemsRefreshed) {
                                                        Start-Sleep -Seconds 2
                                                    }
                                                    Sync-UDElement -Id "HKLMChildItemsUDGrid"
                                                }
                                            }
                                        }
                                    } | Out-UDGridData
                                }
                                catch {}
    
                                $HKLMGridRefreshed = $True
                                $Session:HKLMUDGridLoadingTracker = "FinishedLoading"
                            }
                        }
                    }
                }
            }
    
            New-UDCollapsible -Items {
                New-UDCollapsibleItem -Title "HKEY_CURRENT_USER" -Icon laptop -Endpoint {
                    New-UDElement -Id "UpdateHKCUGridObjects" -Tag div -EndPoint {
                        $Session:HKCUGridItemsRefreshed = $False
    
                        [System.Collections.ArrayList]$HKCUObjectsForGridPrep = @()
                        if (@($Session:HKCUChildKeys).Count -gt 0) {
                            foreach ($obj in $Session:HKCUChildKeys) {
                                if ($obj.Name) {
                                    $null = $HKCUObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        if (@($Session:HKCUValues).Count -gt 0) {
                            foreach ($obj in $Session:HKCUValues) {
                                if ($obj.Name) {
                                    $null = $HKCUObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        $Session:HKCUObjectsForGrid = $HKCUObjectsForGridPrep
    
                        $Session:HKCUGridItemsRefreshed = $True
                    }
    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 3 -Endpoint {}
                        New-UDColumn -Size 6 -Endpoint {
                            New-UDElement -Id "CurrentHKCURootDirTB" -Tag div -EndPoint {
                                <#
                                $RootDirSlashCheck = $Session:HKCUChildKeys[0].Path -split "HKEY_CURRENT_USER\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCU:"} else {"HKCU:\"}
                                $CurrentDirectory = $Session:HKCUChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                New-UDHeading -Text "Current Directory: $($Session:HKCUCurrentDir)" -Size 5
                            }
                            New-UDElement -Id "NewHKCURootDirTB" -Tag div -EndPoint {
                                New-UDTextbox -Id "NewHKCURootDirTBProper" -Label "New Directory"
                            }
                            New-UDButton -Text "Explore" -OnClick {
                                $Session:HKCUUDGridLoadingTracker = "Loading"
                                $NewRootDirTextBox = Get-UDElement -Id "NewHKCURootDirTBProper"
                                $FullPathToExplore = $NewRootDirTextBox.Attributes['value']
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $HKCUChildKeys = Get-RegistrySubKeys -path "HKCU:\" -ErrorAction SilentlyContinue
                                    $HKCUValues = Get-RegistryValues -path "HKCU:\" -ErrorAction SilentlyContinue
                                    $HKCUCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKCUChildKeys   = $HKCUChildKeys
                                        HKCUValues      = $HKCUValues
                                        HKCUCurrentDir  = $HKCUCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKCUChildKeys = $StaticInfo.HKCUChildKeys
                                $Session:HKCUValues = $StaticInfo.HKCUValues
                                $Session:HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUChildKeys = $StaticInfo.HKCUChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUValues = $StaticInfo.HKCUValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
    
                                $Session:HKCUGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCURootDirTB"
                                Sync-UDElement -Id "CurrentHKCURootDirTB"
                                Sync-UDElement -Id "UpdateHKCUGridObjects"
                                while (!$Session:HKCUGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCUChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Parent Directory" -OnClick {
                                $Session:HKCUUDGridLoadingTracker = "Loading"
                                <#
                                $RootDirSlashCheck = $Session:HKLMChildKeys[0].Path -split "HKEY_CURRENT_USER\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCU:"} else {"HKCU:\"}
                                $FullPathToExplorePrep = $Session:HKCUChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                $FullPathToExplore = if ($($Session:HKCUCurrentDir | Split-Path -Parent) -eq "") {
                                    $Session:HKCUCurrentDir
                                }
                                else {
                                    $Session:HKCUCurrentDir | Split-Path -Parent
                                }
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $HKCUChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCUValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCUCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKCUChildKeys   = $HKCUChildKeys
                                        HKCUValues      = $HKCUValues
                                        HKCUCurrentDir  = $HKCUCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKCUChildKeys = $StaticInfo.HKCUChildKeys
                                $Session:HKCUValues = $StaticInfo.HKCUValues
                                $Session:HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUChildKeys = $StaticInfo.HKCUChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUValues = $StaticInfo.HKCUValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
    
                                $Session:HKCUGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCURootDirTB"
                                Sync-UDElement -Id "CurrentHKCURootDirTB"
                                Sync-UDElement -Id "UpdateHKCUGridObjects"
                                while (!$Session:HKCUGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCUChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Force Refresh" -OnClick {
                                $Session:HKCUUDGridLoadingTracker = "Loading"
                                $Session:HKCUGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCURootDirTB"
                                Sync-UDElement -Id "CurrentHKCURootDirTB"
                                Sync-UDElement -Id "UpdateHKCUGridObjects"
                                while (!$Session:HKCUGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCUChildItemsUDGrid"
                            }
                        }
                        New-UDColumn -Size 3 -Endpoint {}
                    }
                    New-UDRow -Endpoint {
                        New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                            if ($Session:HKCUUDGridLoadingTracker -eq "Loading") {
                                New-UDHeading -Text "Loading...Please wait..." -Size 6
                                New-UDPreloader -Size small
                            }
                        }
    
                        New-UDColumn -Size 12 -Endpoint {
                            $RootRegistryProperties = @("Name","Path","Type","Data","ChildCount","Explore")
                            $RootRegistryUDGridSplatParams = @{
                                Id              = "HKCUChildItemsUDGrid"
                                Headers         = $RootRegistryProperties
                                Properties      = $RootRegistryProperties
                                PageSize        = 10
                            }
                            New-UDGrid @RootRegistryUDGridSplatParams -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
                                
                                $HKCUGridRefreshed = $False
                                while (!$HKCUGridRefreshed) {
                                    try {
                                        $Session:HKCUObjectsForGrid | foreach {
                                            if ($_.Name) {
                                                if ($_.Path) {
                                                    $RootDirSlashCheck = $_.Path -split "HKEY_CURRENT_USER\\"
                                                    $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCU:"} else {"HKCU:\"}
                                                    $PathUpdatedFormat = $_.Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                                }
    
                                                #elseif ($_.ChildCount -eq 0 -and $($PathUpdatedFormat -split "\\").Count -gt 2) {'Empty'}
                                                [pscustomobject]@{
                                                    Name            = $_.Name
                                                    Path            = if ($_.Path) {$PathUpdatedFormat} else {$null}
                                                    Type            = if ($_.Type) {$_.Type.ToString()} else {"Key"}
                                                    Data            = if ($_.Data) {$_.Data -join ", "} else {$null}
                                                    ChildCount      = if ($_.ChildCount) {$_.ChildCount} else {$null}
                                                    Explore         = if (!$_.Path) {'-'} else {
                                                        New-UDButton -Text "Explore" -OnClick {
                                                            $Session:HKCUUDGridLoadingTracker = "Loading"
                                                            #$NewRootDirTextBox = Get-UDElement -Id "NewRootDirTB"
                                                            $FullPathToExplore = $PathUpdatedFormat
    
                                                            $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                                Invoke-Expression $using:GetRegistrySubKeysFunc
                                                                Invoke-Expression $using:GetRegistryValuesFunc
    
                                                                $HKCUChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKCUValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKCUCurrentDir = $args[0]
    
                                                                [pscustomobject]@{
                                                                    HKCUChildKeys   = $HKCUChildKeys
                                                                    HKCUValues      = $HKCUValues
                                                                    HKCUCurrentDir  = $HKCUCurrentDir
                                                                }
                                                            } -ArgumentList $FullPathToExplore
                                                            $Session:HKCUChildKeys = $StaticInfo.HKCUChildKeys
                                                            $Session:HKCUValues = $StaticInfo.HKCUValues
                                                            $Session:HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUChildKeys = $StaticInfo.HKCUChildKeys
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUValues = $StaticInfo.HKCUValues
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUCurrentDir = $StaticInfo.HKCUCurrentDir
    
                                                            $Session:HKCUGridItemsRefreshed = $False
                                                            Sync-UDElement -Id "NewHKCURootDirTB"
                                                            Sync-UDElement -Id "CurrentHKCURootDirTB"
                                                            Sync-UDElement -Id "UpdateHKCUGridObjects"
                                                            while (!$Session:HKCUGridItemsRefreshed) {
                                                                Start-Sleep -Seconds 2
                                                            }
                                                            Sync-UDElement -Id "HKCUChildItemsUDGrid"
                                                        }
                                                    }
                                                }
                                            }
                                        } | Out-UDGridData
    
                                        $HKCUGridRefreshed = $True
                                        $Session:HKCUUDGridLoadingTracker = "FinishedLoading"
                                    }
                                    catch {}
                                }
                            }
                        }
                    }
                }
            }
    
            New-UDCollapsible -Items {
                New-UDCollapsibleItem -Title "HKEY_CLASSES_ROOT" -Icon laptop -Endpoint {
                    New-UDElement -Id "UpdateHKCRGridObjects" -Tag div -EndPoint {
                        $Session:HKCRGridItemsRefreshed = $False
    
                        [System.Collections.ArrayList]$HKCRObjectsForGridPrep = @()
                        if (@($Session:HKCRChildKeys).Count -gt 0) {
                            foreach ($obj in $Session:HKCRChildKeys) {
                                if ($obj.Name) {
                                    $null = $HKCRObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        if (@($Session:HKCRValues).Count -gt 0) {
                            foreach ($obj in $Session:HKCRValues) {
                                if ($obj.Name) {
                                    $null = $HKCRObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        $Session:HKCRObjectsForGrid = $HKCRObjectsForGridPrep
    
                        $Session:HKCRGridItemsRefreshed = $True
                    }
    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 3 -Endpoint {}
                        New-UDColumn -Size 6 -Endpoint {
                            New-UDElement -Id "CurrentHKCRRootDirTB" -Tag div -EndPoint {
                                <#
                                $RootDirSlashCheck = $Session:HKCRChildKeys[0].Path -split "HKEY_CLASSES_ROOT\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCR:"} else {"HKCR:\"}
                                $CurrentDirectory = $Session:HKCRChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                New-UDHeading -Text "Current Directory: $($Session:HKCRCurrentDir)" -Size 5
                            }
                            New-UDElement -Id "NewHKCRRootDirTB" -Tag div -EndPoint {
                                New-UDTextbox -Id "NewHKCRRootDirTBProper" -Label "New Directory"
                            }
                            New-UDButton -Text "Explore" -OnClick {
                                $Session:HKCRUDGridLoadingTracker = "Loading"
                                $NewRootDirTextBox = Get-UDElement -Id "NewHKCRRootDirTBProper"
                                $FullPathToExplore = $NewRootDirTextBox.Attributes['value']
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $null = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    
                                    $HKCRChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCRValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCRCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKCRChildKeys   = $HKCRChildKeys
                                        HKCRValues      = $HKCRValues
                                        HKCRCurrentDir  = $HKCRCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKCRChildKeys = $StaticInfo.HKCRChildKeys
                                $Session:HKCRValues = $StaticInfo.HKCRValues
                                $Session:HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRChildKeys = $StaticInfo.HKCRChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRValues = $StaticInfo.HKCRValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
    
                                $Session:HKCRGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCRRootDirTB"
                                Sync-UDElement -Id "CurrentHKCRRootDirTB"
                                Sync-UDElement -Id "UpdateHKCRGridObjects"
                                while (!$Session:HKCRGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCRChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Parent Directory" -OnClick {
                                $Session:HKCRUDGridLoadingTracker = "Loading"
                                <#
                                $RootDirSlashCheck = $Session:HKCRChildKeys[0].Path -split "HKEY_CLASSES_ROOT\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCR:"} else {"HKCR:\"}
                                $FullPathToExplorePrep = $Session:HKCRChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                $FullPathToExplore = if ($($Session:HKCRCurrentDir | Split-Path -Parent) -eq "") {
                                    $Session:HKCRCurrentDir
                                }
                                else {
                                    $Session:HKCRCurrentDir | Split-Path -Parent
                                }
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $null = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    
                                    $HKCRChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCRValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCRCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKCRChildKeys   = $HKCRChildKeys
                                        HKCRValues      = $HKCRValues
                                        HKCRCurrentDir  = $HKCRCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKCRChildKeys = $StaticInfo.HKCRChildKeys
                                $Session:HKCRValues = $StaticInfo.HKCRValues
                                $Session:HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRChildKeys = $StaticInfo.HKCRChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRValues = $StaticInfo.HKCRValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
    
                                $Session:HKCRGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCRRootDirTB"
                                Sync-UDElement -Id "CurrentHKCRRootDirTB"
                                Sync-UDElement -Id "UpdateHKCRGridObjects"
                                while (!$Session:HKCRGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCRChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Force Refresh" -OnClick {
                                $Session:HKCRUDGridLoadingTracker = "Loading"
                                $Session:HKCRGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCRRootDirTB"
                                Sync-UDElement -Id "CurrentHKCRRootDirTB"
                                Sync-UDElement -Id "UpdateHKCRGridObjects"
                                while (!$Session:HKCRGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCRChildItemsUDGrid"
                            }
                        }
                        New-UDColumn -Size 3 -Endpoint {}
                    }
                    New-UDRow -Endpoint {
                        New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                            if ($Session:HKCRUDGridLoadingTracker -eq "Loading") {
                                New-UDHeading -Text "Loading...Please wait..." -Size 6
                                New-UDPreloader -Size small
                            }
                        }
    
                        New-UDColumn -Size 12 -Endpoint {
                            $RootRegistryProperties = @("Name","Path","Type","Data","ChildCount","Explore")
                            $RootRegistryUDGridSplatParams = @{
                                Id              = "HKCRChildItemsUDGrid"
                                Headers         = $RootRegistryProperties
                                Properties      = $RootRegistryProperties
                                PageSize        = 10
                            }
                            New-UDGrid @RootRegistryUDGridSplatParams -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
                                
                                $HKCRGridRefreshed = $False
                                while (!$HKCRGridRefreshed) {
                                    try {
                                        $Session:HKCRObjectsForGrid | foreach {
                                            if ($_.Name) {
                                                if ($_.Path) {
                                                    $RootDirSlashCheck = $_.Path -split "HKEY_CLASSES_ROOT\\"
                                                    $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCR:"} else {"HKCR:\"}
                                                    $PathUpdatedFormat = $_.Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                                }
    
                                                #elseif ($_.ChildCount -eq 0 -and $($PathUpdatedFormat -split "\\").Count -gt 2) {'Empty'}
                                                [pscustomobject]@{
                                                    Name            = $_.Name
                                                    Path            = if ($_.Path) {$PathUpdatedFormat} else {$null}
                                                    Type            = if ($_.Type) {$_.Type.ToString()} else {"Key"}
                                                    Data            = if ($_.Data) {$_.Data -join ", "} else {$null}
                                                    ChildCount      = if ($_.ChildCount) {$_.ChildCount} else {$null}
                                                    Explore         = if (!$_.Path) {'-'} else {
                                                        New-UDButton -Text "Explore" -OnClick {
                                                            $Session:HKCRUDGridLoadingTracker = "Loading"
                                                            #$NewRootDirTextBox = Get-UDElement -Id "NewRootDirTB"
                                                            $FullPathToExplore = $PathUpdatedFormat
    
                                                            $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                                Invoke-Expression $using:GetRegistrySubKeysFunc
                                                                Invoke-Expression $using:GetRegistryValuesFunc
    
                                                                $null = New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    
                                                                $HKCRChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKCRValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKCRCurrentDir = $args[0]
    
                                                                [pscustomobject]@{
                                                                    HKCRChildKeys   = $HKCRChildKeys
                                                                    HKCRValues      = $HKCRValues
                                                                    HKCRCurrentDir  = $HKCRCurrentDir
                                                                }
                                                            } -ArgumentList $FullPathToExplore
                                                            $Session:HKCRChildKeys = $StaticInfo.HKCRChildKeys
                                                            $Session:HKCRValues = $StaticInfo.HKCRValues
                                                            $Session:HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRChildKeys = $StaticInfo.HKCRChildKeys
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRValues = $StaticInfo.HKCRValues
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRCurrentDir = $StaticInfo.HKCRCurrentDir
    
                                                            $Session:HKCRGridItemsRefreshed = $False
                                                            Sync-UDElement -Id "NewHKCRRootDirTB"
                                                            Sync-UDElement -Id "CurrentHKCRRootDirTB"
                                                            Sync-UDElement -Id "UpdateHKCRGridObjects"
                                                            while (!$Session:HKCRGridItemsRefreshed) {
                                                                Start-Sleep -Seconds 2
                                                            }
                                                            Sync-UDElement -Id "HKCRChildItemsUDGrid"
                                                        }
                                                    }
                                                }
                                            }
                                        } | Out-UDGridData
    
                                        $HKCRGridRefreshed = $True
                                        $Session:HKCRUDGridLoadingTracker = "FinishedLoading"
    
                                    }
                                    catch {}
                                }
                            }
                        }
                    }
                }
            }
    
            New-UDCollapsible -Items {
                New-UDCollapsibleItem -Title "HKEY_USERS" -Icon laptop -Endpoint {
                    New-UDElement -Id "UpdateHKUGridObjects" -Tag div -EndPoint {
                        $Session:HKUGridItemsRefreshed = $False
    
                        [System.Collections.ArrayList]$HKUObjectsForGridPrep = @()
                        if (@($Session:HKUChildKeys).Count -gt 0) {
                            foreach ($obj in $Session:HKUChildKeys) {
                                if ($obj.Name) {
                                    $null = $HKUObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        if (@($Session:HKUValues).Count -gt 0) {
                            foreach ($obj in $Session:HKUValues) {
                                if ($obj.Name) {
                                    $null = $HKUObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        $Session:HKUObjectsForGrid = $HKUObjectsForGridPrep
    
                        $Session:HKUGridItemsRefreshed = $True
                    }
    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 3 -Endpoint {}
                        New-UDColumn -Size 6 -Endpoint {
                            New-UDElement -Id "CurrentHKURootDirTB" -Tag div -EndPoint {
                                <#
                                $RootDirSlashCheck = $Session:HKUChildKeys[0].Path -split "HKEY_USERS\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKU:"} else {"HKU:\"}
                                $CurrentDirectory = $Session:HKUChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                New-UDHeading -Text "Current Directory: $($Session:HKUCurrentDir)" -Size 5
                            }
                            New-UDElement -Id "NewHKURootDirTB" -Tag div -EndPoint {
                                New-UDTextbox -Id "NewHKURootDirTBProper" -Label "New Directory"
                            }
                            New-UDButton -Text "Explore" -OnClick {
                                $Session:HKUUDGridLoadingTracker = "Loading"
                                $NewRootDirTextBox = Get-UDElement -Id "NewHKURootDirTBProper"
                                $FullPathToExplore = $NewRootDirTextBox.Attributes['value']
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
    
                                    $HKUChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKUValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKUCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKUChildKeys    = $HKUChildKeys
                                        HKUValues       = $HKUValues
                                        HKUCurrentDir   = $HKUCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKUChildKeys = $StaticInfo.HKUChildKeys
                                $Session:HKUValues = $StaticInfo.HKUValues
                                $Session:HKUCurrentDir = $StaticInfo.HKUCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUChildKeys = $StaticInfo.HKUChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUValues = $StaticInfo.HKUValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUCurrentDir = $StaticInfo.HKUCurrentDir
    
                                $Session:HKUGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKURootDirTB"
                                Sync-UDElement -Id "CurrentHKURootDirTB"
                                Sync-UDElement -Id "UpdateHKUGridObjects"
                                while (!$Session:HKUGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKUChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Parent Directory" -OnClick {
                                $Session:HKUUDGridLoadingTracker = "Loading"
                                <#
                                $RootDirSlashCheck = $Session:HKUChildKeys[0].Path -split "HKEY_USER\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKU:"} else {"HKU:\"}
                                $FullPathToExplorePrep = $Session:HKUChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                $FullPathToExplore = if ($($Session:HKUCurrentDir | Split-Path -Parent) -eq "") {
                                    $Session:HKUCurrentDir
                                }
                                else {
                                    $Session:HKUCurrentDir | Split-Path -Parent
                                }
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
    
                                    $HKUChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKUValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKUCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKUChildKeys    = $HKUChildKeys
                                        HKUValues       = $HKUValues
                                        HKUCurrentDir   = $HKUCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKUChildKeys = $StaticInfo.HKUChildKeys
                                $Session:HKUValues = $StaticInfo.HKUValues
                                $Session:HKUCurrentDir = $StaticInfo.HKUCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUChildKeys = $StaticInfo.HKUChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUValues = $StaticInfo.HKUValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUCurrentDir = $StaticInfo.HKUCurrentDir
    
                                $Session:HKUGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKURootDirTB"
                                Sync-UDElement -Id "CurrentHKURootDirTB"
                                Sync-UDElement -Id "UpdateHKUGridObjects"
                                while (!$Session:HKUGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKUChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Force Refresh" -OnClick {
                                $Session:HKUUDGridLoadingTracker = "Loading"
                                $Session:HKUGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKURootDirTB"
                                Sync-UDElement -Id "CurrentHKURootDirTB"
                                Sync-UDElement -Id "UpdateHKUGridObjects"
                                while (!$Session:HKUGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKUChildItemsUDGrid"
                            }
                        }
                        New-UDColumn -Size 3 -Endpoint {}
                    }
                    New-UDRow -Endpoint {
                        New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                            if ($Session:HKUUDGridLoadingTracker -eq "Loading") {
                                New-UDHeading -Text "Loading...Please wait..." -Size 6
                                New-UDPreloader -Size small
                            }
                        }
    
                        New-UDColumn -Size 12 -Endpoint {
                            $RootRegistryProperties = @("Name","Path","Type","Data","ChildCount","Explore")
                            $RootRegistryUDGridSplatParams = @{
                                Id              = "HKUChildItemsUDGrid"
                                Headers         = $RootRegistryProperties
                                Properties      = $RootRegistryProperties
                                PageSize        = 10
                            }
                            New-UDGrid @RootRegistryUDGridSplatParams -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
                                
                                $HKUGridRefreshed = $False
                                while (!$HKUGridRefreshed) {
                                    try {
                                        $Session:HKUObjectsForGrid | foreach {
                                            if ($_.Name) {
                                                if ($_.Path) {
                                                    $RootDirSlashCheck = $_.Path -split "HKEY_USERS\\"
                                                    $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKU:"} else {"HKU:\"}
                                                    $PathUpdatedFormat = $_.Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                                }
    
                                                #elseif ($_.ChildCount -eq 0 -and $($PathUpdatedFormat -split "\\").Count -gt 2) {'Empty'}
                                                [pscustomobject]@{
                                                    Name            = $_.Name
                                                    Path            = if ($_.Path) {$PathUpdatedFormat} else {$null}
                                                    Type            = if ($_.Type) {$_.Type.ToString()} else {"Key"}
                                                    Data            = if ($_.Data) {$_.Data -join ", "} else {$null}
                                                    ChildCount      = if ($_.ChildCount) {$_.ChildCount} else {$null}
                                                    Explore         = if (!$_.Path) {'-'} else {
                                                        New-UDButton -Text "Explore" -OnClick {
                                                            $Session:HKUUDGridLoadingTracker = "Loading"
                                                            #$NewRootDirTextBox = Get-UDElement -Id "NewRootDirTB"
                                                            $FullPathToExplore = $PathUpdatedFormat
    
                                                            $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                                Invoke-Expression $using:GetRegistrySubKeysFunc
                                                                Invoke-Expression $using:GetRegistryValuesFunc
    
                                                                $null = New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
    
                                                                $HKUChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKUValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKUCurrentDir = $args[0]
    
                                                                [pscustomobject]@{
                                                                    HKUChildKeys    = $HKUChildKeys
                                                                    HKUValues       = $HKUValues
                                                                    HKUCurrentDir   = $HKUCurrentDir
                                                                }
                                                            } -ArgumentList $FullPathToExplore
                                                            $Session:HKUChildKeys = $StaticInfo.HKUChildKeys
                                                            $Session:HKUValues = $StaticInfo.HKUValues
                                                            $Session:HKUCurrentDir = $StaticInfo.HKUCurrentDir
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUChildKeys = $StaticInfo.HKUChildKeys
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUValues = $StaticInfo.HKUValues
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUCurrentDir = $StaticInfo.HKUCurrentDir
    
                                                            $Session:HKUGridItemsRefreshed = $False
                                                            Sync-UDElement -Id "NewHKURootDirTB"
                                                            Sync-UDElement -Id "CurrentHKURootDirTB"
                                                            Sync-UDElement -Id "UpdateHKUGridObjects"
                                                            while (!$Session:HKUGridItemsRefreshed) {
                                                                Start-Sleep -Seconds 2
                                                            }
                                                            Sync-UDElement -Id "HKUChildItemsUDGrid"
                                                        }
                                                    }
                                                }
                                            }
                                        } | Out-UDGridData
    
                                        $HKUGridRefreshed = $True
                                        $Session:HKUUDGridLoadingTracker = "FinishedLoading"
    
                                    }
                                    catch {}
                                }
                            }
                        }
                    }
                }
            }
    
            New-UDCollapsible -Items {
                New-UDCollapsibleItem -Title "HKEY_CURRENT_CONFIG" -Icon laptop -Endpoint {
                    New-UDElement -Id "UpdateHKCCGridObjects" -Tag div -EndPoint {
                        $Session:HKCCGridItemsRefreshed = $False
    
                        [System.Collections.ArrayList]$HKCCObjectsForGridPrep = @()
                        if (@($Session:HKCCChildKeys).Count -gt 0) {
                            foreach ($obj in $Session:HKCCChildKeys) {
                                if ($obj.Name) {
                                    $null = $HKCCObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        if (@($Session:HKCCValues).Count -gt 0) {
                            foreach ($obj in $Session:HKCCValues) {
                                if ($obj.Name) {
                                    $null = $HKCCObjectsForGridPrep.Add($obj)
                                }
                            }
                        }
                        $Session:HKCCObjectsForGrid = $HKCCObjectsForGridPrep
    
                        $Session:HKCCGridItemsRefreshed = $False
                    }
    
                    New-UDRow -Endpoint {
                        New-UDColumn -Size 3 -Endpoint {}
                        New-UDColumn -Size 6 -Endpoint {
                            New-UDElement -Id "CurrentHKCCRootDirTB" -Tag div -EndPoint {
                                <#
                                $RootDirSlashCheck = $Session:HKCCChildKeys[0].Path -split "HKEY_CURRENT_CONFIG\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCC:"} else {"HKCC:\"}
                                $CurrentDirectory = $Session:HKCCChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                New-UDHeading -Text "Current Directory: $($Session:HKCCCurrentDir)" -Size 5
                            }
                            New-UDElement -Id "NewHKCCRootDirTB" -Tag div -EndPoint {
                                New-UDTextbox -Id "NewHKCCRootDirTBProper" -Label "New Directory"
                            }
                            New-UDButton -Text "Explore" -OnClick {
                                $Session:HKCCUDGridLoadingTracker = "Loading"
                                $NewRootDirTextBox = Get-UDElement -Id "NewHKCCRootDirTBProper"
                                $FullPathToExplore = $NewRootDirTextBox.Attributes['value']
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $null = New-PSDrive -Name HKCC -PSProvider Registry -Root HKEY_CURRENT_CONFIG
    
                                    $HKCCChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCCValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCCCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKCCChildKeys   = $HKCCChildKeys
                                        HKCCValues      = $HKCCValues
                                        HKCCCurrentDir  = $HKCCCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKCCChildKeys = $StaticInfo.HKCCChildKeys
                                $Session:HKCCValues = $StaticInfo.HKCCValues
                                $Session:HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCChildKeys = $StaticInfo.HKCCChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCValues = $StaticInfo.HKCCValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
    
                                $Session:HKCCGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCCRootDirTB"
                                Sync-UDElement -Id "CurrentHKCCRootDirTB"
                                Sync-UDElement -Id "UpdateHKCCGridObjects"
                                while (!$Session:HKCCGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCCChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Parent Directory" -OnClick {
                                $Session:HKCCUDGridLoadingTracker = "Loading"
                                <#
                                $RootDirSlashCheck = $Session:HKUChildKeys[0].Path -split "HKEY_USER\\"
                                $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKU:"} else {"HKU:\"}
                                $FullPathToExplorePrep = $Session:HKUChildKeys[0].Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                #>
                                $FullPathToExplore = if ($($Session:HKUCurrentDir | Split-Path -Parent) -eq "") {
                                    $Session:HKUCurrentDir
                                }
                                else {
                                    $Session:HKUCurrentDir | Split-Path -Parent
                                }
    
                                $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                    Invoke-Expression $using:GetRegistrySubKeysFunc
                                    Invoke-Expression $using:GetRegistryValuesFunc
    
                                    $null = New-PSDrive -Name HKCC -PSProvider Registry -Root HKEY_CURRENT_CONFIG
    
                                    $HKCCChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCCValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                    $HKCCCurrentDir = $args[0]
    
                                    [pscustomobject]@{
                                        HKCCChildKeys   = $HKCCChildKeys
                                        HKCCValues      = $HKCCValues
                                        HKCCCurrentDir  = $HKCCCurrentDir
                                    }
                                } -ArgumentList $FullPathToExplore
                                $Session:HKCCChildKeys = $StaticInfo.HKCCChildKeys
                                $Session:HKCCValues = $StaticInfo.HKCCValues
                                $Session:HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCChildKeys = $StaticInfo.HKCCChildKeys
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCValues = $StaticInfo.HKCCValues
                                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
    
                                $Session:HKCCGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCCRootDirTB"
                                Sync-UDElement -Id "CurrentHKCCRootDirTB"
                                Sync-UDElement -Id "UpdateHKCCGridObjects"
                                while (!$Session:HKCCGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCCChildItemsUDGrid"
                            }
    
                            New-UDButton -Text "Force Refresh" -OnClick {
                                $Session:HKCCUDGridLoadingTracker = "Loading"
                                $Session:HKCCGridItemsRefreshed = $False
                                Sync-UDElement -Id "NewHKCCRootDirTB"
                                Sync-UDElement -Id "CurrentHKCCRootDirTB"
                                Sync-UDElement -Id "UpdateHKCCGridObjects"
                                while (!$Session:HKCCGridItemsRefreshed) {
                                    Start-Sleep -Seconds 2
                                }
                                Sync-UDElement -Id "HKCCChildItemsUDGrid"
                            }
                        }
                        New-UDColumn -Size 3 -Endpoint {}
                    }
                    New-UDRow -Endpoint {
                        New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                            if ($Session:HKCCUDGridLoadingTracker -eq "Loading") {
                                New-UDHeading -Text "Loading...Please wait..." -Size 6
                                New-UDPreloader -Size small
                            }
                        }
    
                        New-UDColumn -Size 12 -Endpoint {
                            $RootRegistryProperties = @("Name","Path","Type","Data","ChildCount","Explore")
                            $RootRegistryUDGridSplatParams = @{
                                Id              = "HKCCChildItemsUDGrid"
                                Headers         = $RootRegistryProperties
                                Properties      = $RootRegistryProperties
                                PageSize        = 10
                            }
                            New-UDGrid @RootRegistryUDGridSplatParams -Endpoint {
                                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                                $HKCCGridRefreshed = $False
                                while (!$HKCCGridRefreshed) {
                                    try {
                                        $Session:HKCCObjectsForGrid | foreach {
                                            if ($_.Name) {
                                                if ($_.Path) {
                                                    $RootDirSlashCheck = $_.Path -split "HKEY_CURRENT_CONFIG\\"
                                                    $ReplaceString = if ($RootDirSlashCheck[-1][0] -eq "\") {"HKCC:"} else {"HKCC:\"}
                                                    $PathUpdatedFormat = $_.Path -replace "Microsoft.PowerShell.Core\\Registry::.*?\\",$ReplaceString
                                                }
    
                                                #elseif ($_.ChildCount -eq 0 -and $($PathUpdatedFormat -split "\\").Count -gt 2) {'Empty'}
                                                [pscustomobject]@{
                                                    Name            = $_.Name
                                                    Path            = if ($_.Path) {$PathUpdatedFormat} else {$null}
                                                    Type            = if ($_.Type) {$_.Type.ToString()} else {"Key"}
                                                    Data            = if ($_.Data) {$_.Data -join ", "} else {$null}
                                                    ChildCount      = if ($_.ChildCount) {$_.ChildCount} else {$null}
                                                    Explore         = if (!$_.Path) {'-'} else {
                                                        New-UDButton -Text "Explore" -OnClick {
                                                            $Session:HKCCUDGridLoadingTracker = "Loading"
                                                            #$NewRootDirTextBox = Get-UDElement -Id "NewRootDirTB"
                                                            $FullPathToExplore = $PathUpdatedFormat
    
                                                            $GetRegistrySubKeysFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistrySubKeys" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $GetRegistryValuesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RegistryValues" -and $_ -notmatch "function Get-PUDAdminCenter"}
                                                            $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                                                Invoke-Expression $using:GetRegistrySubKeysFunc
                                                                Invoke-Expression $using:GetRegistryValuesFunc
    
                                                                $null = New-PSDrive -Name HKCC -PSProvider Registry -Root HKEY_CURRENT_CONFIG
    
                                                                $HKCCChildKeys = Get-RegistrySubKeys -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKCCValues = Get-RegistryValues -path $args[0] -ErrorAction SilentlyContinue
                                                                $HKCCCurrentDir = $args[0]
    
                                                                [pscustomobject]@{
                                                                    HKCCChildKeys   = $HKCCChildKeys
                                                                    HKCCValues      = $HKCCValues
                                                                    HKCCCurrentDir  = $HKCCCurrentDir
                                                                }
                                                            } -ArgumentList $FullPathToExplore
                                                            $Session:HKCCChildKeys = $StaticInfo.HKCCChildKeys
                                                            $Session:HKCCValues = $StaticInfo.HKCCValues
                                                            $Session:HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCChildKeys = $StaticInfo.HKCCChildKeys
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCValues = $StaticInfo.HKCCValues
                                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCCurrentDir = $StaticInfo.HKCCCurrentDir
    
                                                            $Session:HKCCGridItemsRefreshed = $False
                                                            Sync-UDElement -Id "NewHKCCRootDirTB"
                                                            Sync-UDElement -Id "CurrentHKCCRootDirTB"
                                                            Sync-UDElement -Id "UpdateHKCCGridObjects"
                                                            while (!$Session:HKCCGridItemsRefreshed) {
                                                                Start-Sleep -Seconds 2
                                                            }
                                                            Sync-UDElement -Id "HKCCChildItemsUDGrid"
                                                        }
                                                    }
                                                }
                                            }
                                        } | Out-UDGridData
    
                                        $HKCCGridRefreshed = $True
                                        $Session:HKCCUDGridLoadingTracker = "FinishedLoading"
    
                                    }
                                    catch {}
                                }
                            }
                        }
                    }
                }
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:RegistryPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Registry/:RemoteHost" -Endpoint $RegistryPageContent
    $null = $Pages.Add($Page)
    
    $RolesAndFeaturesPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:RolesAndFeaturesPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:RolesAndFeaturesPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                $OSInfo = Get-CimInstance Win32_OperatingSystem
                if ($OSInfo.Caption -match "Server") {
                    Import-Module ServerManager
                    $RolesAndFeaturesInfo = Get-WindowsFeature
                }
                else {
                    try {
                        Import-Module "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\Dism\Dism.psd1" -ErrorAction Stop
                        $RolesAndFeaturesInfo = Get-WindowsOptionalFeature -Online
                    }
                    catch {
                        $RolesAndFeaturesInfo = [pscustomobject]@{
                            FeatureName         = "Unable to load Dism Module!"
                            State               = "Unable to load Dism Module!"
                            Path                = "Unable to load Dism Module!"
                            Online              = "Unable to load Dism Module!"
                            WinPath             = "Unable to load Dism Module!"
                            SysDrivePath        = "Unable to load Dism Module!"
                            RestartNeeded       = "Unable to load Dism Module!"
                            LogPath             = "Unable to load Dism Module!"
                            ScratchDirectory    = "Unable to load Dism Module!"
                            LogLevel            = "Unable to load Dism Module!"
                        }
                    }
                }
    
                [pscustomobject]@{
                    RolesAndFeaturesInfo    = $RolesAndFeaturesInfo
                }
            }
            $Session:RolesAndFeaturesInfoStatic = $StaticInfo.RolesAndFeaturesInfo
            if ($PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.Keys -notcontains "RolesAndFeaturesInfo") {
                $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.Add("RolesAndFeaturesInfo",$Session:RolesAndFeaturesInfoStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.RolesAndFeaturesInfo = $Session:RolesAndFeaturesInfoStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "RolesAndFeatures (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            <#
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetRolesAndFeaturesOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RolesAndFeaturesOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetRolesAndFeaturesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-RolesAndFeatures" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetRolesAndFeaturesOverviewFunc,$GetRolesAndFeaturesFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "RolesAndFeatures$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "RolesAndFeatures$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllRolesAndFeaturess = Get-RolesAndFeatures}
                            }
    
                            # Operations that you want to run once every second go here
                            @{RolesAndFeaturesSummary = Get-RolesAndFeaturesOverview -channel "Microsoft-Windows-RolesAndFeatureservicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "RolesAndFeatures$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo equal to
                # $RSSyncHash."RolesAndFeatures$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.LiveDataRSInfo = $RSSyncHash."RolesAndFeatures$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            # Dism 'Get-WindowsOptionalFeature -Online' Properties
            <#
                FeatureName      : ADCertificateServicesRole
                State            : Disabled
                Path             :
                Online           : True
                WinPath          :
                SysDrivePath     :
                RestartNeeded    : False
                LogPath          : C:\Windows\Logs\DISM\dism.log
                ScratchDirectory :
                LogLevel         : WarningsInfo
            #>
    
            # ServerManager Get-WindowsFeature Properties
            <#
                Name                      : AD-Certificate
                DisplayName               : Active Directory Certificate Services
                Description               : Active Directory Certificate Services (AD CS) is used to create certification authorities and related role services that allow you to issue and manage certificates used in a variety of applications.
                Installed                 : False
                InstallState              : Available
                FeatureType               : Role
                Path                      : Active Directory Certificate Services
                Depth                     : 1
                DependsOn                 : {}
                Parent                    :
                ServerComponentDescriptor : ServerComponent_AD_Certificate
                SubFeatures               : {ADCS-Cert-Authority, ADCS-Enroll-Web-Pol, ADCS-Enroll-Web-Svc, ADCS-Web-Enrollment...}
                SystemService             : {}
                Notification              : {}
                BestPracticesModelId      : Microsoft/Windows/CertificateServices
                EventQuery                : ActiveDirectoryCertificateServices.Events.xml
                PostConfigurationNeeded   : False
                AdditionalInfo            : {MajorVersion, MinorVersion, NumericId, InstallName}
            #>
    
            $RolesAndFeaturesProperties = @("Name","State","Parent","SubFeatures","DependsOn")
            $RolesAndFeaturesUDGridSplatParams = @{
                Headers         = $RolesAndFeaturesProperties
                Properties      = $RolesAndFeaturesProperties
                NoPaging        = $True
            }
            New-UDGrid @RolesAndFeaturesUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    $OSInfo = Get-CimInstance Win32_OperatingSystem
    
                    if ($OSInfo.Caption -match "Server") {
                        Import-Module ServerManager
                        $RolesAndFeaturesInfo = Get-WindowsFeature
                    }
                    else {
                        try {
                            Import-Module "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\Dism\Dism.psd1" -ErrorAction Stop
                            $RolesAndFeaturesInfo = Get-WindowsOptionalFeature -Online
                        }
                        catch {
                            $RolesAndFeaturesInfo = [pscustomobject]@{
                                FeatureName         = "Unable to load Dism Module!"
                                State               = "Unable to load Dism Module!"
                                Path                = "Unable to load Dism Module!"
                                Online              = "Unable to load Dism Module!"
                                WinPath             = "Unable to load Dism Module!"
                                SysDrivePath        = "Unable to load Dism Module!"
                                RestartNeeded       = "Unable to load Dism Module!"
                                LogPath             = "Unable to load Dism Module!"
                                ScratchDirectory    = "Unable to load Dism Module!"
                                LogLevel            = "Unable to load Dism Module!"
                            }
                        }
                    }
        
                    [pscustomobject]@{
                        RolesAndFeaturesInfo    = $RolesAndFeaturesInfo
                    }
                }
                
                if ($($StaticInfo.RolesAndFeaturesInfo[0] | Get-Member -MemberType Property).Name -contains "FeatureName") {
                    $Session:RolesAndFeaturesInfoStatic = foreach ($obj in $StaticInfo.RolesAndFeaturesInfo) {
                        [pscustomobject]@{
                            Name            = $obj.FeatureName
                            State           = $obj.State # Enabled/Disabled
                            Parent          = "Info Not Available"
                            SubFeatures     = "Info Not Available"
                            DependsOn       = "Info Not Available"
                        }
                    }
                }
                else {
                    $Session:RolesAndFeaturesInfoStatic = foreach ($obj in $StaticInfo.RolesAndFeaturesInfo) {
                        [pscustomobject]@{
                            Name            = $obj.Name
                            State           = if ($obj.Installed) {"Enabled"} else {"Disabled"}
                            Parent          = $obj.Parent
                            SubFeatures     = $obj.SubFeatures -join ", "
                            DependsOn       = $obj.DependsOn -join ", "
                        }
                    }
                }
                $PUDRSSyncHT."$RemoteHost`Info".RolesAndFeatures.RolesAndFeaturesInfo = $Session:RolesAndFeaturesInfoStatic
                
                $Session:RolesAndFeaturesInfoStatic | Out-UDGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:RolesAndFeaturesPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/RolesAndFeatures/:RemoteHost" -Endpoint $RolesAndFeaturesPageContent
    $null = $Pages.Add($Page)
    
    $ScheduledTasksPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:ScheduledTasksPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:ScheduledTasksPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $GetScheduledTasksFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ScheduledTasks" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetScheduledTasksFunc
                
                $AllScheduledTasks = Get-ScheduledTasks
    
                [pscustomobject]@{
                    AllScheduledTasks   = $AllScheduledTasks
                }
            }
            $Session:AllScheduledTasksStatic = $StaticInfo.AllScheduledTasks
            if ($PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.Keys -notcontains "AllScheduledTasks") {
                $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.Add("AllScheduledTasks",$Session:AllScheduledTasksStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.AllScheduledTasks = $Session:AllScheduledTasksStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "ScheduledTasks (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            <#
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetScheduledTasksOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ScheduledTasksOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetScheduledTasksFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ScheduledTasks" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetScheduledTasksOverviewFunc,$GetScheduledTasksFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "ScheduledTasks$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "ScheduledTasks$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllScheduledTaskss = Get-ScheduledTasks}
                            }
    
                            # Operations that you want to run once every second go here
                            @{ScheduledTasksSummary = Get-ScheduledTasksOverview -channel "Microsoft-Windows-ScheduledTaskservicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "ScheduledTasks$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo equal to
                # $RSSyncHash."ScheduledTasks$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.LiveDataRSInfo = $RSSyncHash."ScheduledTasks$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            <#
                PS C:\Users\zeroadmin> $SchTsks[0].ScheduledTaskInfo
    
                LastRunTime        : 8/28/2018 10:50:50 PM
                LastTaskResult     : 0
                NextRunTime        : 8/29/2018 10:50:50 PM
                NumberOfMissedRuns : 0
                TaskName           : GoogleUpdateTaskMachineCore
                TaskPath           : \
                PSComputerName     :
    
                PS C:\Users\zeroadmin> $SchTsks[0].ScheduledTask
    
                TaskPath                                       TaskName                          State
                --------                                       --------                          -----
                \                                              GoogleUpdateTaskMachineCore       Ready
    
                PS C:\Users\zeroadmin> $SchTsks[0].ScheduledTask | fl *
    
                status                : Ready
                TriggersEx            : {MSFT_TaskLogonTrigger, MSFT_TaskDailyTrigger}
                State                 : Ready
                Actions               : {MSFT_TaskExecAction}
                Author                :
                Date                  :
                Description           : Keeps your Google software up to date. If this task is disabled or stopped, your Google software will not be kept up to date, meaning security vulnerabilities that may arise cannot be fixed and features may not
                                        work. This task uninstalls itself when there is no Google software using it.
                Documentation         :
                Principal             : MSFT_TaskPrincipal2
                SecurityDescriptor    :
                Settings              : MSFT_TaskSettings3
                Source                :
                TaskName              : GoogleUpdateTaskMachineCore
                TaskPath              : \
                Triggers              : {MSFT_TaskLogonTrigger, MSFT_TaskDailyTrigger}
                URI                   : \GoogleUpdateTaskMachineCore
                Version               : 1.3.33.17
                PSComputerName        :
                CimClass              : Root/Microsoft/Windows/TaskScheduler:MSFT_ScheduledTask
                CimInstanceProperties : {Actions, Author, Date, Description...}
                CimSystemProperties   : Microsoft.Management.Infrastructure.CimSystemProperties
    
    
            Trigger Value: $($($($($($($SchTsks.ScheduledTask[6].Triggers | gm).TypeName | Sort-Object | Get-Unique) | foreach {$_ -split "/"}) -match "Trigger") -replace "MSFT_Task") -replace "Trigger") -join ", "
            
            #>
    
            $AllScheduledTasksProperties = @("Name","Status","Triggers","NextRunTime","LastRunTime","LastRunResult","Author","Created")
            $AllScheduledTasksUDTableSplatParams = @{
                Headers         = $AllScheduledTasksProperties
                Properties      = $AllScheduledTasksProperties
                PageSize        = 20
            }
            New-UDGrid @AllScheduledTasksUDTableSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetScheduledTasksFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ScheduledTasks" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $SchTsksInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetScheduledTasksFunc
                    
                    $AllScheduledTasks = Get-ScheduledTasks
        
                    [pscustomobject]@{
                        AllScheduledTasks   = $AllScheduledTasks
                    }
                }
                
                $Session:AllScheduledTasksStatic = foreach ($obj in $SchTsksInfo.AllScheduledTasks) {
                    [array]$TriggersPrepA = @($obj.ScheduledTask.Triggers | Where-Object {$_})
                    if ($TriggersPrepA.Count -gt 0) {
                        $TriggersPrep = $($($TriggersPrepA | Get-Member).TypeName | Sort-Object | Get-Unique) | foreach {$_ -split "/"}
                        $Triggers = $($($TriggersPrepA -match "Trigger") -replace "MSFT_Task") -replace "Trigger"
                    }
                    else {
                        $Triggers = $null
                    }
    
                    # LastRunResult Translation
                    # From: https://en.wikipedia.org/wiki/Windows_Task_Scheduler
                    $LastRunResult = switch ($obj.ScheduledTaskInfo.LastTaskResult) {
                        {$('{0:X}' -f $_) -eq '0'}          { "The operation completed successfully." }
                        {$('{0:X}' -f $_) -eq '1'}          { "Incorrect function called or unknown function called." }
                        {$('{0:X}' -f $_) -eq '2'}          { "File not found." }
                        {$('{0:X}' -f $_) -eq '10'}         { "The environment is incorrect." }
                        {$('{0:X}' -f $_) -eq '41300'}      { "Task is ready to run at its next scheduled time." }
                        {$('{0:X}' -f $_) -eq '41301'}      { "The task is currently running." }
                        {$('{0:X}' -f $_) -eq '41302'}      { "The task has been disabled." }
                        {$('{0:X}' -f $_) -eq '41303'}      { "The task has not yet run." }
                        {$('{0:X}' -f $_) -eq '41304'}      { "There are no more runs scheduled for this task." }
                        {$('{0:X}' -f $_) -eq '41305'}      { "One or more of the properties that are needed to run this task have not been set." }
                        {$('{0:X}' -f $_) -eq '41306'}      { "The last run of the task was terminated by the user." }
                        {$('{0:X}' -f $_) -eq '41307'}      { "Either the task has no triggers or the existing triggers are disabled or not set." }
                        {$('{0:X}' -f $_) -eq '41308'}      { "Event triggers do not have set run times." }
                        {$('{0:X}' -f $_) -eq '80010002'}   { "Call was canceled by the message filter." }
                        {$('{0:X}' -f $_) -eq '80041309'}   { "A task's trigger is not found." }
                        {$('{0:X}' -f $_) -eq '8004130A'}   { "One or more of the properties required to run this task have not been set." }
                        {$('{0:X}' -f $_) -eq '8004130B'}   { "There is no running instance of the task." }
                        {$('{0:X}' -f $_) -eq '8004130C'}   { "The Task Scheduler service is not installed on this computer." }
                        {$('{0:X}' -f $_) -eq '8004130D'}   { "The task object could not be opened." }
                        {$('{0:X}' -f $_) -eq '8004130E'}   { "The object is either an invalid task object or is not a task object." }
                        {$('{0:X}' -f $_) -eq '8004130F'}   { "No account information could be found in the Task Scheduler security database for the task indicated." }
                        {$('{0:X}' -f $_) -eq '80041310'}   { "Unable to establish existence of the account specified." }
                        {$('{0:X}' -f $_) -eq '80041311'}   { "Corruption was detected in the Task Scheduler security database." }
                        {$('{0:X}' -f $_) -eq '80041312'}   { "Task Scheduler security services are available only on Windows NT." }
                        {$('{0:X}' -f $_) -eq '80041313'}   { "The task object version is either unsupported or invalid." }
                        {$('{0:X}' -f $_) -eq '80041314'}   { "The task has been configured with an unsupported combination of account settings and run time options." }
                        {$('{0:X}' -f $_) -eq '80041315'}   { "The Task Scheduler Service is not running." }
                        {$('{0:X}' -f $_) -eq '80041316'}   { "The task XML contains an unexpected node." }
                        {$('{0:X}' -f $_) -eq '80041317'}   { "The task XML contains an element or attribute from an unexpected namespace." }
                        {$('{0:X}' -f $_) -eq '80041318'}   { "The task XML contains a value which is incorrectly formatted or out of range." }
                        {$('{0:X}' -f $_) -eq '80041319'}   { "The task XML is missing a required element or attribute." }
                        {$('{0:X}' -f $_) -eq '8004131A'}   { "The task XML is malformed." }
                        {$('{0:X}' -f $_) -eq '0004131B'}   { "The task is registered, but not all specified triggers will start the task." }
                        {$('{0:X}' -f $_) -eq '0004131C'}   { "The task is registered, but may fail to start. Batch logon privilege needs to be enabled for the task principal." }
                        {$('{0:X}' -f $_) -eq '8004131D'}   { "The task XML contains too many nodes of the same type." }
                        {$('{0:X}' -f $_) -eq '8004131E'}   { "The task cannot be started after the trigger end boundary." }
                        {$('{0:X}' -f $_) -eq '8004131F'}   { "An instance of this task is already running." }
                        {$('{0:X}' -f $_) -eq '80041320'}   { "The task will not run because the user is not logged on." }
                        {$('{0:X}' -f $_) -eq '80041321'}   { "The task image is corrupt or has been tampered with." }
                        {$('{0:X}' -f $_) -eq '80041322'}   { "The Task Scheduler service is not available." }
                        {$('{0:X}' -f $_) -eq '80041323'}   { "The Task Scheduler service is too busy to handle your request. Please try again later." }
                        {$('{0:X}' -f $_) -eq '80041324'}   { "The Task Scheduler service attempted to run the task, but the task did not run due to one of the constraints in the task definition." }
                        {$('{0:X}' -f $_) -eq '00041325'}   { "The Task Scheduler service has asked the task to run." }
                        {$('{0:X}' -f $_) -eq '80041326'}   { "The task is disabled." }
                        {$('{0:X}' -f $_) -eq '80041327'}   { "The task has properties that are not compatible with earlier versions of Windows." }
                        {$('{0:X}' -f $_) -eq '80041328'}   { "The task settings do not allow the task to start on demand." }
                        {$('{0:X}' -f $_) -eq 'C000013A'}   { "The application terminated as a result of a CTRL+C." }
                        {$('{0:X}' -f $_) -eq 'C0000142'}   { "The application failed to initialize properly." }
                        Default                             { $null }
                    }
    
                    [pscustomobject]@{
                        Name            = $obj.ScheduledTask.TaskName
                        Status          = $obj.ScheduledTask.status
                        Triggers        = $Triggers
                        NextRunTime     = if ($obj.ScheduledTaskInfo.NextRunTime) {Get-Date $obj.ScheduledTaskInfo.NextRunTime -Format MM-dd-yy_hh:mm:sstt} else {$null}
                        LastRunTime     = if ($obj.ScheduledTaskInfo.LastRunTime) {Get-Date $obj.ScheduledTaskInfo.LastRunTime -Format MM-dd-yy_hh:mm:sstt} else {$null}
                        LastRunResult   = $LastRunResult
                        Author          = $obj.ScheduledTask.Author
                        Created         = if ($obj.ScheduledTask.Date) {Get-Date $obj.ScheduledTask.Date -Format MM-dd-yy_hh:mm:sstt} else {$null}
                    }
                }
                $PUDRSSyncHT."$RemoteHost`Info".ScheduledTasks.AllScheduledTasks = $Session:AllScheduledTasksStatic
                
                $Session:AllScheduledTasksStatic | Out-UDGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:ScheduledTasksPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/ScheduledTasks/:RemoteHost" -Endpoint $ScheduledTasksPageContent
    $null = $Pages.Add($Page)
    
    $ServicesPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:ServicesPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:ServicesPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                $AllServices = Get-CimInstance Win32_Service
    
                [pscustomobject]@{
                    AllServices             = [pscustomobject]$AllServices
                }
            }
            $Session:AllServicesStatic = $StaticInfo.AllServices
            if ($PUDRSSyncHT."$RemoteHost`Info".Services.Keys -notcontains "AllServices") {
                $PUDRSSyncHT."$RemoteHost`Info".Services.Add("AllServices",$Session:AllServicesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Services.AllServices = $Session:AllServicesStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Services (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            <#
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetServicesOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ServicesOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetServicesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Services" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetServicesOverviewFunc,$GetServicesFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Services$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Services$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllServicess = Get-Services}
                            }
    
                            # Operations that you want to run once every second go here
                            @{ServicesSummary = Get-ServicesOverview -channel "Microsoft-Windows-ServiceservicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Services$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo equal to
                # $RSSyncHash."Services$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Services.LiveDataRSInfo = $RSSyncHash."Services$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            <#
                Name                    : AJRouter
                Status                  : OK
                ExitCode                : 1077
                DesktopInteract         : False
                ErrorControl            : Normal
                PathName                : C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted
                ServiceType             : Share Process
                StartMode               : Manual
                Caption                 : AllJoyn Router Service
                Description             : Routes AllJoyn messages for the local AllJoyn clients. If this service is stopped the AllJoyn clients that do not have their own bundled routers will be unable to run.
                InstallDate             :
                CreationClassName       : Win32_Service
                Started                 : False
                SystemCreationClassName : Win32_ComputerSystem
                SystemName              : ZEROTESTING
                AcceptPause             : False
                AcceptStop              : False
                DisplayName             : AllJoyn Router Service
                ServiceSpecificExitCode : 0
                StartName               : NT AUTHORITY\LocalService
                State                   : Stopped
                TagId                   : 0
                CheckPoint              : 0
                DelayedAutoStart        : False
                ProcessId               : 0
                WaitHint                : 0
                PSComputerName          :
                CimClass                : root/cimv2:Win32_Service
                CimInstanceProperties   : {Caption, Description, InstallDate, Name...}
                CimSystemProperties     : Microsoft.Management.Infrastructure.CimSystemProperties
            
            #>
    
            $AllServicesProperties = @("Name","DisplayName","Status","State","StartMode","PathName","Description")
            $AllServicesUDGridSplatParams = @{
                Headers         = $AllServicesProperties
                Properties      = $AllServicesProperties
                PageSize        = 20
            }
            New-UDGrid @AllServicesUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    $AllServices = Get-CimInstance Win32_Service
        
                    [pscustomobject]@{
                        AllServices             = [pscustomobject]$AllServices
                    }
                }
                $Session:AllServicesStatic = $StaticInfo.AllServices
                $PUDRSSyncHT."$RemoteHost`Info".Services.AllServices = $Session:AllServicesStatic
                
                $Session:AllServicesStatic | Out-UDGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:ServicesPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Services/:RemoteHost" -Endpoint $ServicesPageContent
    $null = $Pages.Add($Page)
    
    $StoragePageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:StoragePageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:StoragePageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $GetStorageDiskFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-StorageDisk" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetStorageFileShareFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-StorageFileShare" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetStorageVolumeFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-StorageVolume" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $FunctionsToLoad = @($GetStorageDiskFunc,$GetStorageFileShareFunc,$GetStorageVolumeFunc)
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                $using:FunctionsToLoad | foreach {Invoke-Expression $_}
                
                $DiskSummary = Get-StorageDisk
                $VolumeSummary = Get-StorageVolume
                $FileShareSummary = Get-StorageFileShare
    
                [pscustomobject]@{
                    DiskSummary         = $DiskSummary | foreach {[pscustomobject]$_}
                    VolumeSummary       = $VolumeSummary | foreach {[pscustomobject]$_}
                    FileShareSummary    = $FileShareSummary | foreach {[pscustomobject]$_}
                }
            }
            $Session:DiskSummaryStatic = $StaticInfo.DiskSummary
            $Session:VolumeSummaryStatic = $StaticInfo.VolumeSummary
            $Session:FileShareSummaryStatic = $StaticInfo.FileShareSummary
            if ($PUDRSSyncHT."$RemoteHost`Info".Storage.Keys -notcontains "DiskSummary") {
                $PUDRSSyncHT."$RemoteHost`Info".Storage.Add("DiskSummary",$StaticInfo.DiskSummary)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Storage.DiskSummary = $StaticInfo.DiskSummary
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Storage.Keys -notcontains "VolumeSummary") {
                $PUDRSSyncHT."$RemoteHost`Info".Storage.Add("VolumeSummary",$Session:VolumeSummaryStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Storage.VolumeSummary = $Session:VolumeSummaryStatic
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Storage.Keys -notcontains "FileShareSummary") {
                $PUDRSSyncHT."$RemoteHost`Info".Storage.Add("FileShareSummary",$Session:FileShareSummaryStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Storage.FileShareSummary = $Session:FileShareSummaryStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Storage (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            <#
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetStorageOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-StorageOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetStorageFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Storage" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetStorageOverviewFunc,$GetStorageFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Storage$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Storage$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllStorages = Get-Storage}
                            }
    
                            # Operations that you want to run once every second go here
                            @{StorageSummary = Get-StorageOverview -channel "Microsoft-Windows-StorageervicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Storage$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo equal to
                # $RSSyncHash."Storage$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Storage.LiveDataRSInfo = $RSSyncHash."Storage$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            <#        
                PS C:\Users\zeroadmin> Get-StorageDisk
    
                Name                           Value
                ----                           -----
                UniqueId                       60022480D969B073D0ADAF27131151DF
                SerialNumber
                ProvisioningType               1
                IsSystem                       True
                LogicalSectorSize              512
                Number                         0
                IsHighlyAvailable              False
                HealthStatus                   0
                volumeIds                      {\\?\Volume{96ae8ad0-e1c2-4cd0-9109-83a47970250f}\, \\?\Volume{7c1da3c0-361d-4803-939c-6e375035ab96}\}
                PhysicalSectorSize             4096
                NumberOfPartitions             4
                Model                          Virtual Disk
                IsReadOnly                     False
                OperationalStatus              {53264}
                IsScaleOut                     False
                IsClustered                    False
                IsOffline                      False
                FirmwareVersion                1.0
                LargestFreeExtent              0
                BootFromDisk                   True
                BusType                        10
                Size                           68719476736
                OfflineReason                  0
                AllocatedSize                  68719476736
                Location                       Integrated : Adapter 0 : Port 0 : Target 0 : LUN 0
                IsBoot                         True
                FriendlyName                   Msft Virtual Disk
                UniqueIdFormat                 3
                Path                           \\?\scsi#disk&ven_msft&prod_virtual_disk#000000#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}
                PartitionStyle                 2
                Signature
                
    
                PS C:\Users\zeroadmin> Get-StorageVolume
    
                Name                           Value
                ----                           -----
                UniqueId                       \\?\Volume{7c1da3c0-361d-4803-939c-6e375035ab96}\
                FileSystemLabel
                Name                           (C:)
                IsSystem                       False
                FileSystemType                 14
                DiskNumber                     0
                FileSystem                     NTFS
                IsBoot                         True
                SizeRemaining                  43436892160
                IsActive                       False
                OperationalStatus              {2}
                HealthStatus                   0
                DriveType                      3
                PartitionNumber                4
                DriveLetter                    C
                AllocationUnitSize             4096
                Size                           68124930048
                DedupMode                      4
                Path                           \\?\Volume{7c1da3c0-361d-4803-939c-6e375035ab96}\
                
    
                PS C:\Users\zeroadmin> Get-StorageFileShare
    
                Name                           Value
                ----                           -----
                UniqueId                       smb|ZeroTesting.zero.lab/C$
                Description                    Default share
                EncryptData                    False
                ContinuouslyAvailable          False
                IsHidden                       True
                ShareState                     1
                Name                           C$
                FileSharingProtocol            3
                HealthStatus                   0
                OperationalStatus              {53264}
                VolumePath                     \
    
            #>
    
            # Disk Summary
            $DiskSummaryProperties = @("Number","Name","Health","Status","Unallocated","Capacity","BootDisk")
            $DiskSummaryUDGridSplatParams = @{
                Title           = "Disk Summary"
                Headers         = $DiskSummaryProperties
                Properties      = $DiskSummaryProperties
                NoPaging        = $True
            }
            New-UDGrid @DiskSummaryUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetStorageDiskFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-StorageDisk" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetStorageDiskFunc
                    
                    $DiskSummary = Get-StorageDisk
    
                    [pscustomobject]@{
                        DiskSummary         = $DiskSummary | foreach {[pscustomobject]$_}
                    }
                }
                $Session:DiskSummaryStatic = foreach ($obj in $StaticInfo.DiskSummary) {
                    $Health = switch ($obj.HealthStatus) {
                        '0'     {"Healthy"}
                        '1'     {"Warning"}
                        '2'     {"Unhealthy"}
                        '5'     {"Unknown"}
                        Default {$null}
                    }
    
                    [pscustomobject]@{
                        Number          = $obj.Number
                        Name            = $obj.FriendlyName
                        Health          = $Health
                        Status          = if ($obj.isOffline) {"Offline"} else {"Online"}
                        Unallocated     = [Math]::Round($($($obj.Size - $obj.AllocatedSize) / 1GB),2).ToString() + 'GB'
                        Capacity        = [Math]::Round($($obj.Size / 1GB),2).ToString() + 'GB'
                        BootDisk        = if ($obj.isBoot) {"True"} else {"False"}
                    }
                }
                $PUDRSSyncHT."$RemoteHost`Info".Storage.DiskSummary = $Session:DiskSummaryStatic
                
                $Session:DiskSummaryStatic | Out-UDGridData
            }
    
            # Volume Summary
            $VolumeSummaryProperties = @("Name","DiskNumber","BootVolume","DriveType","FileSystem","Health","SpaceRemaining","Size")
            $VolumeSummaryUDGridSplatParams = @{
                Title           = "Volume Summary"
                Headers         = $VolumeSummaryProperties
                Properties      = $VolumeSummaryProperties
                NoPaging        = $True
            }
            New-UDGrid @VolumeSummaryUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetStorageVolumeFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-StorageVolume" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetStorageVolumeFunc
                    
                    $VolumeSummary = Get-StorageVolume
    
                    [pscustomobject]@{
                        VolumeSummary       = $VolumeSummary | foreach {[pscustomobject]$_}
                    }
                }
                $Session:VolumeSummaryStatic = foreach ($obj in $StaticInfo.VolumeSummary) {
                    $Health = switch ($obj.HealthStatus) {
                        '0'     {"Healthy"}
                        '1'     {"Warning"}
                        '2'     {"Unhealthy"}
                        '5'     {"Unknown"}
                        Default {$null}
                    }
    
                    $DriveType = switch ($obj.DriveType) {
                        '0'     {"Unknown"}
                        '1'     {"No Root Directory"}
                        '2'     {"Removeable Disk"}
                        '3'     {"Local Disk"}
                        '4'     {"Network Drive"}
                        '5'     {"Compact Disk"}
                        '6'     {"RAM Disk"}
                        Default {$null}
                    }
    
                    [pscustomobject]@{
                        Name            = $obj.Name
                        DiskNumber      = $obj.DiskNumber
                        BootVolume      = $obj.isBoot.ToString()
                        DriveType       = $DriveType
                        FileSystem      = $obj.FileSystem
                        Health          = $Health
                        SpaceRemaining  = [Math]::Round($($obj.SizeRemaining / 1GB),2).ToString() + 'GB'
                        Size            = [Math]::Round($($obj.Size / 1GB),2).ToString() + 'GB'
                    }
                }
                $PUDRSSyncHT."$RemoteHost`Info".Storage.VolumeSummary = $Session:VolumeSummaryStatic
                
                $Session:VolumeSummaryStatic | Out-UDGridData
            }
    
            # FileShare Summary
            $FileShareSummaryProperties = @("Name","Health","ShareState","FileSharingProtocol","EncryptData","Hidden")
            $FileShareSummaryUDGridSplatParams = @{
                Title           = "FileShare Summary"
                Headers         = $FileShareSummaryProperties
                Properties      = $FileShareSummaryProperties
                NoPaging        = $True
            }
            New-UDGrid @FileShareSummaryUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetStorageFileShareFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-StorageFileShare" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetStorageFileShareFunc
                    
                    $FileShareSummary = Get-StorageFileShare
    
                    [pscustomobject]@{
                        FileShareSummary    = $FileShareSummary | foreach {[pscustomobject]$_}
                    }
                }
                # See: https://docs.microsoft.com/en-us/previous-versions/windows/desktop/stormgmt/msft-fileshare
                $Session:FileShareSummaryStatic = foreach ($obj in $StaticInfo.FileShareSummary) {
                    $Health = switch ($obj.HealthStatus) {
                        '0'     {"Healthy"}
                        '1'     {"Warning"}
                        '2'     {"Unhealthy"}
                        '5'     {"Unknown"}
                        Default {$null}
                    }
    
                    $ShareState = switch ($obj.ShareState) {
                        '0'     {"Pending"}
                        '1'     {"Online"}
                        '2'     {"Offline"}
                        Default {$null}
                    }
    
                    $FileSharingProtocol = switch ($obj.FileSharingProtocol) {
                        '2'     {"NFS"}
                        '3'     {"CIFS(SMB)"}
                        Default {$null}
                    }
    
                    [pscustomobject]@{
                        Name                = $obj.Name
                        Health              = $Health
                        ShareState          = $ShareState
                        FileSharingProtocol = $FileSharingProtocol
                        EncryptData         = $obj.EncryptData.ToString()
                        Hidden              = $obj.IsHidden.ToString()
                    }
                }
                
                $PUDRSSyncHT."$RemoteHost`Info".Storage.FileShareSummary = $Session:FileShareSummaryStatic
                
                $Session:FileShareSummaryStatic | Out-UDGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:StoragePageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Storage/:RemoteHost" -Endpoint $StoragePageContent
    $null = $Pages.Add($Page)
    
    #region >> Test Page
    
    $TestPageContent = {
        New-UDTable -Title "Users" -Headers @("Name", "Emails per Day") -Endpoint {
            Import-Module UniversalDashboard.Sparklines
            @(
                [PSCustomObject]@{"Name" = "Adam"; Values = @(12,12,4,2,75,23,54,12); Color = "#234254"}
                [PSCustomObject]@{"Name" = "Jon"; Values = @(2,42,33,21,11,3,32,9); Color = "#453423"}
                [PSCustomObject]@{"Name" = "Bill"; Values = @(1,92,40,21,7,3,2,12); Color = "#923923"}
                [PSCustomObject]@{"Name" = "Ted"; Values = @(112,11,41,2,5,63,74,12); Color = "#A43534"}
                [PSCustomObject]@{"Name" = "Tommy"; Values = @(12,2,42,21,18,26,26,19); Color = "#593493"}
            ) | ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Name
                    Sparkline = New-UDSparkline -Data $_.Values -Color $_.Color
                }
            } | Out-UDTableData -Property @("Name", "Sparkline")
        }
    }
    $Page = New-UDPage -Url "/Test" -Endpoint $TestPageContent
    $null = $Pages.Add($Page)
    
    #endregion >> Test Page
    
    #region >> Tool Select Page
    
    $ToolSelectPageContent = {
        param($RemoteHost)
    
        New-UDColumn -Endpoint {$Session:ThisRemoteHost = $RemoteHost}
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, we can't use the $DisconnectedPageContent directly here. It needs to be a different object before it actually outputs
        # UD Elements. Not sure why.
        $RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else 
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:ToolSelectPageLoadingTracker = [System.Collections.ArrayList]::new()
                #$PUDRSSyncHT.ToolSelectPageLoadingTracker = $Session:ToolSelectPageLoadingTracker
            }
            #New-UDHeading -Text "Select a Tool" -Size 4
        }
    
        New-UDRow -Columns {
            New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                if ($Session:ToolSelectPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            $RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $Session:ThisRemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/PSRemotingCreds/$Session:ThisRemoteHost"
                #Write-Error "Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds is null"
            }
            else {
                # Check $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds Credentials. If they don't work, redirect to "/PSRemotingCreds/$Session:ThisRemoteHost"
                try {
                    $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $RHostIP -AltCredentials $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds -ErrorAction Stop
    
                    if ($GetWorkingCredsResult.DeterminedCredsThatWorkedOnRemoteHost) {
                        if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                            Invoke-UDRedirect -Url "/PSRemotingCreds/$Session:ThisRemoteHost"
                            #Write-Error "GetWorkingCredentials A"
                        }
                    }
                    else {
                        Invoke-UDRedirect -Url "/PSRemotingCreds/$Session:ThisRemoteHost"
                        #Write-Error "GetWorkingCredentials B"
                    }
                }
                catch {
                    Invoke-UDRedirect -Url "/PSRemotingCreds/$Session:ThisRemoteHost"
                    #Write-Error $_
                }
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$Session:ThisRemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $Session:ThisRemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                Invoke-UDRedirect -Url "/Disconnected/$Session:ThisRemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","CredSSP","DateTime") -AutoRefresh -RefreshInterval 5 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $Session:ThisRemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $Session:ThisRemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                <#
                                $TableData = @{
                                    RemoteHost      = $Session:ThisRemoteHost.ToUpper()
                                    Status          = "Disconnected"
                                }
                                #>
                                Invoke-UDRedirect -Url "/Disconnected/$Session:ThisRemoteHost"
                            }
    
                            #region >> Gather Some Initial Info From $Session:ThisRemoteHost
    
                            $GetServerInventoryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ServerInventory" -and $_ -notmatch "function Get-PUDAdminCenter"}
                            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                Invoke-Expression $using:GetServerInventoryFunc
    
                                [pscustomobject]@{ServerInventoryStatic = Get-ServerInventory}
                            }
                            $Session:ServerInventoryStatic = $StaticInfo.ServerInventoryStatic
                            $PUDRSSyncHT."$Session:ThisRemoteHost`Info".ServerInventoryStatic = $Session:ServerInventoryStatic
    
                            #endregion >> Gather Some Initial Info From $Session:ThisRemoteHost
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Previous = $PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Previous = $PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Current = $PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataRSInfo.LiveOutput.Clone()
                            }
                            
                            if ($PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Previous.Count -eq 0) {
                                if ($Session:ServerInventoryStatic.IsCredSSPEnabled) {
                                    $CredSSPStatus = "Enabled"
                                }
                                else {
                                    $CredSSPStatus = "Disabled"
                                }
                            }
                            elseif (@($PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Previous.ServerInventory).Count -gt 0) {
                                if (@($PUDRSSyncHT."$Session:ThisRemoteHost`Info".LiveDataTracker.Previous.ServerInventory)[-1].IsCredSSPEnabled) {
                                    $CredSSPStatus = "Enabled"
                                }
                                else {
                                    $CredSSPStatus = "Disabled"
                                }
                            }
                            else {
                                $CredSSPStatus = "NotYetDetermined"
                            }
                            $TableData.Add("CredSSP",$CredSSPStatus)
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","CredSSP","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected to $Session:ThisRemoteHost
    
            #region >> Create the Tool Select Content
            
            if ($ConnectionStatus -eq "Connected") {
                [System.Collections.ArrayList]$DynPageRows = @()
                $RelevantDynamicPages = $DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"}
                $ItemsPerRow = 3
                $NumberOfRows = $DynamicPages.Count / $ItemsPerRow
                for ($i=0; $i -lt $NumberOfRows; $i++) {
                    New-Variable -Name "Row$i" -Value $(New-Object System.Collections.ArrayList) -Force
    
                    if ($i -eq 0) {$j = 0} else {$j = $i * $ItemsPerRow}
                    $jLoopLimit = $j + $($ItemsPerRow - 1)
                    while ($j -le $jLoopLimit) {
                        $null = $(Get-Variable -Name "Row$i" -ValueOnly).Add($RelevantDynamicPages[$j])
                        $j++
                    }
    
                    $null = $DynPageRows.Add($(Get-Variable -Name "Row$i" -ValueOnly))
                }
    
                foreach ($DynPageRow in $DynPageRows) {
                    New-UDRow -Endpoint {
                        foreach ($DynPage in $DynPageRow) {
                            # Make sure we're connected before loadting the UDCards
                            $DynPageNoSpace = $DynPage -replace "[\s]",""
                            $CardId = $DynPageNoSpace + "Card"
                            New-UDColumn -Size 4 -Endpoint {
                                if ($DynPage -ne $null) {
                                    $Links = @(New-UDLink -Text $DynPage -Url "/$DynPageNoSpace/$Session:ThisRemoteHost" -Icon dashboard)
                                    New-UDCard -Title $DynPage -Id $CardId -Text "$DynPage Info" -Links $Links
                                }
                            }
                        }
                    }
                }
    
                $null = $Session:ToolSelectPageLoadingTracker.Add("FinishedLoading")
            }
    
            #endregion >> Create the Tool Select Content
        }
    }
    $Page = New-UDPage -Url "/ToolSelect/:RemoteHost" -Endpoint $ToolSelectPageContent
    $null = $Pages.Add($Page)
    
    #endregion >> Tool Select Page
    
    $UpdatesPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:UpdatesPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:UpdatesPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $GetWUAHistoryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-WUAHistory" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetPendingUpdatesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-PendingUpdates" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                Invoke-Expression $using:GetPendingUpdatesFunc
                Invoke-Expression $using:GetWUAHistoryFunc
                
                $UpdatesHistory = Get-WUAHistory
                $PendingUpdates = Get-PendingUpdates
    
                [pscustomobject]@{
                    UpdatesHistory      = $UpdatesHistory
                    PendingUpdates      = $PendingUpdates
                }
            }
            $Session:UpdatesHistoryStatic = $StaticInfo.UpdatesHistory
            $Session:PendingUpdatesStatic = $StaticInfo.PendingUpdates
            if ($PUDRSSyncHT."$RemoteHost`Info".Updates.Keys -notcontains "UpdatesHistory") {
                $PUDRSSyncHT."$RemoteHost`Info".Updates.Add("UpdatesHistory",$Session:UpdatesHistoryStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Updates.UpdatesHistory = $Session:UpdatesHistoryStatic
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Updates.Keys -notcontains "PendingUpdates") {
                $PUDRSSyncHT."$RemoteHost`Info".Updates.Add("PendingUpdates",$Session:PendingUpdatesStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Updates.PendingUpdates = $Session:PendingUpdatesStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "Updates (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            <#
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetUpdatesOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-UpdatesOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetUpdatesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Updates" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetUpdatesOverviewFunc,$GetUpdatesFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "Updates$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "Updates$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllUpdatess = Get-Updates}
                            }
    
                            # Operations that you want to run once every second go here
                            @{UpdatesSummary = Get-UpdatesOverview -channel "Microsoft-Windows-UpdateservicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "Updates$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo equal to
                # $RSSyncHash."Updates$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".Updates.LiveDataRSInfo = $RSSyncHash."Updates$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            <#
                PS C:\Users\zeroadmin> $testWUAHist[0]
    
                Result              : Succeeded
                UpdateId            : 7aea2f20-80a5-44b7-aab1-f1f491651c13
                RevisionNumber      : 200
                Product             : Windows Defender
                Operation           : 1
                ResultCode          : 2
                HResult             : 0
                Date                : 8/29/2018 9:36:50 PM
                UpdateIdentity      : System.__ComObject
                Title               : Definition Update for Windows Defender Antivirus - KB2267602 (Definition 1.275.400.0)
                Description         : Install this update to revise the definition files that are used to detect viruses, spyware, and other potentially unwanted software. Once you have installed this item, it cannot be removed.
                UnmappedResultCode  : 0
                ClientApplicationID : Windows Defender (77BDAF73-B396-481F-9042-AD358843EC24)
                ServerSelection     : 2
                ServiceID           :
                UninstallationSteps : System.__ComObject
                UninstallationNotes :
                SupportUrl          : https://go.microsoft.com/fwlink/?LinkId=52661
                Categories          : System.__ComObject
    
    
                PS C:\Users\zeroadmin> $testPendUp[0]
    
                Computername     : ZEROTESTING
                Title            : Windows Malicious Software Removal Tool x64 - August 2018 (KB890830)
                KB               : 890830
                SecurityBulletin :
                MsrcSeverity     :
                IsDownloaded     : False
                Url              : http://support.microsoft.com/kb/890830
                Categories       : {Update Rollups, Windows Server 2016}
                BundledUpdates   : @{Title=Windows Malicious Software Removal Tool - August 2018 (KB890830) Multi-Lingual - Delta 5;
                                DownloadUrl=http://download.windowsupdate.com/c/msdownload/update/software/uprl/2018/08/windows-kb890830-x64-v5.63-delta_6ba4a8c5a8bd8441bbbca3dcbf38f337fefc1a82.exe}
            
            #>
    
            $UpdatesHistoryProperties = @("Title","Result","Product","KB","Date","Description","SupportUrl")
            $UpdatesHistoryUDGridSplatParams = @{
                Title           = "Updates History"
                Headers         = $UpdatesHistoryProperties
                Properties      = $UpdatesHistoryProperties
                PageSize        = 10
            }
            New-UDGrid @UpdatesHistoryUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetWUAHistoryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-WUAHistory" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetWUAHistoryFunc
                    
                    $UpdatesHistory = Get-WUAHistory
    
                    [pscustomobject]@{
                        UpdatesHistory      = $UpdatesHistory
                    }
                }
                $Session:UpdatesHistoryStatic = foreach ($obj in $StaticInfo.UpdatesHistory) {
                    [pscustomobject]@{
                        Title       = $obj.Title
                        Result      = $obj.Result
                        Product     = $obj.Product
                        KB          = $($obj.Title | Select-String -Pattern "KB[0-9]+").Matches.Value
                        Date        = Get-Date $obj.Date -Format MM-dd-yy_hh:mm:sstt
                        Description = $obj.Description
                        SupportUrl  = $obj.SupportUrl
                    }
                }
                $PUDRSSyncHT."$RemoteHost`Info".Updates.UpdatesHistory = $Session:UpdatesHistoryStatic
                
                $Session:UpdatesHistoryStatic | Out-UDGridData
            }
    
            $PendingUpdatesProperties = @("Title","KB","MsrcSeverity","IsDownloaded","Url","Categories")
            $PendingUpdatesUDGridSplatParams = @{
                Title           = "Pending Updates"
                Headers         = $PendingUpdatesProperties
                Properties      = $PendingUpdatesProperties
                PageSize        = 10
            }
            New-UDGrid @PendingUpdatesUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetPendingUpdatesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-PendingUpdates" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetPendingUpdatesFunc
                    
                    $PendingUpdates = Get-PendingUpdates
    
                    [pscustomobject]@{
                        PendingUpdates      = $PendingUpdates
                    }
                }
                $Session:PendingUpdatesStatic = foreach ($obj in $StaticInfo.PendingUpdates) {
                    [pscustomobject]@{
                        Title               = $obj.Title
                        KB                  = 'KB' + $obj.KB
                        MsrcSeverity        = $obj.MsrcSeverity
                        IsDownloaded        = $obj.IsDownloaded
                        Url                 = $obj.Url
                        Categories          = $obj.Categories -join ", "
                    }
                }
                $PUDRSSyncHT."$RemoteHost`Info".Updates.PendingUpdates = $Session:PendingUpdatesStatic
                
                $Session:PendingUpdatesStatic | Out-UDGridData
            }
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:UpdatesPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/Updates/:RemoteHost" -Endpoint $UpdatesPageContent
    $null = $Pages.Add($Page)
    
    $UsersAndGroupsPageContent = {
        param($RemoteHost)
    
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
        #region >> Ensure $RemoteHost is Valid
    
        if ($PUDRSSyncHT.RemoteHostList.HostName -notcontains $RemoteHost) {
            $ErrorText = "The Remote Host $($RemoteHost.ToUpper()) is not a valid Host Name!"
        }
    
        if ($ErrorText) {
            New-UDRow -Columns {
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text $ErrorText -Size 6
                }
                New-UDColumn -Size 4 -Content {
                    New-UDHeading -Text ""
                }
            }
        }
    
        # If $RemoteHost isn't valid, don't load anything else
        if ($ErrorText) {
            return
        }
    
        #endregion >> Ensure $RemoteHost is Valid
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Session:UsersAndGroupsPageLoadingTracker = [System.Collections.ArrayList]::new()
            }
            New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
                if ($Session:UsersAndGroupsPageLoadingTracker -notcontains "FinishedLoading") {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        # Master Endpoint - All content will be within this Endpoint so that we can reference $Cache: and $Session: scope variables
        New-UDColumn -Size 12 -Endpoint {
            #region >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            $PUDRSSyncHT = $global:PUDRSSyncHT
    
            # Load PUDAdminCenter Module Functions Within ScriptBlock
            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
            # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
            # they actually behave as expected. Not sure why.
            #$RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)
    
            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
            if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
    
            try {
                $ConnectionStatus = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
            }
            catch {
                $ConnectionStatus = "Disconnected"
            }
    
            # If we're not connected to $RemoteHost, don't load anything else
            if ($ConnectionStatus -ne "Connected") {
                #Invoke-Command -ScriptBlock $RecreatedDisconnectedPageContent -ArgumentList $RemoteHost
                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
            }
            else {
                New-UDRow -EndPoint {
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","DateTime") -AutoRefresh -RefreshInterval 2 -Endpoint {
                            $PUDRSSyncHT = $global:PUDRSSyncHT
    
                            # Load PUDAdminCenter Module Functions Within ScriptBlock
                            $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
                            
                            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                            $WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                            $WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $TableData = @{
                                    RemoteHost      = $RemoteHost.ToUpper()
                                    Status          = "Connected"
                                }
                            }
                            else {
                                Invoke-UDRedirect -Url "/Disconnected/$RemoteHost"
                            }
    
                            # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
                            if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.LiveOutput.Count -gt 0) {
                                if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataTracker.Previous -eq $null) {
                                    $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.LiveOutput.Clone()
                                }
                                if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataTracker.Current.Count -gt 0) {
                                    $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataTracker.Current.Clone()
                                }
                                $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.LiveOutput.Clone()
                            }
    
                            $TableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                            [PSCustomObject]$TableData | Out-UDTableData -Property @("RemoteHost","Status","DateTime")
                        }
                    }
                    New-UDColumn -Size 3 -Content {
                        New-UDHeading -Text ""
                    }
                }
            }
    
            #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost
    
            #region >> Gather Some Initial Info From $RemoteHost
    
            $GetLocalUsersFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalUsers" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetLocalGroupsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalGroups" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetLocalGroupUsersFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalGroupUsers" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetLocalUserBelongGroupsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalUserBelongGroups" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $FunctionsToLoad = @($GetLocalUsersFunc,$GetLocalGroupsFunc,$GetLocalGroupUsersFunc,$GetLocalUserBelongGroupsFunc)
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                $using:FunctionsToLoad | foreach {Invoke-Expression $_}
    
                $LocalUsersInfo = Get-LocalUsers | foreach {
                    [pscustomobject]@{
                        AccountExpires          = if ($_.AccountExpires) {$_.AccountExpires.ToString()} else {$null}
                        Description             = $_.Description
                        Enabled                 = $_.Enabled
                        FullName                = $_.FullName
                        LastLogon               = if ($_.LastLogon) {$_.LastLogon.ToString()} else {$null}
                        Name                    = $_.Name
                        GroupMembership         = $_.GroupMembership
                        ObjectClass             = $_.ObjectClass
                        PasswordChangeableDate  = if ($_.PasswordChangeableDate) {$_.PasswordChangeableDate.ToString()} else {$null}
                        PasswordExpires         = if ($_.PasswordExpires) {$_.PasswordExpires.ToString()} else {$null}
                        PasswordLastSet         = if ($_.PasswordLastSet) {$_.PasswordLastSet.ToString()} else {$null}
                        PasswordRequired        = $_.PasswordRequired
                        SID                     = $_.SID.Value
                        UserMayChangePassword   = $_.UserMayChangePassword
                    }
                }
                $LocalGroupsInfo = Get-LocalGroups 
    
                [pscustomobject]@{
                    LocalUsers      = $LocalUsersInfo
                    LocalGroups     = $LocalGroupsInfo
                }
            }
            $Session:LocalUsersStatic = $StaticInfo.LocalUsers
            $Session:LocalGroupsStatic = $StaticInfo.LocalGroups
            if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Keys -notcontains "LocalUsers") {
                $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Add("LocalUsers",$Session:LocalUsersStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LocalUsers = $Session:LocalUsersStatic
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Keys -notcontains "LocalGroups") {
                $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Add("LocalGroups",$Session:LocalGroupsStatic)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LocalGroups = $Session:LocalGroupsStatic
            }
    
            #endregion >> Gather Some Initial Info From $RemoteHost
    
            #region >> Page Name and Horizontal Nav
    
            New-UDRow -Endpoint {
                New-UDColumn -Content {
                    New-UDHeading -Text "UsersAndGroups (In Progress)" -Size 3
                    New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
                }
            }
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Content {
                    New-UDCollapsible -Items {
                        New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Active -Endpoint {
                            New-UDRow -Endpoint {
                                foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                    New-UDColumn -Endpoint {
                                        New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                    }
                                }
                                #New-UDCard -Links $Links
                            }
                        }
                    }
                }
            }
    
            #endregion >> Page Name and Horizontal Nav
    
            #region >> Setup LiveData
    
            <#
            New-UDColumn -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                # Remove Existing Runspace for LiveDataRSInfo if it exists as well as the PSSession Runspace within
                if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo -ne $null) {
                    $PSSessionRunspacePrep = @(
                        Get-Runspace | Where-Object {
                            $_.RunspaceIsRemote -and
                            $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.ThisRunspace.Id -and
                            $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                        }
                    )
                    if ($PSSessionRunspacePrep.Count -gt 0) {
                        $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                    }
                    $PSSessionRunspace.Dispose()
                    $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.ThisRunspace.Dispose()
                }
    
                # Create a Runspace that creates a PSSession to $RemoteHost that is used once every second to re-gather data from $RemoteHost
                $GetUsersAndGroupsificateOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-UsersAndGroupsificateOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetUsersAndGroupsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-UsersAndGroups" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $LiveDataFunctionsToLoad = @($GetUsersAndGroupsificateOverviewFunc,$GetUsersAndGroupsFunc)
                
                # The New-Runspace function handles scope for you behind the scenes, so just pretend that everything within -ScriptBlock {} is in the current scope
                New-Runspace -RunspaceName "UsersAndGroups$RemoteHost`LiveData" -ScriptBlock {
                    $PUDRSSyncHT = $global:PUDRSSyncHT
                
                    $LiveDataPSSession = New-PSSession -Name "UsersAndGroups$RemoteHost`LiveData" -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds
    
                    # Load needed functions in the PSSession
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        $using:LiveDataFunctionsToLoad | foreach {Invoke-Expression $_}
                    }
    
                    $RSLoopCounter = 0
    
                    while ($PUDRSSyncHT) {
                        # $LiveOutput is a special ArrayList created and used by the New-Runspace function that collects output as it occurs
                        # We need to limit the number of elements this ArrayList holds so we don't exhaust memory
                        if ($LiveOutput.Count -gt 1000) {
                            $LiveOutput.RemoveRange(0,800)
                        }
    
                        # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.LiveOutput
                        Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                            # Place most resource intensive operations first
    
                            # Operations that you only want running once every 30 seconds go within this 'if; block
                            # Adjust the timing as needed with deference to $RemoteHost resource efficiency.
                            if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                                #@{AllUsersAndGroupss = Get-UsersAndGroups}
                            }
    
                            # Operations that you want to run once every second go here
                            @{UsersAndGroupsSummary = Get-UsersAndGroupsificateOverview -channel "Microsoft-Windows-UsersAndGroupservicesClient-Lifecycle-System*"}
    
                        } | foreach {$null = $LiveOutput.Add($_)}
    
                        $RSLoopCounter++
    
                        [GC]::Collect()
    
                        Start-Sleep -Seconds 1
                    }
                }
                # The New-Runspace function outputs / continually updates a Global Scope variable called $global:RSSyncHash. The results of
                # the Runspace we just created can be found in $global:RSSyncHash's "UsersAndGroups$RemoteHost`LiveDataResult" Property - which is just
                # the -RunspaceName value plus the word 'Info'. By setting $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo equal to
                # $RSSyncHash."UsersAndGroups$RemoteHost`LiveDataResult", we can now reference $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.LiveOutput
                # to get the latest data from $RemoteHost.
                $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo = $RSSyncHash."UsersAndGroups$RemoteHost`LiveDataResult"
            }
            #>
    
            #endregion >> Setup LiveData
    
            #region >> Controls
    
            # Static Data Element Example
    
            #$LocalUsersProperties = @("Name","FullName","SID","Enabled","GroupMembership","LastLogon","PasswordChangeableDate","PasswordExpires","PasswordLastSet","PasswordRequired","UserMayChangePassword")
            $LocalUsersProperties = @("Name","Enabled","GroupMembership","LastLogon","AccountExpires","PasswordChangeableDate","PasswordExpires","UserMayChangePassword")
            $LocalUsersUDGridSplatParams = @{
                Title           = "Local Users"
                Headers         = $LocalUsersProperties
                Properties      = $LocalUsersProperties
                PageSize        = 10
            }
            New-UDGrid @LocalUsersUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetLocalUsersFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalUsers" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetLocalUserBelongGroupsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalUserBelongGroups" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $FunctionsToLoad = @($GetLocalUsersFunc,$GetLocalUserBelongGroupsFunc)
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    $using:FunctionsToLoad | foreach {Invoke-Expression $_}
    
                    $LocalUsersInfo = Get-LocalUsers | foreach {
                        [pscustomobject]@{
                            AccountExpires          = if ($_.AccountExpires) {$_.AccountExpires.ToString()} else {$null}
                            Description             = $_.Description
                            Enabled                 = $_.Enabled.ToString()
                            FullName                = $_.FullName
                            LastLogon               = if ($_.LastLogon) {$_.LastLogon.ToString()} else {$null}
                            Name                    = $_.Name
                            GroupMembership         = $_.GroupMembership -join ", "
                            PasswordChangeableDate  = if ($_.PasswordChangeableDate) {$_.PasswordChangeableDate.ToString()} else {$null}
                            PasswordExpires         = if ($_.PasswordExpires) {$_.PasswordExpires.ToString()} else {$null}
                            PasswordLastSet         = if ($_.PasswordLastSet) {$_.PasswordLastSet.ToString()} else {$null}
                            PasswordRequired        = $_.PasswordRequired.ToString()
                            SID                     = $_.SID.Value
                            UserMayChangePassword   = $_.UserMayChangePassword.ToString()
                        }
                    }
    
                    [pscustomobject]@{
                        LocalUsers      = $LocalUsersInfo
                    }
                }
                $Session:LocalUsersStatic = $StaticInfo.LocalUsers
                if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Keys -notcontains "LocalUsers") {
                    $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Add("LocalUsers",$Session:LocalUsersStatic)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LocalUsers = $Session:LocalUsersStatic
                }
    
                $Session:LocalUsersStatic | Out-UDGridData
            }
    
            $LocalGroupsProperties = @("Name","Description","SID","Members")
            $LocalGroupsUDGridSplatParams = @{
                Title           = "Local Groups"
                Headers         = $LocalGroupsProperties
                Properties      = $LocalGroupsProperties
                PageSize        = 10
            }
            New-UDGrid @LocalGroupsUDGridSplatParams -Endpoint {
                $PUDRSSyncHT = $global:PUDRSSyncHT
    
                $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]
    
                $GetLocalGroupsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalGroups" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $GetLocalGroupUsersFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-LocalGroupUsers" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $FunctionsToLoad = @($GetLocalGroupsFunc,$GetLocalGroupUsersFunc)
                $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    $using:FunctionsToLoad | foreach {Invoke-Expression $_}
    
                    $LocalGroupsInfo = Get-LocalGroups | foreach {
                        [pscustomobject]@{
                            Description         = $_.Description
                            Name                = $_.Name
                            SID                 = $_.SID
                            Members             = $_.Members -join ", "
                        }
                    }
    
                    [pscustomobject]@{
                        LocalGroups     = $LocalGroupsInfo
                    }
                }
                $Session:LocalGroupsStatic = $StaticInfo.LocalGroups
                if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Keys -notcontains "LocalGroups") {
                    $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Add("LocalGroups",$Session:LocalGroupsStatic)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LocalGroups = $Session:LocalGroupsStatic
                }
    
                $Session:LocalGroupsStatic | Out-UDGridData
            }
    
    
            # Live Data Element Example
    
            # Remove the Loading  Indicator
            $null = $Session:UsersAndGroupsPageLoadingTracker.Add("FinishedLoading")
    
            #endregion >> Controls
        }
    }
    $Page = New-UDPage -Url "/UsersAndGroups/:RemoteHost" -Endpoint $UsersAndGroupsPageContent
    $null = $Pages.Add($Page)
    

    #endregion >> Dynamic Pages


    #region >> Static Pages

    #region >> Create Home Page
    
    $HomePageContent = {
        $PUDRSSyncHT = $global:PUDRSSyncHT
    
        # Define some Cache: variables that we'll be using in a lot of different contexts
        $Cache:ThisModuleFunctionsStringArray = $ThisModuleFunctionsStringArray = $(Get-Module PUDAdminCenterPrototype).Invoke({$FunctionsForSBUse})
    
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
    
        # Load PUDAdminCenter Module Functions Within ScriptBlock
        $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
        #region >> Loading Indicator
    
        New-UDRow -Columns {
            New-UDColumn -Endpoint {
                $Cache:RHostRefreshAlreadyRan = $False
                $Session:HomePageLoadingTracker = $False
                $Session:SearchRemoteHosts = $False
            }
            New-UDHeading -Text "Remote Hosts" -Size 4
        }
    
        New-UDRow -Columns {
            New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
                if (!$Session:HomePageLoadingTracker) {
                    New-UDHeading -Text "Loading...Please wait..." -Size 5
                    New-UDPreloader -Size small
                }
            }
        }
    
        #endregion >> Loading Indicator
    
        #region >> HomePage Main Content
    
        New-UDRow -Endpoint {
            New-UDColumn -Endpoint {
                New-UDHeading -Text "General Network Scan" -Size 5
                New-UDElement -Id "ScanNetwork" -Tag div -EndPoint {
                    if ($Session:ScanNetwork) {
                        New-UDHeading -Text "Scanning Network for RemoteHosts...Please wait..." -Size 6
                        New-UDPreloader -Size small
                    }
                }
            }
        }
        New-UDRow -Endpoint {
            New-UDColumn -Endpoint {
                New-UDButton -Text "Scan Network" -OnClick {
                    $Session:ScanNetwork = $True
                    Sync-UDElement -Id "ScanNetwork"
    
                    [System.Collections.ArrayList]$ScanRemoteHostListPrep = $(GetComputerObjectsInLDAP).Name
                    # Let's just get 20 of them initially. We want *something* on the HomePage but we don't want hundreds/thousands of entries. We want
                    # the user to specify individual/range of hosts/devices that they want to manage.
                    #$ScanRemoteHostListPrep = $ScanRemoteHostListPrep[0..20]
                    if ($PSVersionTable.PSEdition -eq "Core") {
                        [System.Collections.ArrayList]$ScanRemoteHostListPrep = $ScanRemoteHostListPrep | foreach {$_ -replace "CN=",""}
                    }
    
                    # Filter Out the Remote Hosts that we can't resolve
                    [System.Collections.ArrayList]$ScanRemoteHostList = @()
    
                    $null = Clear-DnsClientCache
                    foreach ($HName in $ScanRemoteHostListPrep) {
                        try {
                            $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $HName -ErrorAction Stop
    
                            if ($ScanRemoteHostList.FQDN -notcontains $RemoteHostNetworkInfo.FQDN) {
                                $null = $ScanRemoteHostList.Add($RemoteHostNetworkInfo)
                            }
                        }
                        catch {
                            continue
                        }
                    }
    
                    $PUDRSSyncHT.RemoteHostList = $ScanRemoteHostList
    
                    # Add Keys for each of the Remote Hosts in the $InitialRemoteHostList    
                    foreach ($RHost in $ScanRemoteHostList) {
                        $Key = $RHost.HostName + "Info"
                        if ($PUDRSSyncHT.Keys -notcontains $Key) {
                            $Value = @{
                                NetworkInfo                 = $RHost
                                CredHT                      = $null
                                ServerInventoryStatic       = $null
                                RelevantNetworkInterfaces   = $null
                                LiveDataRSInfo              = $null
                                LiveDataTracker             = @{Current = $null; Previous = $null}
                            }
                            foreach ($DynPage in $($DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                $DynPageHT = @{
                                    LiveDataRSInfo      = $null
                                    LiveDataTracker     = @{Current = $null; Previous = $null}
                                }
                                $Value.Add($($DynPage -replace "[\s]",""),$DynPageHT)
                            }
                            $PUDRSSyncHT.Add($Key,$Value)
                        }
                    }
    
                    $Session:ScanNetwork = $False
                    Sync-UDElement -Id "ScanNetwork"
    
                    # Refresh the Main Content
                    Sync-UDElement -Id "MainContent"
                }
            }
        }
    
        # RemoteHost / Device Search
        New-UDRow -Endpoint {
            New-UDColumn -Endpoint {
                New-UDHeading -Text "Find Specific Remote Hosts" -Size 5
                New-UDElement -Id "SearchRemoteHosts" -Tag div -EndPoint {
                    if ($Session:SearchRemoteHosts) {
                        New-UDHeading -Text "Searching for RemoteHosts...Please wait..." -Size 6
                        New-UDPreloader -Size small
                    }
                }
            }
    
            New-UDColumn -Size 12 -Endpoint {
                New-UDRow -Endpoint {
                    New-UDColumn -Size 5 -Endpoint {
                        New-UDTextbox -Id "HostNameOrFQDN" -Label "HostName_Or_FQDN" -Placeholder "Enter a HostName/FQDN, or comma-separated HostNames/FQDNs"
                    }
                    New-UDColumn -Size 5 -Endpoint {
                        New-UDTextbox -Id "IPAddress" -Label "IPAddress" -Placeholder "Enter an IP, comma-separated IPs, a range of IPs using a '-', or a range of IPs using CIDR"
                    }
                    New-UDColumn -Size 2 -Endpoint {
                        New-UDButton -Text "Search" -OnClick {
                            $Session:SearchRemoteHosts = $True
                            Sync-UDElement -Id "SearchRemoteHosts"
    
                            $HostNameTextBox = Get-UDElement -Id "HostNameOrFQDN"
                            $IPTextBox = Get-UDElement -Id "IPAddress"
    
                            $HostNames = $HostNameTextBox.Attributes['value']
                            $IPAddresses = $IPTextBox.Attributes['value']
    
                            [System.Collections.ArrayList]$RemoteHostListPrep = @()
    
                            if ($HostNames) {
                                if ($HostNames -match [regex]::Escape(',')) {
                                    $HostNames -split [regex]::Escape(',') | foreach {
                                        if (![System.String]::IsNullOrWhiteSpace($_)) {
                                            $null = $RemoteHostListPrep.Add($_.Trim())
                                        }
                                    }
                                }
                                else {
                                    $null = $RemoteHostListPrep.Add($HostNames.Trim())
                                }
                            }
    
                            if ($IPAddresses) {
                                # Do some basic validation. Make sure no unexpected characters are present.
                                $UnexpectedCharsCheck = $([char[]]$IPAddresses -notmatch "[\s]|,|-|\/|[0-9]") | Where-Object {$_ -ne '.'}
                                if ($UnexpectedCharsCheck.Count -gt 0) {
                                    $Session:SearchRemoteHosts = $False
                                    Sync-UDElement -Id "SearchRemoteHosts"
                                    $Msg = "The following invalid characters were found in the 'IPAddress' field:`n$($UnexpectedCharsCheck -join ', ')"
                                    Show-UDToast -Message $Msg -Position 'topRight' -Title "BadChars" -Duration 10000
                                    Write-Error $Msg
                                    return
                                }
    
                                if (!$($IPAddresses -match [regex]::Escape(',')) -and !$($IPAddresses -match [regex]::Escape('-')) -and !$($IPAddresses -match [regex]::Escape('/'))) {
                                    $null = $RemoteHostListPrep.Add($IPAddresses.Trim())
                                }
                                if ($IPAddresses -match [regex]::Escape(',')) {
                                    $ArrayOfRanges = $IPAddresses -split [regex]::Escape(',') | foreach {
                                        if (![System.String]::IsNullOrWhiteSpace($_)) {
                                            $_.Trim()
                                        }
                                    }
    
                                    if ($IPAddresses -match [regex]::Escape('-') -and $IPAddresses -match [regex]::Escape('/')) {
                                        foreach ($IPRange in $ArrayOfRanges) {
                                            if ($IPRange -match [regex]::Escape('-')) {
                                                $StartIP = $($IPRange -split [regex]::Escape('-'))[0]
                                                $EndIP = $($IPRange -split [regex]::Escape('-'))[-1]
    
                                                if (!$(TestIsValidIPAddress -IPAddress $StartIP)) {
                                                    Show-UDToast -Message "$StartIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadStartIP" -Duration 5000
                                                }
                                                if (!$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                                    Show-UDToast -Message "$EndIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadEndIP" -Duration 5000
                                                }
                                                if (!$(TestIsValidIPAddress -IPAddress $StartIP) -or !$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                                    continue
                                                }
    
                                                Get-IPRange -start $StartIP -end $EndIP | foreach {
                                                    $null = $RemoteHostListPrep.Add($_)
                                                }
                                            }
                                            if ($IPRange -match [regex]::Escape('/')) {
                                                $IPAddr = $($IPRange -split [regex]::Escape('/'))[0]
                                                $CIDRInt = $($IPRange -split [regex]::Escape('/'))[-1]
    
                                                Get-IPRange -ip $IPAddr -cidr $CIDRInt | foreach {
                                                    $null = $RemoteHostListPrep.Add($_)
                                                }
                                            }
                                        }
                                    }
                                    if ($IPAddresses -match [regex]::Escape('-') -and !$($IPAddresses -match [regex]::Escape('/'))) {
                                        foreach ($IPRange in $ArrayOfRanges) {
                                            $StartIP = $($IPRange -split [regex]::Escape('-'))[0]
                                            $EndIP = $($IPRange -split [regex]::Escape('-'))[-1]
    
                                            if (!$(TestIsValidIPAddress -IPAddress $StartIP)) {
                                                Show-UDToast -Message "$StartIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadStartIP" -Duration 5000
                                            }
                                            if (!$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                                Show-UDToast -Message "$EndIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadEndIP" -Duration 5000
                                            }
                                            if (!$(TestIsValidIPAddress -IPAddress $StartIP) -or !$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                                continue
                                            }
    
                                            Get-IPRange -start $StartIP -end $EndIP | foreach {
                                                $null = $RemoteHostListPrep.Add($_)
                                            }
                                        }
                                    }
                                    if ($IPAddresses -match [regex]::Escape('/') -and !$($IPAddresses -match [regex]::Escape('-'))) {
                                        foreach ($IPRange in $ArrayOfRanges) {
                                            $IPAddr = $($IPRange -split [regex]::Escape('/'))[0]
                                            $CIDRInt = $($IPRange -split [regex]::Escape('/'))[-1]
    
                                            Get-IPRange -ip $IPAddr -cidr $CIDRInt | foreach {
                                                $null = $RemoteHostListPrep.Add($_)
                                            }
                                        }
                                    }
                                    if (!$($IPAddresses -match [regex]::Escape('/')) -and !$($IPAddresses -match [regex]::Escape('-'))) {
                                        $IPAddresses -split [regex]::Escape(',') | foreach {
                                            if (!$(TestIsValidIPAddress -IPAddress $_)) {
                                                Show-UDToast -Message "$_ is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadIP" -Duration 5000
                                            }
                                            else {
                                                $null = $RemoteHostListPrep.Add($_.Trim())
                                            }
                                        }
                                    }
                                }
                                if ($IPAddresses -match [regex]::Escape('-') -and $IPAddresses -match [regex]::Escape('/')) { 
                                    Write-Error "You are either missing a comma between two or more separate IP Ranges, or your notation is incorrect. Please try again."
                                    $global:FunctionResult = "1"
                                    return
                                }
                                if ($IPAddresses -match [regex]::Escape('-') -and !$($IPAddresses -match [regex]::Escape('/'))) {
                                    $StartIP = $($IPRange -split [regex]::Escape('-'))[0]
                                    $EndIP = $($IPRange -split [regex]::Escape('-'))[-1]
    
                                    if (!$(TestIsValidIPAddress -IPAddress $StartIP)) {
                                        Show-UDToast -Message "$StartIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadStartIP" -Duration 5000
                                    }
                                    if (!$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                        Show-UDToast -Message "$EndIP is NOT a valid IPv4 Address!" -Position 'topRight' -Title "BadEndIP" -Duration 5000
                                    }
                                    if (!$(TestIsValidIPAddress -IPAddress $StartIP) -or !$(TestIsValidIPAddress -IPAddress $EndIP)) {
                                        continue
                                    }
    
                                    Get-IPRange -start $StartIP -end $EndIP | foreach {
                                        $null = $RemoteHostListPrep.Add($_)
                                    }
                                    
                                }
                                if ($IPAddresses -match [regex]::Escape('/') -and !$($IPAddresses -match [regex]::Escape('-'))) {
                                    $IPAddr = $($IPRange -split [regex]::Escape('/'))[0]
                                    $CIDRInt = $($IPRange -split [regex]::Escape('/'))[-1]
    
                                    Get-IPRange -ip $IPAddr -cidr $CIDRInt | foreach {
                                        $null = $RemoteHostListPrep.Add($_)
                                    }
                                }
                            }
    
                            # Filter Out the Remote Hosts that we can't resolve via DNS
                            [System.Collections.ArrayList]$RemoteHostList = @()
    
                            $null = Clear-DnsClientCache
                            foreach ($HNameOrIP in $RemoteHostListPrep) {
                                try {
                                    $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $HNameOrIP -ErrorAction Stop
    
                                    $null = $RemoteHostList.Add($RemoteHostNetworkInfo)
                                }
                                catch {
                                    Show-UDToast -Message "Unable to resolve $HNameOrIP" -Position 'topRight' -Title "CheckDNS" -Duration 5000
                                    continue
                                }
                            }
                            $PUDRSSyncHT.RemoteHostList = $RemoteHostList
    
                            # Add Keys for each of the Remote Hosts in the $InitialRemoteHostList    
                            foreach ($RHost in $RemoteHostList) {
                                if ($PUDRSSyncHT.Keys -notcontains "$($RHost.HostName)Info") {
                                    $Key = $RHost.HostName + "Info"
                                    $Value = @{
                                        NetworkInfo                 = $RHost
                                        CredHT                      = $null
                                        ServerInventoryStatic       = $null
                                        RelevantNetworkInterfaces   = $null
                                        LiveDataRSInfo              = $null
                                        LiveDataTracker             = @{Current = $null; Previous = $null}
                                    }
                                    foreach ($DynPage in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                        $DynPageHT = @{
                                            LiveDataRSInfo      = $null
                                            LiveDataTracker     = @{Current = $null; Previous = $null}
                                        }
                                        $Value.Add($($DynPage -replace "[\s]",""),$DynPageHT)
                                    }
                                    $PUDRSSyncHT.Add($Key,$Value)
                                }
                            }
    
                            $Session:SearchRemoteHosts = $True
                            Sync-UDElement -Id "SearchRemoteHosts"
    
                            # Refresh the Main Content
                            Sync-UDElement -Id "MainContent"
                        }
                    }
                }
            }
        }
    
        <#
        New-UDRow -Endpoint {
            New-UDColumn -Endpoint {
                New-UDHeading -Text "Sampling of Available Remote Hosts" -Size 5
            }
        }
        #>
    
        New-UDElement -Id "MainContent" -Tag div -EndPoint {
            New-UDRow -Endpoint {
                New-UDColumn -Size 12 -Endpoint {
                    $RHostUDTableEndpoint = {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                        $RHost = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RHostName}
    
                        $RHostTableData = @{}
                        $RHostTableData.Add("HostName",$RHost.HostName.ToUpper())
                        $RHostTableData.Add("FQDN",$RHost.FQDN)
    
                        # Guess Operating System
                        if ($RHost.HostName -eq $env:ComputerName) {
                            $OSGuess = $(Get-CimInstance Win32_OperatingSystem).Caption
                        }
                        else {
                            $NmapOSResult = nmap -O $RHost.IPAddressList[0]
                            if ($NmapOSResult -match "OS details:") {
                                $OSGuessPrep = $($NmapOSResult | Where-Object {$_ -match "OS details:"}) -replace "OS details: ",""
                                $OSGuess = if ($OSGuessPrep -match ',') {$($OSGuessPrep -split ',')[0].Trim()} else {$OSGuessPrep.Trim()}
                            }
                            if ($NmapOSResult -match "Aggressive OS guesses:") {
                                $OSGuessPrep = $($NmapOSResult | Where-Object {$_ -match "Aggressive OS guesses:"}) -replace "Aggressive OS guesses: ",""
                                $OSGuessPrep = if ($OSGuessPrep -match ',') {$($OSGuessPrep -split ',')[0]} else {$OSGuessPrep}
                                $OSGuess = $($OSGuessPrep -replace "[\s]\([0-9]+%\)","").Trim()
                            }
                            if (!$OSGuess) {
                                $OSGuess = $null
                            }
                        }
                        $RHostTableData.Add("OS_Guess",$OSGuess)
    
                        $IPAddressListAsString = @($RHost.IPAddressList) -join ", "
                        $RHostTableData.Add("IPAddress",$IPAddressListAsString)
    
                        # Check Ping
                        try {
                            $PingResult =  [System.Net.NetworkInformation.Ping]::new().Send(
                                $RHost.IPAddressList[0],1000
                            ) | Select-Object -Property Address,Status,RoundtripTime -ExcludeProperty PSComputerName,PSShowComputerName,RunspaceId
    
                            $PingStatus = if ($PingResult.Status.ToString() -eq "Success") {"Available"} else {"Unavailable"}
                            $RHostTableData.Add("PingStatus",$PingStatus)
                        }
                        catch {
                            $RHostTableData.Add("PingStatus","Unavailable")
                        }
    
                        # Check WSMan Ports
                        try {
                            $WSMan5985Url = "http://$($RHost.IPAddressList[0])`:5985/wsman"
                            $WSMan5986Url = "http://$($RHost.IPAddressList[0])`:5986/wsman"
                            $WSManUrls = @($WSMan5985Url,$WSMan5986Url)
                            foreach ($WSManUrl in $WSManUrls) {
                                $Request = [System.Net.WebRequest]::Create($WSManUrl)
                                $Request.Timeout = 1000
                                try {
                                    [System.Net.WebResponse]$Response = $Request.GetResponse()
                                }
                                catch {
                                    if ($_.Exception.Message -match "The remote server returned an error: \(405\) Method Not Allowed") {
                                        if ($WSManUrl -match "5985") {
                                            $WSMan5985Available = $True
                                        }
                                        else {
                                            $WSMan5986Available = $True
                                        }
                                    }
                                    elseif ($_.Exception.Message -match "The operation has timed out") {
                                        if ($WSManUrl -match "5985") {
                                            $WSMan5985Available = $False
                                        }
                                        else {
                                            $WSMan5986Available = $False
                                        }
                                    }
                                    else {
                                        if ($WSManUrl -match "5985") {
                                            $WSMan5985Available = $False
                                        }
                                        else {
                                            $WSMan5986Available = $False
                                        }
                                    }
                                }
                            }
    
                            if ($WSMan5985Available -or $WSMan5986Available) {
                                $RHostTableData.Add("WSMan","Available")
    
                                [System.Collections.ArrayList]$WSManPorts = @()
                                if ($WSMan5985Available) {
                                    $null = $WSManPorts.Add("5985")
                                }
                                if ($WSMan5986Available) {
                                    $null = $WSManPorts.Add("5986")
                                }
    
                                $WSManPortsString = $WSManPorts -join ', '
                                $RHostTableData.Add("WSManPorts",$WSManPortsString)
                            }
                        }
                        catch {
                            $RHostTableData.Add("WSMan","Unavailable")
                        }
    
                        # Check SSH
                        try {
                            $TestSSHResult = TestPort -HostName $RHost.IPAddressList[0] -Port 22
    
                            if ($TestSSHResult.Open) {
                                $RHostTableData.Add("SSH","Available")
                            }
                            else {
                                $RHostTableData.Add("SSH","Unavailable")
                            }
                        }
                        catch {
                            $RHostTableData.Add("SSH","Unavailable")
                        }
    
                        $RHostTableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))
    
                        if ($RHostTableData.WSMan -eq "Available" -or $RHostTableData.SSH -eq "Available") {
                            # We are within an -Endpoint, so $Session: variables should be available
                            #if ($PUDRSSyncHT."$($RHost.HostName)`Info".CredHT.PSRemotingCreds -ne $null) {
                            if ($Session:CredentialHT.$($RHost.HostName).PSRemotingCreds -ne $null) {
                                $RHostTableData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/ToolSelect/$($RHost.HostName)"))
                            }
                            else {
                                $RHostTableData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/PSRemotingCreds/$($RHost.HostName)"))
                            }
                        }
                        else {
                            $RHostTableData.Add("ManageLink","Unavailable")
                        }
    
                        $RHostTableData.Add("NewCreds",$(New-UDLink -Text "NewCreds" -Url "/PSRemotingCreds/$($RHost.HostName)"))
    
                        if ($PUDRSSyncHT."$($RHost.HostName)Info".Keys -contains "RHostTableData") {
                            $PUDRSSyncHT."$($RHost.HostName)Info".RHostTableData = $RHostTableData
                        }
                        else {
                            $PUDRSSyncHT."$($RHost.HostName)Info".Add("RHostTableData",$RHostTableData)
                        }
                        
                        [pscustomobject]$RHostTableData | Out-UDTableData -Property @("HostName","FQDN","OS_Guess","IPAddress","PingStatus","WSMan","WSManPorts","SSH","DateTime","ManageLink","NewCreds")
                    }
                    $RHostUDTableEndpointAsString = $RHostUDTableEndpoint.ToString()
    
                    $RHostCounter = 0
                    #$Session:CredentialHT = @{}
                    foreach ($RHost in $PUDRSSyncHT.RemoteHostList) {
                        $RHostUDTableEndpoint = [scriptblock]::Create(
                            $(
                                "`$RHostName = '$($RHost.HostName)'" + "`n" +
                                $RHostUDTableEndpointAsString
                            )
                        )
    
                        $ResultProperties = @("HostName","FQDN","OS_Guess","IPAddress","PingStatus","WSMan","WSManPorts","SSH","DateTime","ManageLink","NewCreds")
                        $RHostUDTableSplatParams = @{
                            Title           = $RHost.HostName.ToUpper()
                            Headers         = $ResultProperties
                            #AutoRefresh     = $True 
                            #RefreshInterval = 15
                            Endpoint        = $RHostUDTableEndpoint
                        }
                        New-UDTable @RHostUDTableSplatParams
    
                        $RHostCounter++
    
                        if ($RHostCounter -ge $($PUDRSSyncHT.RemoteHostList.Count-1)) {
                            New-UDColumn -Endpoint {
                                $Session:HomePageLoadingTracker = $True
                                $Session:SearchRemoteHosts = $False
                                Sync-UDElement -Id "SearchRemoteHosts"
                            }
                        }
                    }
    
                    # This hidden column refreshes the RemoteHostList so that when the HomePage is reloaded, it only displays
                    # host/devices that can be resolved. This is so that if PUDAdminCenter is used to shutdown/restart a Remote Host,
                    # the list of hosts on the HomePage is accurate 
                    New-UDColumn -AutoRefresh -RefreshInterval 10 -Endpoint {
                        $PUDRSSyncHT = $global:PUDRSSyncHT
    
                        $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}
    
                        if ($Cache:HomeFinishedLoading -and !$Cache:RHostRefreshAlreadyRan) {
                            $null = Clear-DnsClientCache
                            foreach ($IPAddr in $PUDRSSyncHT.RemoteHostList.IPAddressList) {
                                try {
                                    $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $IPAddr -ErrorAction Stop
    
                                    # ResolveHost will NOT throw an error even if it can't figure out HostName, Domain, or FQDN as long as $IPAddr IS pingable
                                    # So, we need to do the below to compensate for code downstream that relies on HostName, Domain, and FQDN
                                    if (!$RemoteHostNetworkInfo.HostName) {
                                        $LastTwoOctets = $($IPAddr -split '\.')[2..3] -join 'Dot'
                                        $UpdatedHostName = NewUniqueString -PossibleNewUniqueString "Unknown$LastTwoOctets" -ArrayOfStrings $PUDRSSyncHT.RemoteHostList.HostName
                                        $RemoteHostNetworkInfo.HostName = $UpdatedHostName
                                        $RemoteHostNetworkInfo.FQDN = $UpdatedHostName + '.Unknown'
                                        $RemoteHostNetworkInfo.Domain = 'Unknown'
                                    }
    
                                    $null = $RemoteHostList.Add($RemoteHostNetworkInfo)
                                }
                                catch {
                                    continue
                                }
                            }
                            $PUDRSSyncHT.RemoteHostList = $RemoteHostList
    
                            $Cache:RHostRefreshAlreadyRan = $True
                        }
                    }
                }
            }
        }
    
        #endregion >> HomePage Main Content
    }
    # IMPORTANT NOTE: Anytime New-UDPage is used with parameter set '-Name -Content', it appears in the hamburger menu
    # This is REQUIRED for the HomePage, otherwise http://localhost won't load (in otherwords, you can't use the
    # parameter set '-Url -Endpoint' for the HomePage).
    # Also, it is important that the HomePage comes first in the $Pages ArrayList
    $HomePage = New-UDPage -Name "Home" -Icon home -Content $HomePageContent
    $null = $Pages.Insert(0,$HomePage)
    

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

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUdOywL6AeLw9JU4ubabUmV6P1
# ZTOgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFBKLd+2sd+5LLiie
# 01uWW86NpwXPMA0GCSqGSIb3DQEBAQUABIIBAC160JcIobRM1ek3pzLftj0gSv1h
# 2YWSfcvnBA8UQyiJIKXrQaYQYn4Fsl0riqHaOdmiRU1b11TdlUz2M7r3w/j2xDXq
# QEiS1PZJfyGzRuA3xG6M2Puj2fDyjqXzTW3pwAOcAiZdHBkU8ERayzlpGSGdfl23
# 6Y4djn+t5mo/knFongucOq7FAxn/pFNTBS9JwRHJwWaksLTfIapcoJMRmaZEY0w3
# /QCPK2/fLH1FooQg7kfRYxfV1IJuIpqyqqb8nXhe548FKFdjm3rfIATeYqwF+ng5
# mYNXGHf039iJC//kU6bnqSlZVhIy/ZTEOIUoS9BSwf+K0QYWXQRAt0Kkzvk=
# SIG # End signature block
