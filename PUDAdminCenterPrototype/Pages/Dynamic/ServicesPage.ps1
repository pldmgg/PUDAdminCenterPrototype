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
