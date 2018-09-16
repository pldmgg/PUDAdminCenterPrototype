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