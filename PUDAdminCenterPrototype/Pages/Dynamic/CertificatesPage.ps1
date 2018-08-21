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
                        if ($PUDRSSyncHT."$RemoteHost`Info".LiveDataRSInfo.LiveOutput.Count -gt 0) {
                            if ($PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Previous -eq $null) {
                                $PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".LiveDataRSInfo.LiveOutput.Clone()
                            }
                            if ($PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Current.Count -gt 0) {
                                $PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Previous = $PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Current.Clone()
                            }
                            $PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Current = $PUDRSSyncHT."$RemoteHost`Info".LiveDataRSInfo.LiveOutput.Clone()
                        }
                        
                        if ($PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Previous.Count -eq 0) {
                            if ($Session:ServerInventoryStatic.IsCredSSPEnabled) {
                                $CredSSPStatus = "Enabled"
                            }
                            else {
                                $CredSSPStatus = "Disabled"
                            }
                        }
                        elseif (@($PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Previous.ServerInventory).Count -gt 0) {
                            if (@($PUDRSSyncHT."$RemoteHost`Info".LiveDataTracker.Previous.ServerInventory)[-1].IsCredSSPEnabled) {
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

        #endregion >> Ensure We Are Connected / Can Connect to $RemoteHost

        #region >> Gather Some Initial Info From $RemoteHost

        $GetCertificateOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-CertificateOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
        $GetCertificatesFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-Certificates" -and $_ -notmatch "function Get-PUDAdminCenter"}
        $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
            Invoke-Expression $using:GetCertificateOverviewFunc
            Invoke-Expression $using:GetCertificatesFunc
            
            $CertificateSummary = Get-CertificateOverview
            $AllCertificates = Get-Certificates

            [pscustomobject]@{
                CertificateSummary          = $CertificateSummary
                AllCertificates             = $AllCertificates
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
        if ($PUDRSSyncHT."$RemoteHost`Info".Certificates.Keys -notcontains "CertSummary") {
            $PUDRSSyncHT."$RemoteHost`Info".Certificates.Add("AllCerts",$Session:AllCertsStatic)
        }
        else {
            $PUDRSSyncHT."$RemoteHost`Info".Certificates.AllCerts = $Session:AllCertsStatic
        }

        #endregion >> Gather Some Initial Info From $RemoteHost

        #region >> Page Name and Horizontal Nav

        New-UDRow -Endpoint {
            New-UDColumn -Content {
                New-UDHeading -Text "Certificates" -Size 3
                New-UDHeading -Text "NOTE: Domain Group Policy trumps controls with an asterisk (*)" -Size 6
            }
        }
        New-UDRow -Endpoint {
            New-UDColumn -Size 12 -Content {
                New-UDCollapsible -Items {
                    New-UDCollapsibleItem -Title "More Tools" -Icon laptop -Endpoint {
                        New-UDRow -Endpoint {
                            New-UDColumn -Size 1 -Endpoint {}
                            foreach ($ToolName in $($Cache:DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"})) {
                                New-UDColumn -Endpoint {
                                    New-UDLink -Text $ToolName -Url "/$ToolName/$RemoteHost" -Icon dashboard
                                }
                            }
                            New-UDColumn -Size 1 -Endpoint {}
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

            if (!$Session:CertSummaryStatic) {
                $GetCertificateOverviewFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-CertificateOverview" -and $_ -notmatch "function Get-PUDAdminCenter"}
                $StaticInfoA = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                    Invoke-Expression $using:GetCertificateOverviewFunc
                    Invoke-Expression $using:GetCertificatesFunc
                    
                    $CertificateSummary = Get-CertificateOverview

                    [pscustomobject]@{
                        CertificateSummary          = $CertificateSummary
                    }
                }
                $Session:CertSummaryStatic = $StaticInfoA.CertificateSummary
                if ($PUDRSSyncHT."$RemoteHost`Info".Certificates.Keys -notcontains "CertSummary") {
                    $PUDRSSyncHT."$RemoteHost`Info".Certificates.Add("CertSummary",$Session:CertSummaryStatic)
                }
                else {
                    $PUDRSSyncHT."$RemoteHost`Info".Certificates.CertSummary = $Session:CertSummaryStatic
                }
            }

            # Remove Existing Runspace for "Overview$RemoteHost`LiveData" if it exists as well as the PSSession Runspace within
            if ($PUDRSSyncHT."$RemoteHost`Info".LiveDataRSInfo -ne $null) {
                $PSSessionRunspacePrep = @(
                    Get-Runspace | Where-Object {
                        $_.RunspaceIsRemote -and
                        $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".LiveDataRSInfo.ThisRunspace.Id -and
                        $_.OriginalConnectionInfo.ComputerName -eq $RHostIP
                    }
                )
                if ($PSSessionRunspacePrep.Count -gt 0) {
                    $PSSessionRunspace = $($PSSessionRunspacePrep | Sort-Object -Property Id)[0]
                }
                $PSSessionRunspace.Dispose()
                $PUDRSSyncHT."$RemoteHost`Info".LiveDataRSInfo.ThisRunspace.Dispose()
            }

            # Create a Scheduled Task that outputs all desired LiveData to a PSCustomObject .xml file every 5 seconds
            $GetEnvVarsFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-EnvironmentVariables" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $GetServerInventoryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ServerInventory" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $NewRunspaceFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function New-Runspace" -and $_ -notmatch "function Get-PUDAdminCenter"}
            $LiveDataFunctionsToLoad = @($GetEnvVarsFunc,$GetServerInventoryFunc,$NewRunspaceFunc)
            
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
                    <#
                    while ($LiveOutput.Count -gt 1000) {
                        $LiveOutput.RemoveAt(0)
                    }
                    #>
                    if ($LiveOutput.Count -gt 1000) {
                        $LiveOutput.RemoveRange(0,800)
                    }

                    # Stream Results to $PUDRSSyncHT."$RemoteHost`Info".LiveDataRSInfo.LiveOutput
                    Invoke-Command -Session $LiveDataPSSession -ScriptBlock {
                        # Place most resource intensive operations first

                        # Only get ServerInventory once every 30 seconds because these spike CPU
                        if ($using:RSLoopCounter -eq 0 -or $($using:RSLoopCounter % 30) -eq 0) {
                            # Server Inventory
                            @{ServerInventory = Get-ServerInventory}
                            #Start-Sleep -Seconds 3
                        
                            # Processes
                            #@{Processes = [System.Diagnostics.Process]::GetProcesses()}
                            #Start-Sleep -Seconds 3
                        }

                        # Processes
                        @{ProcessesCount = $(Get-Counter "\Process(*)\ID Process" -ErrorAction SilentlyContinue).CounterSamples.Count}
                        @{HandlesCount = $(Get-Counter "\Process(_total)\handle count").CounterSamples.CookedValue}
                        @{ThreadsCount = $(Get-Counter "\Process(_total)\thread count").CounterSamples.CookedValue}

                        # Environment Variables
                        @{EnvVars = [pscustomobject]@{EnvVarsCollection = Get-EnvironmentVariables}}

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

                    Start-Sleep -Seconds 1
                }
            }
            $PUDRSSyncHT."$RemoteHost`Info".LiveDataRSInfo = $RSSyncHash."Overview$RemoteHost`LiveDataResult"
        }

        #endregion >> Setup LiveData
    }
}
$Page = New-UDPage -Url "/Certificates/:RemoteHost" -Endpoint $CertificatesPageContent
$null = $Pages.Add($Page)
