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
            $ConnectionStatus = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}
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

                        #$WSMan5985Available = $(TestPort -HostName $RHostIP -Port 5985).Open
                        #$WSMan5986Available = $(TestPort -HostName $RHostIP -Port 5986).Open

                        $ConnectionStatus = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {"Connected"}

                        if ($ConnectionStatus -eq "Connected") {
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
        $StaticInfo = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
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
                                    $ToolNameNoSpaces = $ToolName -replace "[\s]",""
                                    New-UDLink -Text $ToolName -Url "/$ToolNameNoSpaces/$RemoteHost" -Icon dashboard
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
                        $_.OriginalConnectionInfo.ComputerName -eq $RemoteHost
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
            
                $LiveDataPSSession = New-PSSession -Name "Network$RemoteHost`LiveData" -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds

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
            $StaticInfo = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
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