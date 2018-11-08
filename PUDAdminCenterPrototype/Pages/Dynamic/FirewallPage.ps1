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
        $StaticInfo = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
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
            if ($PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo -ne $null) {
                $PSSessionRunspacePrep = @(
                    Get-Runspace | Where-Object {
                        $_.RunspaceIsRemote -and
                        $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".Firewall.LiveDataRSInfo.ThisRunspace.Id -and
                        $_.OriginalConnectionInfo.ComputerName -eq $RemoteHost
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
            
                $LiveDataPSSession = New-PSSession -Name "Firewall$RemoteHost`LiveData" -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds

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
            $StaticInfo = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
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
            $StaticInfo = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
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
