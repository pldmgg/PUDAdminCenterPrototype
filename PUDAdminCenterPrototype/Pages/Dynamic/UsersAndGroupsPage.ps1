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
        $using:FunctionsToLoad = @($GetLocalUsersFunc,$GetLocalGroupsFunc,$GetLocalGroupUsersFunc,$GetLocalUserBelongGroupsFunc)
        $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
            $using:FunctionsToLoad | foreach {Invoke-Expression $_}

            $LocalUsersInfo = Get-LocalUsers
            $LocalGroupsInfo = Get-LocalGroups

            AccountExpires         :
            Description            :
            Enabled                : True
            FullName               : pdadmin
            LastLogon              : 1/23/2018 3:18:03 PM
            Name                   : pdadmin
            ObjectClass            : User
            PasswordChangeableDate : 1/23/2018 3:31:28 PM
            PasswordExpires        : 3/24/2018 4:31:28 PM
            PasswordLastSet        : 1/23/2018 3:31:28 PM
            PasswordRequired       : True
            SID                    : S-1-5-21-1449244872-1203980509-2053278225-1000
            UserMayChangePassword  : True
            

            [pscustomobject]@{
                UsersAndGroupsummary          = $UsersAndGroupsummary
                AllUsersAndGroups             = [pscustomobject]$AllUsersAndGroups
            }
        }
        $Session:UsersAndGroupsSummaryStatic = $StaticInfo.UsersAndGroupsummary
        $Session:AllUsersAndGroupssStatic = $StaticInfo.AllUsersAndGroups
        if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Keys -notcontains "UsersAndGroupsSummary") {
            $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Add("UsersAndGroupsSummary",$Session:UsersAndGroupsSummaryStatic)
        }
        else {
            $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.UsersAndGroupsSummary = $Session:UsersAndGroupsSummaryStatic
        }
        if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Keys -notcontains "AllUsersAndGroupss") {
            $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.Add("AllUsersAndGroupss",$Session:AllUsersAndGroupssStatic)
        }
        else {
            $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.AllUsersAndGroupss = $Session:AllUsersAndGroupssStatic
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

        #endregion >> Setup LiveData

        #region >> Controls

        # Static Data Element Example

        $AllUsersAndGroupssProperties = @("UsersAndGroupsificateName","FriendlyName","Subject","Issuer","Path","Status","PrivateKey","PublicKey","NotBefore","NotAfter")
        $AllUsersAndGroupssUDTableSplatParams = @{
            Headers         = $AllUsersAndGroupssProperties
            Properties      = $AllUsersAndGroupssProperties
            PageSize        = 5
        }
        New-UDGrid @AllUsersAndGroupssUDTableSplatParams -Endpoint {
            $PUDRSSyncHT = $global:PUDRSSyncHT

            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]

            $AllUsersAndGroupssGridData = $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.AllUsersAndGroupss | Out-UDGridData

            $AllUsersAndGroupssGridData
        }

        # Live Data Element Example
        $UsersAndGroupsSummaryProperties = @("allCount","expiredCount","nearExpiredCount","eventCount")
        $UsersAndGroupsSummaryUDTableSplatParams = @{
            Headers         = $UsersAndGroupsSummaryProperties
            AutoRefresh     = $True 
            RefreshInterval = 5
        }
        New-UDTable @UsersAndGroupsSummaryUDTableSplatParams -Endpoint {
            $PUDRSSyncHT = $global:PUDRSSyncHT

            $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]

            $UsersAndGroupsSummaryLiveOutputCount = $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.LiveOutput.Count
            if ($UsersAndGroupsSummaryLiveOutputCount -gt 0) {
                $ArrayOfUsersAndGroupsSummaryEntries = @(
                    $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataTracker.Previous.UsersAndGroupsSummary
                ) | Where-Object {$_ -ne $null}
                if ($ArrayOfUsersAndGroupsSummaryEntries.Count -gt 0) {
                    $UsersAndGroupsSummaryTableData = $ArrayOfUsersAndGroupsSummaryEntries[-1] | Out-UDTableData -Property $UsersAndGroupsSummaryProperties
                }
            }
            if (!$UsersAndGroupsSummaryTableData) {
                $UsersAndGroupsSummaryTableData = [pscustomobject]@{
                    allCount            = "Collecting Info"
                    expiredCount        = "Collecting Info"
                    nearExpiredcount    = "Collecting Info"
                    eventCount          = "Collecting Info"
                } | Out-UDTableData -Property $UsersAndGroupsSummaryProperties
            }

            $UsersAndGroupsSummaryTableData
        }

        # Remove the Loading  Indicator
        $null = $Session:UsersAndGroupsPageLoadingTracker.Add("FinishedLoading")

        #endregion >> Controls
    }
}
$Page = New-UDPage -Url "/UsersAndGroups/:RemoteHost" -Endpoint $UsersAndGroupsPageContent
$null = $Pages.Add($Page)
