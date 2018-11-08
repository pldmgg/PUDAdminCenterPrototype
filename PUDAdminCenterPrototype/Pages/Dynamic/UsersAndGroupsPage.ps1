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
        $StaticInfo = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
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
            if ($PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo -ne $null) {
                $PSSessionRunspacePrep = @(
                    Get-Runspace | Where-Object {
                        $_.RunspaceIsRemote -and
                        $_.Id -gt $PUDRSSyncHT."$RemoteHost`Info".UsersAndGroups.LiveDataRSInfo.ThisRunspace.Id -and
                        $_.OriginalConnectionInfo.ComputerName -eq $RemoteHost
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
            
                $LiveDataPSSession = New-PSSession -Name "UsersAndGroups$RemoteHost`LiveData" -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds

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
            $StaticInfo = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
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
            $StaticInfo = Invoke-Command -ComputerName $RemoteHost -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
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