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
