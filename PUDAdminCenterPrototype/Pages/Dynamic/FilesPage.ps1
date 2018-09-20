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