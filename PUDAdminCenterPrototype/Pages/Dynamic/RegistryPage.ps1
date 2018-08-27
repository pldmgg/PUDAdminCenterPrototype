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

        if (!$Session:RootDirChildItems) {
            $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                # HKLM and HKCU are already defined by default...
                New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
                New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS
                New-PSDrive -Name HKCC -PSProvider Registry -Root HKEY_CURRENT_CONFIG


                $HKLMChildItems = Get-ChildItem -Path "HKLM:\"
                $HKLMDirItem = Get-Item -Path "HKLM:\"

                $HKCUChildItems = Get-ChildItem -Path "HKCU:\"
                $HKCUDirItem = Get-Item -Path "HKCU:\"

                $HKCRChildItems = Get-ChildItem -Path "HKCR:\"
                $HKCRDirItem = Get-Item -Path "HKCR:\"
                
                $HKUChildItems = Get-ChildItem -Path "HKU:\"
                $HKUDirItem = Get-Item -Path "HKU:\"
                
                $HKCCChildItems = Get-ChildItem -Path "HKCC:\"
                $HKCCDirItem = Get-Item -Path "HKCC:\"

                [pscustomobject]@{
                    HKLMChildItems      = $HKLMChildItems
                    HKLMDirItem         = $HKLMDirItem
                    HKCUChildItems      = $HKCUChildItems
                    HKCUDirItem         = $HKCUDirItem
                    HKCRChildItems      = $HKCRChildItems
                    HKCRDirItem         = $HKCRDirItem
                    HKUChildItems       = $HKUChildItems
                    HKUDirItem          = $HKUDirItem
                    HKCCChildItems      = $HKCCChildItems
                    HKCCDirItem         = $HKCCDirItem
                }
            }
            $Session:HKLMChildItems = $StaticInfo.HKLMChildItems
            $Session:HKLMDirItem = $StaticInfo.HKLMDirItem
            $Session:HKCUChildItems = $StaticInfo.HKCUChildItems
            $Session:HKCUDirItem = $StaticInfo.HKCUDirItem
            $Session:HKCRChildItems = $StaticInfo.HKCRChildItems
            $Session:HKCRDirItem = $StaticInfo.HKCRDirItem
            $Session:HKUChildItems = $StaticInfo.HKUChildItems
            $Session:HKUDirItem = $StaticInfo.HKUDirItem
            $Session:HKCCChildItems  = $StaticInfo.HKCCChildItems
            $Session:HKCCDirItem = $StaticInfo.HKCCDirItem
            if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKLMChildItems") {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKLMChildItems",$StaticInfo.HKLMChildItems)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMChildItems = $StaticInfo.HKLMChildItems
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKLMDirItem") {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKLMDirItem",$StaticInfo.HKLMDirItem)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMDirItem = $StaticInfo.HKLMDirItem
            }

            if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCUChildItems") {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCUChildItems",$StaticInfo.HKCUChildItems)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUChildItems = $StaticInfo.HKCUChildItems
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCUDirItem") {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCUDirItem",$StaticInfo.HKCUDirItem)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCUDirItem = $StaticInfo.HKCUDirItem
            }

            if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCRChildItems") {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCRChildItems",$StaticInfo.HKCRChildItems)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRChildItems = $StaticInfo.HKCRChildItems
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCRDirItem") {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCRDirItem",$StaticInfo.HKCRDirItem)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCRDirItem = $StaticInfo.HKCRDirItem
            }

            if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKUChildItems") {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKUChildItems",$StaticInfo.HKUChildItems)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUChildItems = $StaticInfo.HKUChildItems
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKUDirItem") {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKUDirItem",$StaticInfo.HKUDirItem)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKUDirItem = $StaticInfo.HKUDirItem
            }

            if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCCChildItems") {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCCChildItems",$StaticInfo.HKCCChildItems)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCChildItems = $StaticInfo.HKCCChildItems
            }
            if ($PUDRSSyncHT."$RemoteHost`Info".Registry.Keys -notcontains "HKCCDirItem") {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.Add("HKCCDirItem",$StaticInfo.HKCCDirItem)
            }
            else {
                $PUDRSSyncHT."$RemoteHost`Info".Registry.HKCCDirItem = $StaticInfo.HKCCDirItem
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

        New-UDCollapsible -Id $CollapsibleId -Items {
            New-UDCollapsibleItem -Title "HKEY_LOCAL_MACHINE" -Icon laptop -Active -Endpoint {
                New-UDRow -Endpoint {
                    New-UDColumn -Size 3 -Endpoint {}
                    New-UDColumn -Size 6 -Endpoint {
                        New-UDElement -Id "CurrentHKLMRootDirTB" -Tag div -EndPoint {
                            New-UDHeading -Text "Current Directory: $($Session:HKLMDirItem.FullName)" -Size 5
                        }
                        New-UDElement -Id "NewHKLMRootDirTB" -Tag div -EndPoint {
                            New-UDTextbox -Id "NewHKLMRootDirTBProper" -Label "New Directory"
                        }
                        New-UDButton -Text "Explore" -OnClick {
                            $NewRootDirTextBox = Get-UDElement -Id "NewHKLMRootDirTBProper"
                            $FullPathToExplore = $NewRootDirTextBox.Attributes['value']

                            $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                $HKLMChildItems = Get-ChildItem -Path $args[0]
                                $HKLMDirItem = Get-Item -Path $args[0]

                                [pscustomobject]@{
                                    HKLMChildItems      = $HKLMChildItems
                                    HKLMDirItem         = $HKLMDirItem
                                }
                            } -ArgumentList $FullPathToExplore
                            $Session:HKLMChildItems = $NewPathInfo.HKLMChildItems
                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMChildItems = $NewPathInfo.HKLMChildItems
                            $Session:HKLMDirItem = $NewPathInfo.HKLMDirItem
                            $PUDRSSyncHT."$RemoteHost`Info".Registry.HKLMDirItem = $NewPathInfo.HKLMDirItem

                            Sync-UDElement -Id "HKLMChildItemsUDGrid"
                            Sync-UDElement -Id "NewJKLMRootDirTB"
                            Sync-UDElement -Id "CurrentHKLMRootDirTB"
                        }

                        New-UDButton -Text "Parent Directory" -OnClick {
                            $FullPathToExplore = $Session:RootDirItem.FullName | Split-Path -Parent

                            $NewPathInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                                $RootDirChildItems = Get-ChildItem -Path $args[0]
                                $RootDirItem = Get-Item -Path $args[0]

                                [pscustomobject]@{
                                    RootDirItem            = $RootDirItem
                                    RootDirChildItems      = $RootDirChildItems
                                }
                            } -ArgumentList $FullPathToExplore
                            $Session:RootDirChildItems = $NewPathInfo.RootDirChildItems
                            $PUDRSSyncHT."$RemoteHost`Info".Registry.RootDirChildItems = $NewPathInfo.RootDirChildItems
                            $Session:RootDirItem = $NewPathInfo.RootDirItem
                            $PUDRSSyncHT."$RemoteHost`Info".Registry.RootDirItem = $NewPathInfo.RootDirItem
                            Sync-UDElement -Id "RootDirChildItemsUDGrid"
                            Sync-UDElement -Id "NewRootDirTB"
                            Sync-UDElement -Id "CurrentRootDirTB"
                        }
                    }
                    New-UDColumn -Size 3 -Endpoint {}
                }
                New-UDRow -Endpoint {
                    New-UDColumn -Size 12 -Endpoint {
                        $RootRegistryProperties = @("Name","FullPath","DateModified","Type","Size","Explore")
                        $RootRegistryUDGridSplatParams = @{
                            Id              = "RootDirChildItemsUDGrid"
                            Headers         = $RootRegistryProperties
                            Properties      = $RootRegistryProperties
                            PageSize        = 20
                        }
                        New-UDGrid @RootRegistryUDGridSplatParams -Endpoint {
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
                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.RootDirChildItems = $NewPathInfo.RootDirChildItems
                                            $Session:RootDirItem = $NewPathInfo.RootDirItem
                                            $PUDRSSyncHT."$RemoteHost`Info".Registry.RootDirItem = $NewPathInfo.RootDirItem
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

        # Live Data Element Example

        # Remove the Loading  Indicator
        $null = $Session:RegistryPageLoadingTracker.Add("FinishedLoading")

        #endregion >> Controls
    }
}
$Page = New-UDPage -Url "/Registry/:RemoteHost" -Endpoint $RegistryPageContent
$null = $Pages.Add($Page)