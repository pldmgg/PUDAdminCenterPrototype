#region >> Tool Select Page

$ToolSelectPageContent = {
    param($RemoteHost)

    $PUDRSSyncHT = $global:PUDRSSyncHT

    # Load PUDWinAdminCenter Module Functions Within ScriptBlock
    $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}

    # For some reason, we can't use the $DisconnectedPageContent directly here. It needs to be a different object before it actually outputs
    # UD Elements. Not sure why.
    $RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)

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
            $Session:ToolSelectPageLoadingTracker = [System.Collections.ArrayList]::new()
            #$PUDRSSyncHT.ToolSelectPageLoadingTracker = $Session:ToolSelectPageLoadingTracker
        }
        #New-UDHeading -Text "Select a Tool" -Size 4
    }

    New-UDRow -Columns {
        New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
            if ($Session:ToolSelectPageLoadingTracker -notcontains "FinishedLoading") {
                New-UDHeading -Text "Loading...Please wait..." -Size 5
                New-UDPreloader -Size small
            }
        }
    }

    #endregion >> Loading Indicator

    # Master Endpoint - All content will be within this Endpoint
    New-UDColumn -Size 12 -Endpoint {
        #region >> Ensure We Are Connected to $RemoteHost

        $PUDRSSyncHT = $global:PUDRSSyncHT

        # Load PUDWinAdminCenter Module Functions Within ScriptBlock
        $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}

        # For some reason, scriptblocks defined earlier can't be used directly here. They need to be a different objects before
        # they actually behave as expected. Not sure why.
        $RecreatedDisconnectedPageContent = [scriptblock]::Create($DisconnectedPageContentString)

        $RHostIP = $($PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RemoteHost}).IPAddressList[0]

        if ($Session:CredentialHT.$RemoteHost.PSRemotingCreds -eq $null) {
            Invoke-UDRedirect -Url "/PSRemotingCreds/$RemoteHost"
            #Write-Error "Session:CredentialHT.$RemoteHost.PSRemotingCreds is null"
        }
        else {
            # Check $Session:CredentialHT.$RemoteHost.PSRemotingCreds Credentials. If they don't work, redirect to "/PSRemotingCreds/$RemoteHost"
            try {
                $GetWorkingCredsResult = GetWorkingCredentials -RemoteHostNameOrIP $RHostIP -AltCredentials $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ErrorAction Stop

                if ($GetWorkingCredsResult.DeterminedCredsThatWorkedOnRemoteHost) {
                    if ($GetWorkingCredsResult.WorkingCredentials.GetType().FullName -ne "System.Management.Automation.PSCredential") {
                        Invoke-UDRedirect -Url "/PSRemotingCreds/$RemoteHost"
                        #Write-Error "GetWorkingCredentials A"
                    }
                }
                else {
                    Invoke-UDRedirect -Url "/PSRemotingCreds/$RemoteHost"
                    #Write-Error "GetWorkingCredentials B"
                }
            }
            catch {
                Invoke-UDRedirect -Url "/PSRemotingCreds/$RemoteHost"
                #Write-Error $_
            }
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
                    New-UDTable -Id "TrackingTable" -Headers @("RemoteHost","Status","CredSSP","DateTime") -AutoRefresh -RefreshInterval 5 -Endpoint {
                        $PUDRSSyncHT = $global:PUDRSSyncHT

                        # Load PUDWinAdminCenter Module Functions Within ScriptBlock
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

                        #region >> Gather Some Initial Info From $RemoteHost

                        $GetServerInventoryFunc = $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -match "function Get-ServerInventory" -and $_ -notmatch "function Get-PUDAdminCenter"}
                        $StaticInfo = Invoke-Command -ComputerName $RHostIP -Credential $Session:CredentialHT.$RemoteHost.PSRemotingCreds -ScriptBlock {
                            Invoke-Expression $using:GetServerInventoryFunc

                            [pscustomobject]@{ServerInventoryStatic = Get-ServerInventory}
                        }
                        $Session:ServerInventoryStatic = $StaticInfo.ServerInventoryStatic
                        $PUDRSSyncHT."$RemoteHost`Info".ServerInventoryStatic = $Session:ServerInventoryStatic

                        #endregion >> Gather Some Initial Info From $RemoteHost

                        # SUPER IMPORTANT NOTE: ALL Real-Time Enpoints on the Page reference LiveOutputClone!
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

        #endregion >> Ensure We Are Connected to $RemoteHost

        #region >> Create the Tool Select Content
        
        if ($ConnectionStatus -eq "Connected") {
            [System.Collections.ArrayList]$DynPageRows = @()
            $RelevantDynamicPages = $DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"}
            $ItemsPerRow = 3
            $NumberOfRows = $DynamicPages.Count / $ItemsPerRow
            for ($i=0; $i -lt $NumberOfRows; $i++) {
                New-Variable -Name "Row$i" -Value $(New-Object System.Collections.ArrayList) -Force

                if ($i -eq 0) {$j = 0} else {$j = $i * $ItemsPerRow}
                $jLoopLimit = $j + $($ItemsPerRow - 1)
                while ($j -le $jLoopLimit) {
                    $null = $(Get-Variable -Name "Row$i" -ValueOnly).Add($RelevantDynamicPages[$j])
                    $j++
                }

                $null = $DynPageRows.Add($(Get-Variable -Name "Row$i" -ValueOnly))
            }

            foreach ($DynPageRow in $DynPageRows) {
                New-UDRow -Endpoint {
                    foreach ($DynPage in $DynPageRow) {
                        # Make sure we're connected before loadting the UDCards
                        $DynPageNoSpace = $DynPage -replace "[\s]",""
                        $CardId = $DynPageNoSpace + "Card"
                        New-UDColumn -Size 4 -Endpoint {
                            if ($DynPage -ne $null) {
                                $Links = @(New-UDLink -Text $DynPage -Url "/$DynPageNoSpace/$RemoteHost" -Icon dashboard)
                                New-UDCard -Title $DynPage -Id $CardId -Text "$DynPage Info" -Links $Links
                            }
                        }
                    }
                }
            }

            $null = $Session:ToolSelectPageLoadingTracker.Add("FinishedLoading")
        }

        #endregion >> Create the Tool Select Content
    }
}
$Page = New-UDPage -Url "/ToolSelect/:RemoteHost" -Endpoint $ToolSelectPageContent
$null = $Pages.Add($Page)

#endregion >> Tool Select Page