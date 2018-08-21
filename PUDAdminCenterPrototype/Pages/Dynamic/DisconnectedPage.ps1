#region >> Disconnected Page

$DisconnectedPageContent = {
    param($RemoteHost)

    # Add the SyncHash to the Page so that we can pass output to other pages
    $PUDRSSyncHT = $global:PUDRSSyncHT

    # Load PUDAdminCenter Module Functions Within ScriptBlock
    $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}

    $ConnectionStatusTableProperties = @("RemoteHost", "Status")

    New-UDRow -Columns {
        New-UDColumn -Size 4 -Content {
            New-UDHeading -Text ""
        }
        New-UDColumn -Size 4 -Content {
            New-UDTable -Headers $ConnectionStatusTableProperties -AutoRefresh -Endpoint {
                [PSCustomObject]@{
                    RemoteHost      = $RemoteHost.ToUpper()
                    Status          = "Disconnected"
                } | Out-UDTableData -Property @("RemoteHost", "Status")
            }
        }
        New-UDColumn -Size 4 -Content {
            New-UDHeading -Text ""
        }
    }

    New-UDRow -Columns {
        New-UDColumn -Size 5 -Content {
            New-UDHeading -Text ""
        }
        New-UDColumn -Size 2 -Content {
            New-UDLink -Text "|| Return Home ||" -Url "/Home"
        }
        New-UDColumn -Size 5 -Content {
            New-UDHeading -Text ""
        }
    }

    New-UDRow -Columns {
        New-UDColumn -Size 12 -Content {
            # Grid below UDTable
            $ResultProperties = @("HostName","FQDN","IPAddress","PingStatus","WSMan","WSManPorts","SSH","DateTime","ManageLink")

            $RHost = $PUDRSSyncHT."$RemoteHost`Info".NetworkInfo

            $GridEndpoint = {
                $GridData = @{}
                $GridData.Add("HostName",$RHost.HostName.ToUpper())
                $GridData.Add("FQDN",$RHost.FQDN)
                $GridData.Add("IPAddress",$RHost.IPAddressList[0])

                # Check Ping
                try {
                    $PingResult =  [System.Net.NetworkInformation.Ping]::new().Send(
                        $RHost.IPAddressList[0],1000
                    ) | Select-Object -Property Address,Status,RoundtripTime -ExcludeProperty PSComputerName,PSShowComputerName,RunspaceId

                    $PingStatus = if ($PingResult.Status.ToString() -eq "Success") {"Available"} else {"Unavailable"}
                    $GridData.Add("PingStatus",$PingStatus)
                }
                catch {
                    $GridData.Add("PingStatus","Unavailable")
                }

                # Check WSMan Ports
                try {
                    $WSMan5985Url = "http://$($RHost.IPAddressList[0])`:5985/wsman"
                    $WSMan5986Url = "http://$($RHost.IPAddressList[0])`:5986/wsman"
                    $WSManUrls = @($WSMan5985Url,$WSMan5986Url)
                    foreach ($WSManUrl in $WSManUrls) {
                        $Request = [System.Net.WebRequest]::Create($WSManUrl)
                        $Request.Timeout = 1000
                        try {
                            [System.Net.WebResponse]$Response = $Request.GetResponse()
                        }
                        catch {
                            if ($_.Exception.Message -match "The remote server returned an error: \(405\) Method Not Allowed") {
                                if ($WSManUrl -match "5985") {
                                    $WSMan5985Available = $True
                                }
                                else {
                                    $WSMan5986Available = $True
                                }
                            }
                            elseif ($_.Exception.Message -match "The operation has timed out") {
                                if ($WSManUrl -match "5985") {
                                    $WSMan5985Available = $False
                                }
                                else {
                                    $WSMan5986Available = $False
                                }
                            }
                            else {
                                if ($WSManUrl -match "5985") {
                                    $WSMan5985Available = $False
                                }
                                else {
                                    $WSMan5986Available = $False
                                }
                            }
                        }
                    }

                    if ($WSMan5985Available -or $WSMan5986Available) {
                        $GridData.Add("WSMan","Available")

                        [System.Collections.ArrayList]$WSManPorts = @()
                        if ($WSMan5985Available) {
                            $null = $WSManPorts.Add("5985")
                        }
                        if ($WSMan5986Available) {
                            $null = $WSManPorts.Add("5986")
                        }

                        $WSManPortsString = $WSManPorts -join ', '
                        $GridData.Add("WSManPorts",$WSManPortsString)
                    }
                }
                catch {
                    $GridData.Add("WSMan","Unavailable")
                }

                # Check SSH
                try {
                    $TestSSHResult = TestPort -HostName $RHost.IPAddressList[0] -Port 22

                    if ($TestSSHResult.Open) {
                        $GridData.Add("SSH","Available")
                    }
                    else {
                        $GridData.Add("SSH","Unavailable")
                    }
                }
                catch {
                    $GridData.Add("SSH","Unavailable")
                }

                $GridData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))

                if ($GridData.WSMan -eq "Available" -or $GridData.SSH -eq "Available") {
                    if ($PUDRSSyncHT."$($RHost.HostName)`Info".PSRemotingCreds -ne $null) {
                        $GridData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/ToolSelect/$($RHost.HostName)"))
                    }
                    else {
                        $GridData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/PSRemotingCreds/$($RHost.HostName)"))
                    }
                }
                else {
                    $GridData.Add("ManageLink","Unavailable")
                }
                
                [pscustomobject]$GridData | Out-UDGridData
            }

            $NewUdGridSplatParams = @{
                Headers         = $ResultProperties 
                NoPaging        = $True
                Properties      = $ResultProperties
                AutoRefresh     = $True
                RefreshInterval = 5
                Endpoint        = $GridEndpoint
            }
            New-UdGrid @NewUdGridSplatParams
        }
    }
}
$Page = New-UDPage -Url "/Disconnected/:RemoteHost" -Endpoint $DisconnectedPageContent
$null = $Pages.Add($Page)
# We need this page as a string for later on. For some reason, we can't use this same ScriptBlock directly on other Pages
$DisconnectedPageContentString = $DisconnectedPageContent.ToString()

#endregion >> Disconnected Page