#region >> Create Home Page

$HomePageContent = {
    $PUDRSSyncHT = $global:PUDRSSyncHT

    # Load PUDAdminCenter Module Functions Within ScriptBlock
    $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}

    #region >> Loading Indicator

    New-UDRow -Columns {
        New-UDColumn -Endpoint {
            $Cache:RHostRefreshAlreadyRan = $False
            $Session:HomePageLoadingTracker = [System.Collections.ArrayList]::new()
            #$PUDRSSyncHT.HomePageLoadingTracker = $Session:HomePageLoadingTracker
        }
        New-UDHeading -Text "Remote Hosts" -Size 4
    }

    New-UDRow -Columns {
        New-UDColumn -AutoRefresh -RefreshInterval 1 -Endpoint {
            if ($Session:HomePageLoadingTracker -notcontains "FinishedLoading") {
                New-UDHeading -Text "Loading...Please wait..." -Size 5
                New-UDPreloader -Size small
            }
        }
    }

    #endregion >> Loading Indicator

    #region >> HomePage Main Content

    $RHostUDTableEndpoint = {
        $PUDRSSyncHT = $global:PUDRSSyncHT

        $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}

        $RHost = $PUDRSSyncHT.RemoteHostList | Where-Object {$_.HostName -eq $RHostName}

        $RHostTableData = @{}
        $RHostTableData.Add("HostName",$RHost.HostName.ToUpper())
        $RHostTableData.Add("FQDN",$RHost.FQDN)

        # Guess Operating System
        if ($RHost.HostName -eq $env:ComputerName) {
            $OSGuess = $(Get-CimInstance Win32_OperatingSystem).Caption
        }
        else {
            $NmapOSResult = nmap -O $RHost.IPAddressList[0]
            if ($NmapOSResult -match "OS details:") {
                $OSGuessPrep = $($NmapOSResult | Where-Object {$_ -match "OS details:"}) -replace "OS details: ",""
                $OSGuess = if ($OSGuessPrep -match ',') {$($OSGuessPrep -split ',')[0].Trim()} else {$OSGuessPrep.Trim()}
            }
            if ($NmapOSResult -match "Aggressive OS guesses:") {
                $OSGuessPrep = $($NmapOSResult | Where-Object {$_ -match "Aggressive OS guesses:"}) -replace "Aggressive OS guesses: ",""
                $OSGuessPrep = if ($OSGuessPrep -match ',') {$($OSGuessPrep -split ',')[0]} else {$OSGuessPrep}
                $OSGuess = $($OSGuessPrep -replace "[\s]\([0-9]+%\)","").Trim()
            }
            if (!$OSGuess) {
                $OSGuess = $null
            }
        }
        $RHostTableData.Add("OS_Guess",$OSGuess)

        $IPAddressListAsString = @($RHost.IPAddressList) -join ", "
        $RHostTableData.Add("IPAddress",$IPAddressListAsString)

        # Check Ping
        try {
            $PingResult =  [System.Net.NetworkInformation.Ping]::new().Send(
                $RHost.IPAddressList[0],1000
            ) | Select-Object -Property Address,Status,RoundtripTime -ExcludeProperty PSComputerName,PSShowComputerName,RunspaceId

            $PingStatus = if ($PingResult.Status.ToString() -eq "Success") {"Available"} else {"Unavailable"}
            $RHostTableData.Add("PingStatus",$PingStatus)
        }
        catch {
            $RHostTableData.Add("PingStatus","Unavailable")
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
                $RHostTableData.Add("WSMan","Available")

                [System.Collections.ArrayList]$WSManPorts = @()
                if ($WSMan5985Available) {
                    $null = $WSManPorts.Add("5985")
                }
                if ($WSMan5986Available) {
                    $null = $WSManPorts.Add("5986")
                }

                $WSManPortsString = $WSManPorts -join ', '
                $RHostTableData.Add("WSManPorts",$WSManPortsString)
            }
        }
        catch {
            $RHostTableData.Add("WSMan","Unavailable")
        }

        # Check SSH
        try {
            $TestSSHResult = TestPort -HostName $RHost.IPAddressList[0] -Port 22

            if ($TestSSHResult.Open) {
                $RHostTableData.Add("SSH","Available")
            }
            else {
                $RHostTableData.Add("SSH","Unavailable")
            }
        }
        catch {
            $RHostTableData.Add("SSH","Unavailable")
        }

        $RHostTableData.Add("DateTime",$(Get-Date -Format MM-dd-yy_hh:mm:sstt))

        if ($RHostTableData.WSMan -eq "Available" -or $RHostTableData.SSH -eq "Available") {
            # We are within an -Endpoint, so $Session: variables should be available
            #if ($PUDRSSyncHT."$($RHost.HostName)`Info".CredHT.PSRemotingCreds -ne $null) {
            if ($Session:CredentialHT.$($RHost.HostName).PSRemotingCreds -ne $null) {
                $RHostTableData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/ToolSelect/$($RHost.HostName)"))
            }
            else {
                $RHostTableData.Add("ManageLink",$(New-UDLink -Text "Manage" -Url "/PSRemotingCreds/$($RHost.HostName)"))
            }
        }
        else {
            $RHostTableData.Add("ManageLink","Unavailable")
        }

        $RHostTableData.Add("NewCreds",$(New-UDLink -Text "NewCreds" -Url "/PSRemotingCreds/$($RHost.HostName)"))
        
        [pscustomobject]$RHostTableData | Out-UDTableData -Property @("HostName","FQDN","OS_Guess","IPAddress","PingStatus","WSMan","WSManPorts","SSH","DateTime","ManageLink","NewCreds")
    }
    $RHostUDTableEndpointAsString = $RHostUDTableEndpoint.ToString()

    $RHostCounter = 0
    #$Session:CredentialHT = @{}
    foreach ($RHost in $PUDRSSyncHT.RemoteHostList) {
        $RHostUDTableEndpoint = [scriptblock]::Create(
            $(
                "`$RHostName = '$($RHost.HostName)'" + "`n" +
                $RHostUDTableEndpointAsString
            )
        )

        $ResultProperties = @("HostName","FQDN","OS_Guess","IPAddress","PingStatus","WSMan","WSManPorts","SSH","DateTime","ManageLink","NewCreds")
        $RHostUDTableSplatParams = @{
            Title           = $RHost.HostName.ToUpper()
            Headers         = $ResultProperties
            #AutoRefresh     = $True 
            #RefreshInterval = 15
            Endpoint        = $RHostUDTableEndpoint
        }
        New-UDTable @RHostUDTableSplatParams

        <#
        # We only want to do this once per Session
        if (!$Session:CredHTCreated) {
            $RHostCredHT = @{
                DomainCreds         = $null
                LocalCreds          = $null
                SSHCertPath         = $null
                PSRemotingCredType  = $null
                PSRemotingMethod    = $null
                PSRemotingCreds     = $null
            }
            $Session:CredentialHT.Add($RHost.HostName,$RHostCredHT)
        }
        #>

        # TODO: Comment this out after you're done testing. It's a security vulnerability otherwise...
        #$PUDRSSyncHT."$($RHost.HostName)`Info".CredHT = $Session:CredentialHT

        $RHostCounter++

        if ($RHostCounter -ge $($PUDRSSyncHT.RemoteHostList.Count-1)) {
            #$HomePageTrackingEPSB = [scriptblock]::Create("`$null = `$Session:HomePageLoadingTracker.Add('$($RHost.HostName)')")
            New-UDColumn -Endpoint {
                $null = $Session:HomePageLoadingTracker.Add("FinishedLoading")
                #$Session:CredHTCreated = $True
            }
        }
    }

    New-UDColumn -AutoRefresh -RefreshInterval 5 -Endpoint {
        $PUDRSSyncHT = $global:PUDRSSyncHT

        $Cache:ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}

        if ($Cache:HomeFinishedLoading -and !$Cache:RHostRefreshAlreadyRan) {
            # Get all Computers in Active Directory without the ActiveDirectory Module
            [System.Collections.ArrayList]$RemoteHostListPrep = $(GetComputerObjectsInLDAP).Name
            if ($PSVersionTable.PSEdition -eq "Core") {
                [System.Collections.ArrayList]$RemoteHostListPrep = $RemoteHostListPrep | foreach {$_ -replace "CN=",""}
            }

            # Filter Out the Remote Hosts that we can't resolve
            [System.Collections.ArrayList]$RemoteHostList = @()

            $null = Clear-DnsClientCache
            foreach ($HName in $RemoteHostListPrep) {
                try {
                    $RemoteHostNetworkInfo = ResolveHost -HostNameOrIP $HName -ErrorAction Stop

                    $null = $RemoteHostList.Add($RemoteHostNetworkInfo)
                }
                catch {
                    continue
                }
            }
            $PUDRSSyncHT.RemoteHostList = $RemoteHostList

            $Cache:RHostRefreshAlreadyRan = $True
        }
    }

    #endregion >> HomePage Main Content
}
# IMPORTANT NOTE: Anytime New-UDPage is used with parameter set '-Name -Content', it appears in the hamburger menu
# This is REQUIRED for the HomePage, otherwise http://localhost won't load (in otherwords, you can't use the
# parameter set '-Url -Endpoint' for the HomePage).
# Also, it is important that the HomePage comes first in the $Pages ArrayList
$HomePage = New-UDPage -Name "Home" -Icon home -Content $HomePageContent
$null = $Pages.Insert(0,$HomePage)

#endregion >> Create Home Page