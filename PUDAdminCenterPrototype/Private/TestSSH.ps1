function TestSSH {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False)]
        [string]$OSGuess = "Windows",

        [Parameter(Mandatory=$True)]
        [pscustomobject]$RemoteHostNetworkInfo, # This must be a pscustomobject with properties HostName, FQDN, Domain, IPAddressList, and PingSuccess

        [Parameter(Mandatory=$False)]
        [ValidatePattern("\\")] # Must be in format <RemoteHostName>\<User>
        [string]$LocalUserName,

        [Parameter(Mandatory=$False)]
        [ValidatePattern("\\")] # Must be in format <DomainShortName>\<User>
        [string]$DomainUserName,

        [Parameter(Mandatory=$False)]
        [string]$LocalPassword,

        [Parameter(Mandatory=$False)]
        [string]$DomainPassword,

        [Parameter(Mandatory=$False)]
        [string]$PublicCertPath,

        [Parameter(Mandatory=$False)]
        $OutputTracker
    )
    

    if ($OSGuess -eq "Windows") {
        if ($LocalUserName) {
            $FullUserName = $LocalUserName
        }
        if ($DomainUserName) {
            $FullUserName = $DomainUserName
        }

        if ($RemoteHostNetworkInfo.FQDN -match "unknown") {
            $HostNameValue = @(
                $RemoteHostNetworkInfo.IPAddressList | Where-Object {$_ -notmatch "^169"}
            )[0]
        }
        else {
            $HostNameValue = $RemoteHostNetworkInfo.FQDN
        }

        # This is basically what we're going for with the below string manipulation:
        #   & pwsh -c {Invoke-Command -HostName zerowin16sshb -KeyFilePath "$HOME\.ssh\zeroadmin_090618-cert.pub" -ScriptBlock {[pscustomobject]@{Output = "ConnectionSuccessful"}} | ConvertTo-Json}
        $PwshRemoteScriptBlockStringArray = @(
            '[pscustomobject]@{'
            '    Output = "ConnectionSuccessful"'
            '}'
        ) | foreach {"    $_"}
        $PwshRemoteScriptBlockString = $PwshRemoteScriptBlockStringArray -join "`n"
        [System.Collections.ArrayList]$PwshInvCmdStringArray = @(
            'Invoke-Command'
            '-HostName'
            $HostNameValue
            '-UserName'
            $FullUserName
        )
        if ($PublicCertPath) {
            $null = $PwshInvCmdStringArray.Add('-KeyFilePath')
            $null = $PwshInvCmdStringArray.Add("'$PublicCertPath'")
        }
        $null = $PwshInvCmdStringArray.Add('-HideComputerName')
        $null = $PwshInvCmdStringArray.Add("-ScriptBlock {`n$PwshRemoteScriptBlockString`n}")
        $null = $PwshInvCmdStringArray.Add('|')
        $null = $PwshInvCmdStringArray.Add('ConvertTo-Json')
        $PwshInvCmdString = $PwshInvCmdStringArray -join " "
        $PwshCmdStringArray = @(
            '&'
            '"' + $(Get-Command pwsh).Source + '"'
            "-c {$PwshInvCmdString}"
        )
        $PwshCmdString = $PwshCmdStringArray -join " "

        if ($OutputTracker) {
            if ($OutputTracker.Keys -contains "PwshCmdString") {
                $OutputTracker.PwshCmdString = $PwshCmdString
            }
            else {
                $OutputTracker.Add("PwshCmdString",$PwshCmdString)
            }
        }

        $null = Start-AwaitSession
        Start-Sleep -Seconds 1
        $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
        $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
        Start-Sleep -Seconds 1
        $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
        Start-Sleep -Seconds 1
        $null = Send-AwaitCommand -Command $([scriptblock]::Create($PwshCmdString))
        Start-Sleep -Seconds 5

        # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

        [System.Collections.ArrayList]$CheckForExpectedResponses = @()
        $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
        $Counter = 0
        while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) -and
        ![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("'s password:")) -and 
        ![bool]$($($CheckForExpectedResponses -split "`n") -match "^}") -and $Counter -le 10
        ) {
            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
            $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
            if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]") {
                break
            }
            Start-Sleep -Seconds 1
            $Counter++
        }
        if ($Counter -eq 11) {
            New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
            Sync-UDElement -Id "CredsForm"
            $CheckResponsesOutput = $CheckForExpectedResponses

            if ($OutputTracker) {
                if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                    $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
                }
                else {
                    $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
                }
            }
            return
        }

        $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
        if ($OutputTracker) {
            if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
            }
            else {
                $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
            }
        }

        # Make sure we didn't already throw an error
        if ($CheckResponsesOutput -match "background process reported an error") {
            $TrySSHExe = $True
        }

        #region >> Make Sure Await Module Is Working
        
        if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]") {
            try {
                $null = Stop-AwaitSession
            }
            catch {
                if ($PSAwaitProcess.Id -eq $PID) {
                    Write-Error "The PSAwaitSession never spawned! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    Stop-Process -Id $PSAwaitProcess.Id
                    while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                        Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                        Start-Sleep -Seconds 1
                    }
                }
            }

            $null = Start-AwaitSession
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
            $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
            Start-Sleep -Seconds 1
            $null = Send-AwaitCommand -Command $([scriptblock]::Create($PwshCmdString))
            Start-Sleep -Seconds 5

            # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

            [System.Collections.ArrayList]$CheckForExpectedResponses = @()
            $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
            $Counter = 0
            while ($SuccessOrAcceptHostKeyOrPwdPrompt -notmatch [regex]::Escape("Are you sure you want to continue connecting (yes/no)?") -and
            $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch [regex]::Escape("'s password:") -and 
            $SuccessOrAcceptHostKeyOrPwdPrompt -notmatch "^}" -and $Counter -le 10
            ) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 11) {
                New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                Sync-UDElement -Id "CredsForm"
                $CheckResponsesOutput = $CheckForExpectedResponses
                if ($OutputTracker) {
                    if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                        $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
                    }
                    else {
                        $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
                    }
                }
                return
            }

            $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
            if ($OutputTracker) {
                if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                    $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
                }
                else {
                    $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
                }
            }
        }
        if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]") {
            New-UDInputAction -Toast "Something went wrong with the PowerShell Await Module! Halting!" -Duration 10000
            Sync-UDElement -Id "CredsForm"

            try {
                $null = Stop-AwaitSession
            }
            catch {
                if ($PSAwaitProcess.Id -eq $PID) {
                    Write-Error "The PSAwaitSession never spawned! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
                else {
                    Stop-Process -Id $PSAwaitProcess.Id
                    while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                        Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                        Start-Sleep -Seconds 1
                    }
                }
            }

            return
        }

        #endregion >> Make Sure Await Module Is Working

        if ($CheckResponsesOutput -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) {
            $null = Send-AwaitCommand "yes"
            Start-Sleep -Seconds 3
            
            # This will either not prompt at all or prompt for a password
            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

            [System.Collections.ArrayList]$CheckExpectedSendYesOutput = @()
            $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
            $Counter = 0
            while (![bool]$($($CheckExpectedSendYesOutput -split "`n") -match [regex]::Escape("'s password:")) -and 
            ![bool]$($($CheckExpectedSendYesOutput -split "`n") -match "^}") -and $Counter -le 10
            ) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 11) {
                New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                Sync-UDElement -Id "CredsForm"
                return
            }

            $CheckSendYesOutput = $CheckExpectedSendYesOutput | foreach {$_ -split "`n"}
            if ($OutputTracker) {
                if ($PUDRSSyncHT.Keys -contains "CheckSendYesOutput") {
                    $PUDRSSyncHT.CheckResponsesOutput = $CheckSendYesOutput
                }
                else {
                    $PUDRSSyncHT.Add("CheckSendYesOutput",$CheckSendYesOutput)
                }
            }
            
            if ($CheckSendYesOutput -match [regex]::Escape("'s password:")) {
                if ($LocalPassword) {
                    $null = Send-AwaitCommand $LocalPassword
                }
                if ($DomainPassword) {
                    $null = Send-AwaitCommand $DomainPassword
                }
                Start-Sleep -Seconds 3

                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$JsonOutputPrep = @()
                $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                while (![bool]$($($JsonOutputPrep -split "`n") -match "^}") -and $Counter -le 10) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 10) {
                    if ($OutputTracker) {
                        if ($PUDRSSyncHT.Keys -contains "JsonOutputPrepA") {
                            $PUDRSSyncHT.JsonOutputPrepA = $JsonOutputPrep
                        }
                        else {
                            $PUDRSSyncHT.Add("JsonOutputPrepA",$JsonOutputPrep)
                        }
                    }

                    New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                    Sync-UDElement -Id "CredsForm"
                    return
                }

                [System.Collections.ArrayList]$JsonOutputPrep = $($JsonOutputPrep | foreach {$_ -split "`n"}) | Where-Object {$_ -notmatch "^PS "}
                if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                    $null = $JsonOutputPrep.Insert(0,'{')
                }
            }
        }
        elseif ($CheckResponsesOutput -match [regex]::Escape("'s password:")) {
            if ($LocalPassword) {
                $null = Send-AwaitCommand $LocalPassword
            }
            if ($DomainPassword) {
                $null = Send-AwaitCommand $DomainPassword
            }
            Start-Sleep -Seconds 3

            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

            [System.Collections.ArrayList]$JsonOutputPrep = @()
            $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
            $Counter = 0
            while (![bool]$($($JsonOutputPrep -split "`n") -match "^}") -and $Counter -le 10) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                    $null = $JsonOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                }
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 10) {
                if ($OutputTracker) {
                    if ($PUDRSSyncHT.Keys -contains "JsonOutputPrepB") {
                        $PUDRSSyncHT.JsonOutputPrepB = $JsonOutputPrep
                    }
                    else {
                        $PUDRSSyncHT.Add("JsonOutputPrepB",$JsonOutputPrep)
                    }
                }

                New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                Sync-UDElement -Id "CredsForm"
                return
            }

            [System.Collections.ArrayList]$JsonOutputPrep = $($JsonOutputPrep | foreach {$_ -split "`n"}) | Where-Object {$_ -notmatch "^PS "}
            if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                $null = $JsonOutputPrep.Insert(0,'{')
            }
        }
        else {
            [System.Collections.ArrayList]$JsonOutputPrep = $($CheckResponsesOutput | foreach {$_ -split "`n"}) | Where-Object {
                $_ -notmatch "^PS " -and ![System.String]::IsNullOrWhiteSpace($_)
            }
            $EndOfInputLineContent = $JsonOutputPrep -match [regex]::Escape("ConvertTo-Json}")
            $JsonOutputIndex = $JsonOutputPrep.IndexOf($EndOfInputLineContent) + 1

            [System.Collections.ArrayList]$JsonOutputPrep = $JsonOutputPrep[$JsonOutputIndex..$($JsonOutputPrep.Count-1)]

            if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                $null = $JsonOutputPrep.Insert(0,'{')
            }
        }

        if (!$TrySSHExe) {
            $IndexesOfOpenBracket = for ($i=0; $i -lt $JsonOutputPrep.Count; $i++) {
                if ($JsonOutputPrep[$i] -match "^{") {
                    $i
                }
            }
            $LastIndexOfOpenBracket = $($IndexesOfOpenBracket | Measure-Object -Maximum).Maximum
            $IndexesOfCloseBracket = for ($i=0; $i -lt $JsonOutputPrep.Count; $i++) {
                if ($JsonOutputPrep[$i] -match "^}") {
                    $i
                }
            }
            $LastIndexOfCloseBracket = $($IndexesOfCloseBracket | Measure-Object -Maximum).Maximum
            [System.Collections.ArrayList]$JsonOutputPrep = $JsonOutputPrep[$LastIndexOfOpenBracket..$LastIndexOfCloseBracket] | foreach {$_ -split "`n"}
            if (![bool]$($JsonOutputPrep[0] -match "^{")) {
                $null = $JsonOutputPrep.Insert(0,'{')
            }

            if ($OutputTracker) {
                if ($PUDRSSyncHT.Keys -contains "JsonOutputPrepC") {
                    $PUDRSSyncHT.JsonOutputPrepC = $JsonOutputPrep
                }
                else {
                    $PUDRSSyncHT.Add("JsonOutputPrepC",$JsonOutputPrep)
                }
            }

            $FinalJson = $JsonOutputPrep | foreach {if (![System.String]::IsNullOrWhiteSpace($_)) {$_.Trim()}}

            if ($OutputTracker) {
                if ($PUDRSSyncHT.Keys -contains "FinalJson") {
                    $PUDRSSyncHT.FinalJson = $FinalJson
                }
                else {
                    $PUDRSSyncHT.Add("FinalJson",$FinalJson)
                }
            }

            try {
                $SSHCheckAsJson = $FinalJson | ConvertFrom-Json
                $script:SSHCheckAsJson = $SSHCheckAsJson
            }
            catch {
                New-UDInputAction -Toast $_.Exception.Message -Duration 10000
                Sync-UDElement -Id "CredsForm"
            }
        }

        try {
            $null = Stop-AwaitSession
        }
        catch {
            if ($PSAwaitProcess.Id -eq $PID) {
                Write-Error "The PSAwaitSession never spawned! Halting!"
                $global:FunctionResult = "1"
                return
            }
            else {
                Stop-Process -Id $PSAwaitProcess.Id
                while ([bool]$(Get-Process -Id $PSAwaitProcess.Id -ErrorAction SilentlyContinue)) {
                    Write-Verbose "Waiting for Await Module Process Id $($PSAwaitProcess.Id) to end..."
                    Start-Sleep -Seconds 1
                }
            }
        }

        if ($SSHCheckAsJson.Output -ne "ConnectionSuccessful") {
            $TrySSHExe = $True
            New-UDInputAction -Toast "SSH via PowerShell Core 'Invoke-Command' failed!" -Duration 10000
            Sync-UDElement -Id "CredsForm"
        }
    }

    if ($OSGuess -eq "Linux" -or $TrySSHExe) {
        if ($LocalUserName) {
            $FullUserName = $($LocalUserName -split "\\")[-1]
        }
        if ($DomainUserName) {
            $DomainNameShort = $($DomainUserName -split "\\")[0]
            $FullUserName = $($DomainUserName -split "\\")[-1]
        }

        $HostNameValue = $RHostIP = @(
            $RemoteHostNetworkInfo.IPAddressList | Where-Object {$_ -notmatch "^169"}
        )[0]

        # This is what we're going for:
        # $test = ssh -t pdadmin@192.168.2.10 "echo 'ConnectionSuccessful'"

        [System.Collections.ArrayList]$SSHCmdStringArray = @(
            'ssh'
        )
        if ($Preferred_PSRemotingCredType -eq "SSHCertificate") {
            $null = $SSHCmdStringArray.Add("-i")
            $null = $SSHCmdStringArray.Add("'" + $PublicCertPath + "'")
        }
        $null = $SSHCmdStringArray.Add("-t")
        if ($LocalUserName -and $LocalPassword) {
            $null = $SSHCmdStringArray.Add("$FullUserName@$RHostIP")
        }
        if ($DomainUserName -and $DomainPassword) {
            $null = $SSHCmdStringArray.Add("$FullUserName@$DomainNameShort@$RHostIP")
        }
        $null = $SSHCmdStringArray.Add("`"echo 'ConnectionSuccessful'`"")
        $SSHCmdString = $SSHCmdStringArray -join " "

        if ($OutputTracker) {
            if ($PUDRSSyncHT.Keys -contains "SSHCmdString") {
                $PUDRSSyncHT.SSHCmdString = $SSHCmdString
            }
            else {
                $PUDRSSyncHT.Add("SSHCmdString",$SSHCmdString)
            }
        }

        $null = Start-AwaitSession
        Start-Sleep -Seconds 1
        $null = Send-AwaitCommand '$host.ui.RawUI.WindowTitle = "PSAwaitSession"'
        $PSAwaitProcess = $($(Get-Process | Where-Object {$_.Name -eq "powershell"}) | Sort-Object -Property StartTime -Descending)[0]
        Start-Sleep -Seconds 1
        $null = Send-AwaitCommand "`$env:Path = '$env:Path'"
        Start-Sleep -Seconds 1
        $null = Send-AwaitCommand -Command $([scriptblock]::Create($SSHCmdString))
        Start-Sleep -Seconds 5

        # This will either not prompt at all, prompt to accept the RemoteHost's RSA Host Key, or prompt for a password
        $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

        [System.Collections.ArrayList]$CheckForExpectedResponses = @()
        $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
        $Counter = 0
        while (![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) -and
        ![bool]$($($CheckForExpectedResponses -split "`n") -match [regex]::Escape("'s password:")) -and 
        ![bool]$($($CheckForExpectedResponses -split "`n") -match "^}") -and $Counter -le 10
        ) {
            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
            $null = $CheckForExpectedResponses.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
            if ($CheckResponsesOutput -match "must be greater than zero" -or $CheckResponsesOutput[-1] -notmatch "[a-zA-Z]") {
                break
            }
            Start-Sleep -Seconds 1
            $Counter++
        }
        if ($Counter -eq 11) {
            New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
            Sync-UDElement -Id "CredsForm"
            $CheckResponsesOutput = $CheckForExpectedResponses
            if ($OutputTracker) {
                if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                    $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
                }
                else {
                    $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
                }
            }
            return
        }

        $CheckResponsesOutput = $CheckForExpectedResponses | foreach {$_ -split "`n"}
        if ($OutputTracker) {
            if ($PUDRSSyncHT.Keys -contains "CheckResponsesOutput") {
                $PUDRSSyncHT.CheckResponsesOutput = $CheckResponsesOutput
            }
            else {
                $PUDRSSyncHT.Add("CheckResponsesOutput",$CheckResponsesOutput)
            }
        }

        if ($CheckResponsesOutput -match [regex]::Escape("Are you sure you want to continue connecting (yes/no)?")) {
            $null = Send-AwaitCommand "yes"
            Start-Sleep -Seconds 3
            
            # This will either not prompt at all or prompt for a password
            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

            [System.Collections.ArrayList]$CheckExpectedSendYesOutput = @()
            $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
            $Counter = 0
            while (![bool]$($($CheckExpectedSendYesOutput -split "`n") -match [regex]::Escape("'s password:")) -and 
            ![bool]$($($CheckExpectedSendYesOutput -split "`n") -match "^}") -and $Counter -le 10
            ) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                $null = $CheckExpectedSendYesOutput.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 11) {
                New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                Sync-UDElement -Id "CredsForm"
                return
            }

            $CheckSendYesOutput = $CheckExpectedSendYesOutput | foreach {$_ -split "`n"}
            if ($OutputTracker) {
                if ($PUDRSSyncHT.Keys -contains "CheckSendYesOutput") {
                    $PUDRSSyncHT.CheckResponsesOutput = $CheckSendYesOutput
                }
                else {
                    $PUDRSSyncHT.Add("CheckSendYesOutput",$CheckSendYesOutput)
                }
            }
            
            if ($CheckSendYesOutput -match [regex]::Escape("'s password:")) {
                if ($LocalPassword) {
                    $null = Send-AwaitCommand $LocalPassword
                }
                if ($Domain_Password) {
                    $null = Send-AwaitCommand $DomainPassword
                }
                Start-Sleep -Seconds 3

                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

                [System.Collections.ArrayList]$SSHOutputPrep = @()
                $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                $Counter = 0
                while (![bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful") -and $Counter -le 10) {
                    $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                    if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                        $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                    }
                    Start-Sleep -Seconds 1
                    $Counter++
                }
                if ($Counter -eq 10) {
                    if ($OutputTracker) {
                        if ($PUDRSSyncHT.Keys -contains "SSHOutputPrepA") {
                            $PUDRSSyncHT.SSHOutputPrepA = $SSHOutputPrep
                        }
                        else {
                            $PUDRSSyncHT.Add("SSHOutputPrepA",$SSHOutputPrep)
                        }
                    }

                    New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                    Sync-UDElement -Id "CredsForm"
                    return
                }
            }
        }
        elseif ($CheckResponsesOutput -match [regex]::Escape("'s password:")) {
            if ($LocalPassword) {
                $null = Send-AwaitCommand $LocalPassword
            }
            if ($DomainPassword) {
                $null = Send-AwaitCommand $DomainPassword
            }
            Start-Sleep -Seconds 3

            $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse

            [System.Collections.ArrayList]$SSHOutputPrep = @()
            $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
            $Counter = 0
            while (![bool]$($($SSHOutputPrep -split "`n") -match "^ConnectionSuccessful") -and $Counter -le 10) {
                $SuccessOrAcceptHostKeyOrPwdPrompt = Receive-AwaitResponse
                if (![System.String]::IsNullOrWhiteSpace($SuccessOrAcceptHostKeyOrPwdPrompt)) {
                    $null = $SSHOutputPrep.Add($SuccessOrAcceptHostKeyOrPwdPrompt)
                }
                Start-Sleep -Seconds 1
                $Counter++
            }
            if ($Counter -eq 10) {
                if ($OutputTracker) {
                    if ($PUDRSSyncHT.Keys -contains "SSHOutputPrepB") {
                        $PUDRSSyncHT.SSHOutputPrepA = $SSHOutputPrep
                    }
                    else {
                        $PUDRSSyncHT.Add("SSHOutputPrepB",$SSHOutputPrep)
                    }
                }

                New-UDInputAction -Toast "SSH failed! Please check your credentials." -Duration 10000
                Sync-UDElement -Id "CredsForm"
                return
            }

            $script:SSHOutputPrep = $SSHOutputPrep
        }
    }
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUDwrH03GEnV3CEm0ArwxUxUeR
# B++gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKu5khejz1ohVgdS
# 2WLFaN6JJ2uoMA0GCSqGSIb3DQEBAQUABIIBAJzd3l0w9iOuCF5XQQV8M7hQJ8p4
# /u9PcAmigi56FYH8DXy9ULkALuC6h9Yq6xH4vuK6qU6uPkIxyng3I5aJ5k7SRPaL
# 0WHA/Mbf0wn8R1VB86bksUagKGIrxPIYTyE8TRCfWj/QUK1uTIXRo7aTCuGGCeMP
# ulrFognACP9KeNtLaxS4PBq+wuFhJItstXgp11+c91av1hGRmSEtmSgPUDSwnpxZ
# GQT0g1KSDQkA5j5XNrBxeJUDKcdZKeimFTs7sgN93qm5HMNWQagGXh+XV67oeDrw
# EY1AnkXnIZar/iwJ9ciQ9VDFqjzz3HrMwomE/GIBtdjAjyB/sSKHzQUVORo=
# SIG # End signature block
