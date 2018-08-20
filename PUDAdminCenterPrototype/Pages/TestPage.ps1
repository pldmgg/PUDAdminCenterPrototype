$TestPageContent = {
    # Add the SyncHash to the Page so that we can pass output to other pages
    $PUDRSSyncHT = $global:PUDRSSyncHT

    # Load PUDWinAdminCenter Module Functions Within ScriptBlock
    $ThisModuleFunctionsStringArray | Where-Object {$_ -ne $null} | foreach {Invoke-Expression $_ -ErrorAction SilentlyContinue}

    [System.Collections.ArrayList]$DynPageRows = @()
    $RelevantDynamicPages = $DynamicPages | Where-Object {$_ -notmatch "PSRemotingCreds|ToolSelect"}
    $ItemsPerRow = 3
    $NumberOfRows = $RelevantDynamicPages.Count / $ItemsPerRow
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
                $DynPageNoSpace = $DynPage -replace "[\s]",""
                $CardId = $DynPageNoSpace + "Card"
                New-UDColumn -Size 4 -Endpoint {
                    if ($DynPage -ne $null) {
                        $Links = @(New-UDLink -Text $DynPage -Url "/$DynPageNoSpace/$RemoteHost" -Icon dashboard)
                        New-UDCard -Title $DynPage -Id $CardId -Text "$DynPage Info" -Links $Links -Size small -TextSize small
                    }
                }
            }
        }
    }
}
$Page = New-UDPage -Url "/Test" -Endpoint $TestPageContent
$null = $Pages.Add($Page)