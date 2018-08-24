#region >> Test Page

$TestPageContent = {
    New-UDTable -Title "Users" -Headers @("Name", "Emails per Day") -Endpoint {
        Import-Module UniversalDashboard.Sparklines
        @(
            [PSCustomObject]@{"Name" = "Adam"; Values = @(12,12,4,2,75,23,54,12); Color = "#234254"}
            [PSCustomObject]@{"Name" = "Jon"; Values = @(2,42,33,21,11,3,32,9); Color = "#453423"}
            [PSCustomObject]@{"Name" = "Bill"; Values = @(1,92,40,21,7,3,2,12); Color = "#923923"}
            [PSCustomObject]@{"Name" = "Ted"; Values = @(112,11,41,2,5,63,74,12); Color = "#A43534"}
            [PSCustomObject]@{"Name" = "Tommy"; Values = @(12,2,42,21,18,26,26,19); Color = "#593493"}
        ) | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Sparkline = New-UDSparkline -Data $_.Values -Color $_.Color
            }
        } | Out-UDTableData -Property @("Name", "Sparkline")
    }
}
$Page = New-UDPage -Url "/Test" -Endpoint $TestPageContent
$null = $Pages.Add($Page)

#endregion >> Test Page