function Test-Engine {
    param (
        [string]$Case
    )

    $CaseDirectory = Get-ForensicCaseInfo -Case $Case
    Write-Host "Case Directory: $($CaseDirectory.CaseRoot)"

    Invoke-SqliteQuery -Database $CaseDirectory.Database -Query "SELECT * FROM forensic_case"
}