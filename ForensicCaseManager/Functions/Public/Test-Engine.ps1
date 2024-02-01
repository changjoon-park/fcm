function Get-CaseDirectory {
    param (
        [string]$Case
    )

    return [PSCustomObject]@{
        "CaseRoot" = $Case
        "Database" = Join-Path -Path $Case -ChildPath "case.db"
        "Logfile" = Join-Path -Path $Case -ChildPath "test.log"
    }
}

function Test-Engine {
    param (
        [string]$Case
    )

    $CaseDirectory = Get-CaseDirectory -Case $Case
    Write-Host "Case Directory: $($CaseDirectory.CaseRoot)"
}