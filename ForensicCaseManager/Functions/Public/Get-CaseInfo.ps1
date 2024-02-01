function Get-ForensicCaseInfo {
    param (
        [string]$Case
    )

    return [PSCustomObject]@{
        "CaseRoot" = $Case
        "Database" = Join-Path -Path $Case -ChildPath "case.db"
        "Logfile" = Join-Path -Path $Case -ChildPath "test.log"
    }
}
