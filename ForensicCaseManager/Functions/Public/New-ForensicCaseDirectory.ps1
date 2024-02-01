function New-ForensicCaseDirectory {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Case
    )

    $CasePath = Join-Path -Path $Global:CaseDirectory -ChildPath $Case

    if (Test-Path -Path $CasePath) {
        Write-Warning "Case already exists."
        return $false
    }

    try {
        New-Item -Path $CasePath -ItemType Directory -Force
    } catch {
        Write-Warning "Failed to create case directory."
        return $false
    }

    return $true
}