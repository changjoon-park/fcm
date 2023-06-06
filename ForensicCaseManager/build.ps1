# ForensicCaseManager(FCM)
# Dependencies: dissect 3.5

# Create Virtual Environment
if (-not (Test-Path -Path $PSScriptRoot\.venv -PathType Container)) {
    Write-Host ""
    Write-Host ">>> Creating a Virtual Environment for ForensicCaseManager(FCM)" -ForegroundColor DarkBlue

    try {
        python.exe -m venv $PSScriptRoot\.venv
    }
    catch {
        Write-Warning "Failed to create Python Virtualenv." -ForegroundColor DarkMagenta
        return
    }
}

# Activate Virtual Environment
try {
    & $PSScriptRoot\.venv\Scripts\activate.ps1
}
catch {
    Write-Warning "Failed to enter Python Virtualenv." -ForegroundColor DarkMagenta
    return
}

# Check if Dependencies are installed
$Packages = pip freeze
if (-not $Packages) {
    Write-Host ""
    Write-Warning "Dependencies are required. Installing.."
    Write-Host ""

    & $PSScriptRoot\.venv\Scripts\pip install -r $PSScriptRoot\requirements.txt
}

# Set Virtalenv Information Object
$Packages = pip freeze
$PackageInfo = foreach ($package in $Packages) {
    $obj = [PSCustomObject] @{
        "Name" = $package.split("==")[0]
        "Version" = $package.split("==")[1]
    }
    Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
        return $this.Name
    } -Force

    Write-Output $obj
}

# Out Virtualenv Information Object
$venv = [PSCustomObject] @{
    "Path" = "$PSScriptRoot\.venv"
    "Packages" = $PackageInfo
}

Write-Output $venv
