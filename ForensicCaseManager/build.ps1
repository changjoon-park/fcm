# ForensicCaseManager(FCM)
# Dependencies: dissect 3.9

# User Platform Check
$Platform = $PSVersionTable.Platform

if ($Platform -eq "Unix") {
    $Config = Join-Path -Path $env:HOME -ChildPath ".fcm/config.json"
    $Python = "python3"
    $Pip = "pip3"
}
else {
    $Config = Join-Path -Path $env:USERPROFILE -ChildPath ".fcm/config.json"
    $Python = "python.exe"
    $Pip = "pip.exe"
}

$json = @{
    platform = $Platform
} | ConvertTo-Json

if (Test-Path -Path $Config) {
    $json | Set-Content -Path $Config
}
else {
    New-Item -Path $Config -ItemType File -Force
    $json | Set-Content -Path $Config
}

$VirtualEnvDirectory = Join-Path -Path $PSScriptRoot -ChildPath ".venv"

# Create Virtual Environment
if (-not (Test-Path -Path $PSScriptRoot\.venv -PathType Container)) {
    Write-Host ""
    Write-Host ">>> Creating a Virtual Environment for ForensicCaseManager(FCM)" -ForegroundColor DarkBlue

    $VirtualEnvDirectory = Join-Path -Path $PSScriptRoot -ChildPath ".venv"

    try {
        & $Python -m venv $VirtualEnvDirectory
    }
    catch {
        Write-Warning "Failed to create Python Virtualenv."
        return
    }
}

# Activate Virtual Environment
try {
    $VirtualEnvScript = Get-ChildItem -Path $VirtualEnvDirectory -Recurse | Where-Object { $_.Name -eq "activate.ps1" }

    & $VirtualEnvScript.FullName
}
catch {
    Write-Host ""
    Write-Warning "Failed to enter Python Virtualenv."
    return
}

# Check if Dependencies are installed
$RequiredPackages = Join-Path -Path $PSScriptRoot -ChildPath "requirements.txt"
$Packages = & $Pip freeze

if (-not $Packages) {
    Write-Host ""
    Write-Warning "Dependencies are required. Installing.."
    Write-Host ""

    & $Pip install -r $RequiredPackages
}

# Set Virtalenv Information Object
$Packages = & $Pip freeze

$PackageInfo = foreach ($package in $Packages) {
    $obj = [PSCustomObject] @{
        "Name"    = $package.split("==")[0]
        "Version" = $package.split("==")[1]
    }
    Add-Member -InputObject $obj -MemberType ScriptMethod -Name "ToString" -Value {
        return $this.Name
    } -Force

    Write-Output $obj
}

# Out Virtualenv Information Object
$venv = [PSCustomObject] @{
    "Path"     = $VirtualEnvDirectory
    "Packages" = $PackageInfo
}

Write-Output $venv

