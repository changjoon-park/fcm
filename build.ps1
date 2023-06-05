# ForensicCaseManager(FCM)
# Dependencies: dissect 3.5

param (
    [Parameter()]
    [switch]
    $InstallDependency
)

# Create Virtual Environment
if (-not (Test-Path -Path $PSScriptRoot\venv -PathType Container)) {
    Write-Host ""
    Write-Host ">>> Creating a Virtual Environment for ForensicCaseManager(FCM)" -ForegroundColor DarkBlue

    try {
        python.exe -m .venv $PSScriptRoot\.venv
    }
    catch {
        Write-Warning "Failed to create Python Virtualenv." -ForegroundColor DarkMagenta
        return
    }
}
a
# Activate Virtual Environment
try {
    & $PSScriptRoot\.venv\Scripts\activate.ps1
}
catch {
    Write-Warning "Failed to enter Python Virtualenv." -ForegroundColor DarkMagenta
    return
}

# Dependencies Check and Install
$Packages = pip freeze
if ($Packages) {
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
}

if ($InstallDependency) {
    if (-not ($Packages)) {
        Write-Warning "Dependencies are required. Installing.."
    
        & $PSScriptRoot\.venv\Scripts\pip install -r $PSScriptRoot\requirements.txt
    }
    else {
        Write-Host ""
        Write-Warning "Dependencies are already installed."
        Write-Host ""
    }
}
else {
    if (pip show dissect) {
        Write-Host ""
        Write-Warning "Dependencies are already installed."
        Write-Host ""
    }
}

# Out Virtualenv Information
$venv = [PSCustomObject] @{
    "Path" = "$PSScriptRoot\.venv"
    "Packages" = $PackageInfo
}

Write-Output $venv
