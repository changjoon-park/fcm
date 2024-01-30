function Enter-VirtualEnv {
    $FunctionsDir = Split-Path -Path $PSScriptRoot
    $ParentDir = Split-Path -Path $FunctionsDir
    $BuildScript = Get-ChildItem -Path $ParentDir -Filter "build.ps1" -File

    if ($BuildScript) {
        & $BuildScript.FullName
    } else {
        Write-Error -Message "Failed to find build.ps1 in the directory $ParentDir"
    }
}