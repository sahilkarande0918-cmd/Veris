<#
.SYNOPSIS
  Fix "Cannot snapshot ... .so: not a regular file" Android build failures.

.DESCRIPTION
  A cloud sync engine (OneDrive Files-On-Demand, and some backup tools) can
  replace a file with a *placeholder*: a reparse point that looks like the file
  but holds no data until something reads it. Gradle refuses to snapshot a
  reparse point, so any native build that touches one dies with:

      java.io.IOException: Cannot snapshot <path>\libc++_shared.so: not a regular file

  The confusing part is where it comes from. The placeholder is usually NOT in
  your project: it is in the Android NDK or the Gradle cache. CMake copies
  those files into every native module's build directory, and each copy
  inherits the placeholder state -- so the error appears to hop from module to
  module, and moving your repo does not help.

  This script rewrites every placeholder it finds as a normal file, in the
  three places that feed an Android build.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts/fix_cloud_placeholders.ps1
#>

param(
    [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot)
)

function Repair-Placeholders {
    param([string]$Root, [string]$Label)

    if (-not (Test-Path $Root)) {
        Write-Host ("  {0,-16} absent, skipped" -f $Label)
        return 0
    }

    $bad = Get-ChildItem $Root -Recurse -File -ErrorAction SilentlyContinue |
           Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }

    $count = ($bad | Measure-Object).Count
    if ($count -eq 0) {
        Write-Host ("  {0,-16} clean" -f $Label)
        return 0
    }

    $fixed = 0
    foreach ($file in $bad) {
        try {
            # Reading forces the sync engine to supply the real bytes; writing
            # them back over the file clears the reparse point for good.
            $bytes = [IO.File]::ReadAllBytes($file.FullName)
            $temp = $file.FullName + ".hydrated"
            [IO.File]::WriteAllBytes($temp, $bytes)
            Remove-Item $file.FullName -Force
            Move-Item $temp $file.FullName
            $fixed++
        } catch {
            Write-Warning ("    could not hydrate {0}: {1}" -f $file.FullName, $_.Exception.Message)
        }
    }
    Write-Host ("  {0,-16} hydrated {1} of {2}" -f $Label, $fixed, $count)
    return $fixed
}

Write-Host "Looking for cloud placeholders that break Android native builds..."

$sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { "$env:LOCALAPPDATA\Android\Sdk" }

$total = 0
$total += Repair-Placeholders "$env:USERPROFILE\.gradle\caches" "gradle cache"
$total += Repair-Placeholders "$sdk\ndk"                        "android ndk"
$total += Repair-Placeholders "$ProjectRoot\apps\mobile\node_modules" "node_modules"

if ($total -gt 0) {
    Write-Host ""
    Write-Host "Hydrated $total file(s). Now clear the copies Gradle already made:"
    Write-Host "  Get-ChildItem apps/mobile/node_modules -Recurse -Directory -Filter cxx | Remove-Item -Recurse -Force"
    Write-Host "then build again."
} else {
    Write-Host ""
    Write-Host "No placeholders found. If the build still fails, the cause is something else --"
    Write-Host "read the actual 'What went wrong' block rather than assuming it is this."
}
