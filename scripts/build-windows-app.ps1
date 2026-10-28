#!/usr/bin/env pwsh
# Builds the native Windows app (windows/src/RhgAuthenticator.App) into one
# self-contained exe with the Go core embedded:
#
#   pwsh scripts/build-windows-app.ps1 [-Version X.Y.Z] [-LibDir <dir>]
#
# LibDir is the RELEASE build of the rhgcore library (rhgcore.dll, from
# scripts/rhgcore-smoke.sh: go/release/rhgcore/release); default
# $env:RHGCORE_LIB_DIR, else that directory. This script never builds Go
# itself. Version is the app's assembly version (X.Y.Z, default 0.0.0). A
# release Version (anything but 0.0.0) requires the library's embedded
# version (RHGCORE_VERSION, printed by --version) to be exactly vVersion. For
# 0.0.0 (non-tag builds) any non-empty version is accepted: CI embeds the
# branch name there, never "v0.0.0", which buildinfo.IsRelease would treat as
# a release.
#
# Output: release/windows-app/rhg-authenticator-windows-amd64.exe. Windows
# only; PowerShell 7.
[CmdletBinding()]
param(
    [string]$Version = '0.0.0',
    [string]$LibDir = $env:RHGCORE_LIB_DIR
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$Project = Join-Path $Root 'windows/src/RhgAuthenticator.App/RhgAuthenticator.App.csproj'
$OutDir = Join-Path $Root 'release/windows-app'
$ExeName = 'rhg-authenticator-windows-amd64.exe'
$DevVersion = '0.0.0' # non-tag builds
$VersionTimeout = [TimeSpan]::FromSeconds(60)
$MaxSizeMB = 100

function Fail([string]$Message) {
    [Console]::Error.WriteLine("FAIL: $Message")
    exit 1
}

if (-not $IsWindows) { Fail 'Windows only' }
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+$') { Fail "Version must be X.Y.Z, got '$Version'" }

if (-not $LibDir) { $LibDir = Join-Path $Root 'go/release/rhgcore/release' }
if (-not (Test-Path -LiteralPath $LibDir -PathType Container)) { Fail "LibDir $LibDir is not a directory" }
# MSBuild resolves a relative path against the project: make it absolute.
$LibDir = (Resolve-Path -LiteralPath $LibDir).Path
if (-not (Test-Path -LiteralPath (Join-Path $LibDir 'rhgcore.dll') -PathType Leaf)) {
    Fail "$LibDir/rhgcore.dll not found (bash scripts/rhgcore-smoke.sh builds go/release/rhgcore/release)"
}

$PublishDir = Join-Path ([IO.Path]::GetTempPath()) "rhg-windows-app-$([guid]::NewGuid().ToString('N'))"
try {
    Write-Host "== dotnet publish (win-x64, library $LibDir)"
    # Native libraries (WPF's among them) go inside the exe too, so the exe is
    # the whole app.
    dotnet publish $Project -c Release -r win-x64 --self-contained `
        -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true `
        -p:IncludeNativeLibrariesForSelfExtract=true `
        "-p:RhgCoreLibDir=$LibDir" "-p:Version=$Version" -o $PublishDir
    if ($LASTEXITCODE -ne 0) { Fail "dotnet publish exited $LASTEXITCODE" }

    $BuiltExe = Join-Path $PublishDir 'rhg-authenticator.exe'
    if (-not (Test-Path -LiteralPath $BuiltExe -PathType Leaf)) { Fail "published exe not found in $PublishDir" }
    # A library left beside it would be missing from the shipped exe.
    $extra = @(Get-ChildItem -LiteralPath $PublishDir -File -Filter '*.dll')
    if ($extra.Count -gt 0) { Fail "publish left libraries beside the exe: $($extra.Name -join ', ')" }

    Write-Host "== assemble $OutDir"
    if (Test-Path -LiteralPath $OutDir) { Remove-Item -LiteralPath $OutDir -Recurse -Force }
    New-Item -ItemType Directory -Path $OutDir | Out-Null
    $Exe = Join-Path $OutDir $ExeName
    Copy-Item -LiteralPath $BuiltExe -Destination $Exe
}
finally {
    if (Test-Path -LiteralPath $PublishDir) { Remove-Item -LiteralPath $PublishDir -Recurse -Force }
}

Write-Host '== check the exe'
# A GUI-subsystem exe gets no console, so its output is read through pipes
# (which the Go runtime inherits as its std handles), with a timeout.
$start = [Diagnostics.ProcessStartInfo]::new($Exe)
$start.ArgumentList.Add('--version')
$start.UseShellExecute = $false
$start.RedirectStandardOutput = $true
$start.RedirectStandardError = $true
$start.CreateNoWindow = $true
$process = [Diagnostics.Process]::Start($start)
try {
    # Both read before waiting, so a full pipe cannot stall the exe.
    $stdout = $process.StandardOutput.ReadToEndAsync()
    $stderr = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit([int]$VersionTimeout.TotalMilliseconds)) {
        $process.Kill($true)
        Fail "--version did not exit within $($VersionTimeout.TotalSeconds)s"
    }
    $process.WaitForExit()
    $exitCode = $process.ExitCode
    $versionOut = $stdout.GetAwaiter().GetResult().Trim()
    $versionErr = $stderr.GetAwaiter().GetResult().Trim()
}
finally {
    $process.Dispose()
}
Write-Host "--version: $versionOut"
if ($versionErr) { Write-Host "--version stderr: $versionErr" }
if ($exitCode -ne 0) { Fail "--version exited $exitCode" }
if (-not $versionOut) { Fail '--version printed nothing' }
if ($versionOut -like '*rhgfake*') {
    Fail 'the app embeds the rhgfake library: point RHGCORE_LIB_DIR (or -LibDir) at the release build'
}
if ($Version -ne $DevVersion -and $versionOut -cne "v$Version") {
    Fail "--version is '$versionOut', want 'v$Version': build the library with RHGCORE_VERSION=v$Version"
}

$sizeMB = (Get-Item -LiteralPath $Exe).Length / 1MB
Write-Host ('size: {0:N1} MB' -f $sizeMB)
if ($sizeMB -gt $MaxSizeMB) { Fail ("the exe is {0:N1} MB, over the {1} MB limit" -f $sizeMB, $MaxSizeMB) }

Write-Host "built $Exe"
