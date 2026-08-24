#Requires -Version 5.1
<#
.SYNOPSIS
    terms-env installer for Windows.

.DESCRIPTION
    Downloads a terms-env release from GitHub, verifies its SHA-256 checksum,
    and installs tnv.exe into InstallDir (added to your user PATH).

.EXAMPLE
    irm https://raw.githubusercontent.com/Joshua-OA/terms-env/main/install.ps1 | iex
#>
param(
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\terms-env",
    [switch]$NoVerify
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Repo = "Joshua-OA/terms-env"
$Target = "x86_64-pc-windows-msvc"
$ApiHeaders = @{ "User-Agent" = "terms-env-installer" }

function Fail([string]$Message) {
    Write-Host "error: $Message" -ForegroundColor Red
    exit 1
}

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch { }

if ($env:PROCESSOR_ARCHITECTURE -ne "AMD64") {
    Fail "no prebuilt binary for $env:PROCESSOR_ARCHITECTURE.
Build from source instead:
  cargo install --git https://github.com/$Repo tenv-cli"
}

if ($Version -eq "latest") {
    Write-Host "resolving latest release..."
    try {
        $release = Invoke-RestMethod `
            -Uri "https://api.github.com/repos/$Repo/releases/latest" `
            -Headers $ApiHeaders
    } catch {
        Fail "could not resolve the latest release: $($_.Exception.Message)"
    }
    if (-not $release.tag_name) { Fail "could not resolve the latest release tag" }
    $Version = $release.tag_name
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("terms-env-" + [Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmp | Out-Null

try {
    $asset = "terms-env-$Target.zip"
    $base = "https://github.com/$Repo/releases/download/$Version"

    Write-Host "downloading terms-env $Version for $Target..."
    $zipPath = Join-Path $tmp $asset
    Invoke-WebRequest -Uri "$base/$asset" -OutFile $zipPath -Headers $ApiHeaders

    if ($NoVerify) {
        Write-Host "WARNING: skipping checksum verification (-NoVerify)" -ForegroundColor Yellow
    } else {
        Write-Host "verifying SHA-256 checksum..."
        $shaPath = "$zipPath.sha256"
        Invoke-WebRequest -Uri "$base/$asset.sha256" -OutFile $shaPath -Headers $ApiHeaders
        $expected = ((Get-Content $shaPath -Raw).Trim() -split "\s+")[0].ToLower()
        $actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLower()
        if ($expected -ne $actual) {
            Fail "checksum mismatch:
  expected: $expected
  actual:   $actual"
        }
    }

    Expand-Archive -Path $zipPath -DestinationPath $tmp -Force
    $exe = Join-Path $tmp "tnv.exe"
    if (-not (Test-Path $exe)) {
        Fail "archive did not contain the expected tnv.exe binary"
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Copy-Item $exe (Join-Path $InstallDir "tnv.exe") -Force

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $entries = @($userPath -split ";" | Where-Object { $_ -ne "" })
    if ($entries -notcontains $InstallDir) {
        [Environment]::SetEnvironmentVariable(
            "Path",
            (($entries + $InstallDir) -join ";"),
            "User")
        Write-Host ""
        Write-Host "NOTE: added $InstallDir to your user PATH."
        Write-Host "Restart your terminal for it to take effect."
    }

    Write-Host ""
    Write-Host "installed tnv ($Version, $Target) -> $(Join-Path $InstallDir 'tnv.exe')"
    Write-Host "next steps:"
    Write-Host "  tnv init          create your vault"
    Write-Host "  tnv --help        see all commands"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
