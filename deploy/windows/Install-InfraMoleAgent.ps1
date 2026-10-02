# SPDX-License-Identifier: AGPL-3.0-only
<#
.SYNOPSIS
    Installs and enrols the InfraMole agent on this Windows machine, once.

.DESCRIPTION
    Made for mass deployment: a Group Policy startup script, an Intune
    platform script, an RMM job. Safe to run on every start-up:

      - already installed and enrolled: makes sure the service runs, exits 0;
      - enrolled but the service was removed: reinstalls it with the existing
        credential (no new enrolment);
      - otherwise: downloads the agent, verifies it against SHA256SUMS,
        enrols it with the enrollment token and starts the service.

    Runs as SYSTEM or as an administrator. Writes a short log to
    %ProgramData%\InfraMole\deploy.log (never the token).

    Guide: https://inframole.com/docs/agent/mass-deployment

.PARAMETER Server
    Your InfraMole address, e.g. https://inframole.example.com

.PARAMETER EnrollmentToken
    An enrollment token from Settings > Agents. Use one with an expiry and a
    maximum number of agents, and revoke it when the rollout is done.

.PARAMETER DownloadBaseUrl
    Where the agent binaries and SHA256SUMS are. Default: the latest public
    release. Can be an internal web server or a file share
    (\\fileserver\software\inframole-agent) holding the same files.

.PARAMETER InsecureDev
    Allow an http:// server. Local testing only.

.EXAMPLE
    # Group Policy startup script parameters:
    -Server https://inframole.example.com -EnrollmentToken dmp_enr_...
#>
[CmdletBinding()]
param(
    [string]$Server = "",
    [string]$EnrollmentToken = "",
    [string]$DownloadBaseUrl = "https://github.com/InfraMole/agent/releases/latest/download",
    [switch]$InsecureDev
)

# ─── Intune platform scripts cannot pass parameters: fill these two instead. ───
$IntuneServer = ""          # e.g. "https://inframole.example.com"
$IntuneEnrollmentToken = "" # e.g. "dmp_enr_..."
# ────────────────────────────────────────────────────────────────────────────────
if (-not $Server) { $Server = $IntuneServer }
if (-not $EnrollmentToken) { $EnrollmentToken = $IntuneEnrollmentToken }

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue" # Invoke-WebRequest is far slower with a progress bar

$ServiceName = "inframole-agent"
$InstallDir = Join-Path $env:ProgramFiles "InfraMole"
$Exe = Join-Path $InstallDir "inframole-agent.exe"
$DataDir = Join-Path $env:ProgramData "InfraMole"
$ConfigFile = Join-Path $DataDir "agent.json"
$LogFile = Join-Path $DataDir "deploy.log"

function Write-Log([string]$Message) {
    $line = "{0:u} {1}" -f (Get-Date), $Message
    Write-Output $line
    try {
        New-Item -ItemType Directory -Force $DataDir | Out-Null
        Add-Content -Path $LogFile -Value $line -Encoding UTF8
    } catch { }
}

function Invoke-Agent([string[]]$Arguments) {
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "inframole-agent $($Arguments[0]) failed (exit code $LASTEXITCODE)." }
}

try {
    # 1. Already done: keep the service running and stop here.
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and (Test-Path $ConfigFile) -and (Test-Path $Exe)) {
        if ($service.Status -ne "Running") {
            Start-Service -Name $ServiceName
            Write-Log "Service was $($service.Status); started."
        }
        exit 0
    }

    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run as SYSTEM or as an administrator."
    }
    if (-not $Server) { throw "No server: pass -Server or fill `$IntuneServer at the top of the script." }
    if (-not $InsecureDev -and $Server -notmatch '^https://') {
        throw "The server must use https:// (-InsecureDev is for local tests only)."
    }

    # 2. The binary, verified against SHA256SUMS before it is ever run.
    if (-not (Test-Path $Exe)) {
        # Windows PowerShell 5.1 may still default to TLS 1.0.
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or $env:PROCESSOR_ARCHITEW6432 -eq "ARM64") { "arm64" } else { "amd64" }
        $file = "inframole-agent_windows_$arch.exe"
        $base = $DownloadBaseUrl.TrimEnd("/", "\")
        $temp = Join-Path ([IO.Path]::GetTempPath()) ("inframole-" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Force $temp | Out-Null
        try {
            foreach ($name in @($file, "SHA256SUMS")) {
                $target = Join-Path $temp $name
                if ($base -match '^https?://') {
                    Invoke-WebRequest -Uri "$base/$name" -OutFile $target -UseBasicParsing
                } else {
                    Copy-Item -Path (Join-Path $base $name) -Destination $target
                }
            }
            # Lines are "<sha256>  <file>" (or "<sha256> *<file>").
            $expected = Get-Content (Join-Path $temp "SHA256SUMS") | ForEach-Object {
                $hash, $name = $_ -split '\s+\*?', 2
                if ($name -eq $file) { $hash }
            } | Select-Object -First 1
            $actual = (Get-FileHash (Join-Path $temp $file) -Algorithm SHA256).Hash
            if (-not $expected -or $actual -ne $expected.ToUpperInvariant()) {
                throw "Checksum mismatch for $file - not installing it."
            }
            New-Item -ItemType Directory -Force $InstallDir | Out-Null
            Move-Item -Force (Join-Path $temp $file) $Exe
            Write-Log "Installed $file (sha256 $actual) from $base."
        } finally {
            Remove-Item -Recurse -Force $temp -ErrorAction SilentlyContinue
        }
    }

    $common = @("--server", $Server)
    if ($InsecureDev) { $common += "--insecure-dev" }

    # 3. Enrolled before (the service was removed): reuse the credential.
    if (Test-Path $ConfigFile) {
        Remove-Item Env:\INFRAMOLE_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
        Invoke-Agent (@("install") + $common)
        Write-Log "Service reinstalled with the existing enrolment."
        exit 0
    }

    # 4. First time: enrol and start the service. The token goes through the
    #    environment, never on a command line other processes can read.
    if (-not $EnrollmentToken) { throw "No enrollment token: pass -EnrollmentToken or fill `$IntuneEnrollmentToken at the top of the script." }
    $env:INFRAMOLE_ENROLLMENT_TOKEN = $EnrollmentToken
    try {
        Invoke-Agent (@("install") + $common)
    } finally {
        Remove-Item Env:\INFRAMOLE_ENROLLMENT_TOKEN -ErrorAction SilentlyContinue
    }
    Write-Log "Enrolled $env:COMPUTERNAME with $Server and started the service."
    exit 0
} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    exit 1
}
