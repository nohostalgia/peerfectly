<#
.SYNOPSIS
Builds the Windows installer, target\dist\peerfectly-<version>-windows-x64.msi.

.DESCRIPTION
From the repository root:

    .\deploy\windows\package.ps1
    .\deploy\windows\package.ps1 -Sign <certificate thumbprint>

1. Fetches the WiX toolset and the two extensions peerfectly.wxs uses from NuGet,
   each checked against the SHA-256 written below, and runs them on the .NET
   runtime: no .NET SDK is needed.
2. Builds peerfectlyd.exe, peerfectly.exe and peerfectly-tray.exe.
3. Fetches Wintun, checks the archive and the driver against their SHA-256, and
   then asks the daemon's own driver check - the function the installed daemon
   runs before loading it, with its pins - whether it would load this file. A
   driver the daemon would refuse is never packed.
4. With -Sign, signs the three programs before they are packed and the package
   after, with a timestamp. Without it, says on its last line that nothing is
   signed.
5. Writes the package and its line in target\dist\SHA256SUMS.

.PARAMETER Sign
The thumbprint of a code-signing certificate in the certificate store. A
certificate on a token or in a provider's cloud signing service shows up there
like any other. Needs signtool, from the Windows SDK.

.PARAMETER Timestamp
The timestamp server signtool asks. The certificate provider's own is usually
the one to use.
#>
[CmdletBinding()]
param(
    [string] $Sign,
    [string] $Timestamp = 'http://timestamp.digicert.com'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$Dist = Join-Path $Root 'target\dist'
$Tools = Join-Path $Root 'target\tools'
$Stage = Join-Path $Root 'target\package-windows'
# A target directory of its own: a daemon running from target\release, as one
# does during development, holds its executable open and a build there fails.
$Build = Join-Path $Root 'target\package-build'

# ---- What is fetched, and what it must be ----------------------------------

# The WiX toolset 5, which is MS-RL and asks nothing more of whoever runs it.
$WixVersion = '5.0.2'
$WixPackages = [ordered]@{
    'wix'                    = 'F30EF0C74E2A986126539C5780BE93AC24E8136EAF723B1937B26272703AE173'
    'wixtoolset.ui.wixext'   = '5EF2C707614B9F70B6BBADD2D4ABCB4124EFEE215E9B16BFBC80113079A604C7'
    'wixtoolset.util.wixext' = 'DDA1CC1B4D3B2305B1246F167C6AF6FCDED5000BE84B3BBFF3DDA4F442BF4740'
}

# Wintun 0.14.1, from wintun.net. These two are download integrity only; whether
# the driver may be packed is the daemon's decision, asked below.
$WintunUrl = 'https://www.wintun.net/builds/wintun-0.14.1.zip'
$WintunZipSha256 = '07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51'
$WintunDllSha256 = 'E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE'

# ---- Helpers ----------------------------------------------------------------

function Invoke-Checked {
    param([string] $What, [scriptblock] $Run)
    & $Run
    if ($LASTEXITCODE -ne 0) {
        throw "$What failed (exit code $LASTEXITCODE)."
    }
}

# Fetches a file once, and checks it every time: a file already here that does
# not match is fetched again, and one that still does not match stops the build.
function Get-Pinned {
    param([string] $Url, [string] $File, [string] $Sha256)
    if (-not (Test-Path $File) -or (Get-FileHash -Algorithm SHA256 $File).Hash -ne $Sha256) {
        Write-Host "Fetching $Url"
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $File
    }
    $found = (Get-FileHash -Algorithm SHA256 $File).Hash
    if ($found -ne $Sha256) {
        Remove-Item $File
        throw "$Url is not what this script expects.`n  found    SHA-256 $found`n  expected SHA-256 $Sha256"
    }
}

# Unpacks a fetched archive into a folder of its own, from scratch.
function Expand-Fresh {
    param([string] $Archive, [string] $Into)
    if (Test-Path $Into) { Remove-Item -Recurse -Force $Into }
    Expand-Archive -Path $Archive -DestinationPath $Into
}

# The newest signtool the Windows SDK installed.
function Find-Signtool {
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $found = Get-ChildItem -Path $kits -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Directory.Name -eq 'x64' } |
        Sort-Object { $_.Directory.Parent.Name } -Descending |
        Select-Object -First 1
    if (-not $found) {
        throw "signtool.exe was not found under $kits. It comes with the Windows SDK (the 'Windows SDK Signing Tools for Desktop Apps' feature)."
    }
    $found.FullName
}

function Set-Signature {
    param([string] $Signtool, [string[]] $Files)
    Invoke-Checked 'Signing' {
        & $Signtool sign /sha1 $Sign /fd sha256 /tr $Timestamp /td sha256 $Files
    }
}

# ---- 1. WiX -----------------------------------------------------------------

New-Item -ItemType Directory -Force $Dist, $Tools | Out-Null
$wix = @{}
foreach ($name in $WixPackages.Keys) {
    # Expand-Archive in Windows PowerShell only takes a .zip, which a .nupkg is.
    $archive = Join-Path $Tools "$name.$WixVersion.zip"
    Get-Pinned -Url "https://api.nuget.org/v3-flatcontainer/$name/$WixVersion/$name.$WixVersion.nupkg" `
        -File $archive -Sha256 $WixPackages[$name]
    $wix[$name] = Join-Path $Tools "$name.$WixVersion"
    Expand-Fresh -Archive $archive -Into $wix[$name]
}
$wixDll = Join-Path $wix['wix'] 'tools\net6.0\any\wix.dll'
$uiExtension = Join-Path $wix['wixtoolset.ui.wixext'] 'wixext5\WixToolset.UI.wixext.dll'
$utilExtension = Join-Path $wix['wixtoolset.util.wixext'] 'wixext5\WixToolset.Util.wixext.dll'

# ---- 2. The programs --------------------------------------------------------

Push-Location $Root
try {
    $metadata = cargo metadata --format-version 1 --no-deps | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0) { throw 'cargo metadata failed.' }
    $version = ($metadata.packages | Where-Object { $_.name -eq 'programs' }).version
    Invoke-Checked 'Building the programs' { cargo build --release -p programs --target-dir $Build }
}
finally {
    Pop-Location
}

if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }
New-Item -ItemType Directory -Force $Stage | Out-Null
Copy-Item (Join-Path $Build 'release\peerfectlyd.exe') $Stage
Copy-Item (Join-Path $Build 'release\peerfectly.exe') $Stage
Copy-Item (Join-Path $Build 'release\peerfectly-tray.exe') $Stage

# ---- 3. The driver ----------------------------------------------------------

$wintunZip = Join-Path $Tools 'wintun-0.14.1.zip'
Get-Pinned -Url $WintunUrl -File $wintunZip -Sha256 $WintunZipSha256
$wintun = Join-Path $Tools 'wintun-0.14.1'
Expand-Fresh -Archive $wintunZip -Into $wintun
$driver = Join-Path $wintun 'wintun\bin\amd64\wintun.dll'
$found = (Get-FileHash -Algorithm SHA256 $driver).Hash
if ($found -ne $WintunDllSha256) {
    throw "The driver in $WintunUrl is not what this script expects.`n  found    SHA-256 $found`n  expected SHA-256 $WintunDllSha256"
}

# The daemon decides: the same function, pins and signature check it runs before
# loading the driver. A refusal names the digest it found.
Push-Location $Root
try {
    Invoke-Checked "The daemon's driver check" {
        cargo run --release -q -p windows-daemon --example check_driver --target-dir $Build -- $driver
    }
}
finally {
    Pop-Location
}
Copy-Item $driver $Stage
Copy-Item (Join-Path $wintun 'wintun\LICENSE.txt') (Join-Path $Stage 'wintun-LICENSE.txt')

# ---- 4 and 5. Signing and the package --------------------------------------

$programs = @('peerfectlyd.exe', 'peerfectly.exe', 'peerfectly-tray.exe') | ForEach-Object { Join-Path $Stage $_ }
$signtool = $null
if ($Sign) {
    $signtool = Find-Signtool
    # wintun.dll keeps WireGuard LLC's signature, which the daemon checks.
    Set-Signature -Signtool $signtool -Files $programs
}

$name = "peerfectly-$version-windows-x64.msi"
$msi = Join-Path $Dist $name
Invoke-Checked 'Building the package' {
    dotnet $wixDll build (Join-Path $PSScriptRoot 'peerfectly.wxs') -arch x64 `
        -d "Version=$version" -d "Stage=$Stage" `
        -ext $uiExtension -ext $utilExtension `
        -o $msi
}
# The debugging symbols WiX writes beside the package are not shipped.
Remove-Item -ErrorAction SilentlyContinue ([IO.Path]::ChangeExtension($msi, '.wixpdb'))
# Windows Installer's own consistency checks. ICE61 warns, as it must, that the
# same version replaces itself: that is AllowSameVersionUpgrades, on purpose.
Invoke-Checked 'Validating the package' { dotnet $wixDll msi validate $msi }

if ($Sign) {
    Set-Signature -Signtool $signtool -Files @($msi)
}

# This package's line replaces any earlier Windows package's; the other lines,
# the Linux archive's among them, are left as they were. Written with LF and no
# byte-order mark, as `sha256sum -c` expects.
$sums = Join-Path $Dist 'SHA256SUMS'
$kept = @()
if (Test-Path $sums) {
    $kept = @(Get-Content $sums | Where-Object { $_ -and $_ -notmatch '-windows-x64\.msi$' })
}
$line = '{0}  {1}' -f (Get-FileHash -Algorithm SHA256 $msi).Hash.ToLowerInvariant(), $name
[IO.File]::WriteAllText($sums, ((@($kept) + $line) -join "`n") + "`n", (New-Object Text.UTF8Encoding($false)))

Write-Host ''
Write-Host "Built target\dist\$name"
if ($Sign) {
    Write-Host "SIGNED: $name and the programs in it, with the certificate $Sign"
}
else {
    Write-Host "UNSIGNED: $name and the programs in it carry no signature"
}
