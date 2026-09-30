$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$releaseTag = 'installer-v0.1.0'
$releaseRepository = 'Dartsnut/dartsnut-cli'
$releaseRoot = "https://github.com/$releaseRepository/releases/download/$releaseTag"
$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()

switch ($architecture) {
    'X64' {
        $asset = 'dartsnut-rpi-installer-x86_64-pc-windows-msvc.exe'
        # Intentionally unpinned until the release asset can be obtained and hashed.
        $expectedSha256 = ''
    }
    'Arm64' {
        $asset = 'dartsnut-rpi-installer-aarch64-pc-windows-msvc.exe'
        # Intentionally unpinned until the release asset can be obtained and hashed.
        $expectedSha256 = ''
    }
    default {
        throw "dartsnut-rpi-installer: unsupported Windows CPU architecture '$architecture'. See https://github.com/$releaseRepository/releases/tag/$releaseTag for supported assets."
    }
}

if (-not (Get-Command Invoke-WebRequest -ErrorAction SilentlyContinue)) {
    throw 'dartsnut-rpi-installer: Invoke-WebRequest is unavailable; refusing to continue.'
}
if (-not (Get-Command Get-FileHash -ErrorAction SilentlyContinue)) {
    throw 'dartsnut-rpi-installer: Get-FileHash is unavailable; refusing to run an unverified binary.'
}
if ($expectedSha256 -notmatch '\A[0-9a-fA-F]{64}\z') {
    throw "dartsnut-rpi-installer: no verified SHA-256 pin is available for '$asset'; refusing to download or execute an unverified binary. Publish '$releaseTag', then pin the asset's actual SHA-256."
}

$tempDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ("dartsnut-rpi-installer-" + [guid]::NewGuid().ToString('N'))
$binaryPath = Join-Path $tempDirectory $asset
try {
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $directoryAcl = [System.Security.AccessControl.DirectorySecurity]::new()
    $directoryAcl.SetAccessRuleProtection($true, $false)
    $directoryAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
        $currentSid,
        [System.Security.AccessControl.FileSystemRights]::FullControl,
        ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [System.Security.AccessControl.PropagationFlags]::None,
        [System.Security.AccessControl.AccessControlType]::Allow
    ))
    [System.IO.Directory]::CreateDirectory($tempDirectory, $directoryAcl) | Out-Null

    $releaseUrl = "$releaseRoot/$asset"
    Invoke-WebRequest -Uri $releaseUrl -OutFile $binaryPath -UseBasicParsing -ErrorAction Stop
    $actualSha256 = (Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256 -ErrorAction Stop).Hash
    if (-not [string]::Equals($actualSha256, $expectedSha256, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "dartsnut-rpi-installer: SHA-256 mismatch for '$asset'; refusing to execute the downloaded file."
    }

    # Invoke the verified executable directly so it remains attached to this console.
    & $binaryPath @args
    $global:LASTEXITCODE = $LASTEXITCODE
}
finally {
    if (Test-Path -LiteralPath $tempDirectory) {
        Remove-Item -LiteralPath $tempDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
}
