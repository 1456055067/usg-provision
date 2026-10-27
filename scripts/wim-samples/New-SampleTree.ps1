#Requires -Version 7.2
<#
.SYNOPSIS
    Writes a deterministic directory tree of our own generated content, used
    as the capture source for the DISM sample WIMs (plan WU-W, decision 0006).

.DESCRIPTION
    Every file is generated here: ASCII text written by this script, and
    pseudorandom bytes from System.Random seeded with -Seed. No Windows media,
    no third-party or copyrighted content, nothing downloaded.

    Profiles:
      Standard        text files (compressible), pseudorandom files at sizes
                      around the 32768-byte chunk boundary, an empty file, an
                      empty directory, names with spaces and non-ASCII
                      characters (including one outside the Basic
                      Multilingual Plane), a nested directory chain, one file
                      with an alternate data stream, and a shared/ directory
                      whose content does not depend on -Seed (so captures of
                      different seeds share it).
      Incompressible  one 65536-byte pseudorandom file (two 32768-byte
                      chunks), for OPEN-WIM-5.
      Large           one pseudorandom file of -LargeBytes bytes (default
                      4.5 GiB), for OPEN-WIM-10.
      LongRun         long runs for XPRESS long matches (BOOT-004):
                      zeros-32768.bin (32768 zero bytes, one chunk),
                      zeros-98304.bin (98304 zero bytes, three chunks) and
                      pattern300-98304.bin (a 300-byte pseudorandom pattern
                      from -Seed, repeated to 98304 bytes). Expected to use
                      the 16-bit length extension and multi-chunk tables,
                      which R1 never showed (OBS-012).
      Service         the content added to a mounted image before commit
                      (sample S12A, BOOT-012): serviced.txt (text) and
                      serviced-40000.bin (40000 pseudorandom bytes from
                      -Seed, two chunks), so the commit writes new file
                      resources as well as new metadata.

    All file and directory times are set to one fixed UTC instant so that two
    runs with the same seed give the same tree. The script refuses to write
    into an existing non-empty directory.

    The script is ASCII-only; non-ASCII names are built from code points.

.PARAMETER Path
    Directory to create (must not exist, or must be empty).

.PARAMETER Seed
    Seed for System.Random (0 to 2147483647).

.PARAMETER TreeProfile
    Standard, Incompressible, Large, LongRun or Service. Alias: -Profile
    (plan WU-W wording).

.PARAMETER LargeBytes
    Size of the Large profile's file in bytes.

.NOTES
    COMPLIANCE MAPPING:
    - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-7 (test
      inputs for integrity checking of image content)
    - SPEC: specs/standards/wim.md section 13 (OPEN-WIM-5, OPEN-WIM-6
      samples S11 and S12, OPEN-WIM-10);
      specs/standards/wim-compression.md sections 3.4 and 7 (OPEN-WIMC-1)
    - Decision 0006 items 1 and 3; decision 0014
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Path,

    [Parameter(Mandatory = $true)]
    [ValidateRange(0, 2147483647)]
    [int] $Seed,

    [Parameter(Mandatory = $true)]
    [Alias('Profile')]
    [ValidateSet('Standard', 'Incompressible', 'Large', 'LongRun', 'Service')]
    [string] $TreeProfile,

    [ValidateRange(1, 68719476736)]
    [long] $LargeBytes = 4831838208
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# One fixed instant for every created item (2026-01-01T00:00:00Z).
$FixedTime = [datetime]::new(2026, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
$Ascii = [System.Text.ASCIIEncoding]::new()
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)

function New-Dir([string] $Dir) {
    [void][System.IO.Directory]::CreateDirectory($Dir)
}

# Pseudorandom bytes from the given generator, written in 1 MiB blocks.
function Write-RandomFile([string] $File, [long] $Length, [System.Random] $Rng) {
    $stream = [System.IO.File]::Open($File, [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $block = [byte[]]::new(1048576)
        $left = $Length
        while ($left -gt 0) {
            $Rng.NextBytes($block)
            $n = [int][Math]::Min([long]$block.Length, $left)
            $stream.Write($block, 0, $n)
            $left -= $n
        }
    }
    finally {
        $stream.Dispose()
    }
}

# Compressible ASCII text: numbered lines of words from a small fixed list.
function Write-TextFile([string] $File, [int] $Lines, [System.Random] $Rng) {
    $words = @('alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot',
        'golf', 'hotel', 'india', 'juliett', 'kilo', 'lima')
    $sb = [System.Text.StringBuilder]::new()
    for ($i = 0; $i -lt $Lines; $i++) {
        [void]$sb.Append('line ').Append($i).Append(':')
        for ($w = 0; $w -lt 8; $w++) {
            [void]$sb.Append(' ').Append($words[$Rng.Next(0, $words.Count)])
        }
        [void]$sb.Append("`r`n")
    }
    [System.IO.File]::WriteAllBytes($File, $Ascii.GetBytes($sb.ToString()))
}

function Set-FixedTimes([string] $Root) {
    # Files first, then directories deepest first, so setting a child does not
    # change its parent's time afterwards.
    Get-ChildItem -LiteralPath $Root -Recurse -Force -File | ForEach-Object {
        $_.CreationTimeUtc = $FixedTime
        $_.LastWriteTimeUtc = $FixedTime
        $_.LastAccessTimeUtc = $FixedTime
    }
    $dirs = @(Get-ChildItem -LiteralPath $Root -Recurse -Force -Directory |
            Sort-Object { $_.FullName.Length } -Descending)
    $dirs += Get-Item -LiteralPath $Root
    foreach ($d in $dirs) {
        $d.CreationTimeUtc = $FixedTime
        $d.LastWriteTimeUtc = $FixedTime
        $d.LastAccessTimeUtc = $FixedTime
    }
}

if (Test-Path -LiteralPath $Path) {
    if (@(Get-ChildItem -LiteralPath $Path -Force).Count -ne 0) {
        throw "refusing to write into non-empty directory: $Path"
    }
}
New-Dir $Path
$Root = (Resolve-Path -LiteralPath $Path).ProviderPath
$rng = [System.Random]::new($Seed)

switch ($TreeProfile) {
    'Standard' {
        New-Dir (Join-Path $Root 'text')
        New-Dir (Join-Path $Root 'bin')
        New-Dir (Join-Path $Root 'empty-dir')
        New-Dir (Join-Path $Root 'names')
        New-Dir (Join-Path $Root 'shared')

        [System.IO.File]::WriteAllBytes((Join-Path $Root 'text\readme.txt'),
            $Ascii.GetBytes("usg-provision WIM sample tree`r`nprofile Standard`r`nseed $Seed`r`n"))
        Write-TextFile (Join-Path $Root 'text\words-small.txt') 40 $rng
        Write-TextFile (Join-Path $Root 'text\words-large.txt') 6000 $rng

        # Sizes around the 32768-byte chunk boundary (wim.md section 4).
        foreach ($size in @(1, 4095, 32767, 32768, 32769, 65536, 100000, 200001)) {
            Write-RandomFile (Join-Path $Root ("bin\random-{0}.bin" -f $size)) $size $rng
        }

        [System.IO.File]::WriteAllBytes((Join-Path $Root 'text\empty.txt'), [byte[]]::new(0))

        # Names: a space, Latin-1 (U+00E9), Greek (U+03A9), CJK (U+65E5 U+672C)
        # and a supplementary-plane letter (U+10400, a surrogate pair in UTF-16).
        $names = @(
            'with space.txt',
            ('caf' + [char]0x00E9 + '.txt'),
            ([string][char]0x03A9 + '-omega.txt'),
            ([string][char]0x65E5 + [char]0x672C + '.txt'),
            ([char]::ConvertFromUtf32(0x10400) + '-supplementary.txt')
        )
        foreach ($n in $names) {
            [System.IO.File]::WriteAllBytes((Join-Path (Join-Path $Root 'names') $n),
                $Utf8NoBom.GetBytes("name sample, seed $Seed`r`n"))
        }

        $deep = Join-Path $Root 'nested\a\b\c\d\e'
        New-Dir $deep
        [System.IO.File]::WriteAllBytes((Join-Path $deep 'deep.txt'),
            $Ascii.GetBytes("nested file, seed $Seed`r`n"))

        # One file with an alternate data stream (NTFS).
        $ads = Join-Path $Root 'text\with-stream.txt'
        [System.IO.File]::WriteAllBytes($ads, $Ascii.GetBytes("main stream, seed $Seed`r`n"))
        Set-Content -LiteralPath $ads -Stream 'usgp-sample' -Value "alternate stream, seed $Seed" -Encoding ascii -NoNewline

        # Seed-independent content, identical in every Standard tree.
        $fixed = [System.Random]::new(0)
        Write-RandomFile (Join-Path $Root 'shared\common-98304.bin') 98304 $fixed
        Write-TextFile (Join-Path $Root 'shared\common.txt') 500 $fixed
    }
    'Incompressible' {
        Write-RandomFile (Join-Path $Root 'random-65536.bin') 65536 $rng
    }
    'Large' {
        Write-RandomFile (Join-Path $Root 'random-large.bin') $LargeBytes $rng
    }
    'LongRun' {
        [System.IO.File]::WriteAllBytes((Join-Path $Root 'zeros-32768.bin'), [byte[]]::new(32768))
        [System.IO.File]::WriteAllBytes((Join-Path $Root 'zeros-98304.bin'), [byte[]]::new(98304))
        $pattern = [byte[]]::new(300)
        $rng.NextBytes($pattern)
        $buf = [byte[]]::new(98304)
        for ($i = 0; $i -lt $buf.Length; $i++) { $buf[$i] = $pattern[$i % 300] }
        [System.IO.File]::WriteAllBytes((Join-Path $Root 'pattern300-98304.bin'), $buf)
    }
    'Service' {
        [System.IO.File]::WriteAllBytes((Join-Path $Root 'serviced.txt'),
            $Ascii.GetBytes("usg-provision WIM sample: added after capture, seed $Seed`r`n"))
        Write-RandomFile (Join-Path $Root 'serviced-40000.bin') 40000 $rng
    }
}

Set-FixedTimes $Root

$files = @(Get-ChildItem -LiteralPath $Root -Recurse -Force -File)
$total = ($files | Measure-Object -Property Length -Sum).Sum
if ($null -eq $total) { $total = 0 }
Write-Output ("New-SampleTree: {0} profile={1} seed={2} files={3} bytes={4}" -f
    $Root, $TreeProfile, $Seed, $files.Count, $total)
