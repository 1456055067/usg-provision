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
      Metadata        directory and security metadata for OPEN-WIM-7 (plan
                      M3 section 1.4, M-01 to M-20, samples S13 to S16).
                      Must be written on an NTFS volume with short-name
                      generation enabled (Build-Samples.ps1 creates one on a
                      VHD) and needs an elevated shell. It holds:
                        links\      three hard links to one file; relative
                                    and absolute (in-tree) symbolic links
                                    to a file and to a directory; a
                                    junction
                        attrs\      read-only, hidden, system, not
                                    content-indexed and archive-cleared
                                    files; a hidden and system directory
                        acl\        four ACL variants set with icacls,
                                    well-known SIDs only (protected
                                    explicit DACL, explicit owner, deny
                                    ACE, inheritable directory ACE with an
                                    inheriting child), and a second file
                                    with the first one's descriptor
                        shortnames\ long names that make NTFS generate
                                    short names, one explicit
                                    fsutil file setshortname, and names
                                    that need none
                        streams\    two named streams on one file, a
                                    stream on a directory, a zero-length
                                    named stream, an empty main stream
                                    with a non-empty named stream
                        special\    a sparse file (fsutil sparse), an
                                    NTFS-compressed file (compact /c) and
                                    an EFS-encrypted file (File.Encrypt)
                        longpath\   a file whose path below the tree root
                                    is over 300 UTF-16 units
                        many\       3000 small files with distinct
                                    content, named so that name order and
                                    creation order differ
                      Times are set last and differ per item and per field:
                      creation in 2021, last access in 2022, last write in
                      2023, each with a sub-second part, so a record can
                      tell the three fields apart (M-11). Reparse points
                      (links, junction) keep the times Windows gave them.
                      If EFS is not available the file stays plain; the
                      script prints a NOTE line and the tree listing
                      records the attributes it really has.
      Mixed           one chunk that does not shrink inside a compressed
                      resource (OPEN-WIM-5 chunk level, M-21, sample S17):
                      mixed-65536.bin (32768 bytes of text, then 32768
                      pseudorandom bytes) and mixed-reverse-65536.bin (the
                      same two halves in the other order).

    Every native command the Metadata profile runs is printed as a "cmd:"
    line, and its failure stops the script (fail closed).

    Except in the Metadata profile, all file and directory times are set to
    one fixed UTC instant so that two runs with the same seed give the same
    tree. The script refuses to write into an existing non-empty directory.

    The script is ASCII-only; non-ASCII names are built from code points.

.PARAMETER Path
    Directory to create (must not exist, or must be empty).

.PARAMETER Seed
    Seed for System.Random (0 to 2147483647).

.PARAMETER TreeProfile
    Standard, Incompressible, Large, LongRun, Service, Metadata or Mixed.
    Alias: -Profile (plan WU-W wording).

.PARAMETER LargeBytes
    Size of the Large profile's file in bytes.

.NOTES
    COMPLIANCE MAPPING:
    - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-7 (test
      inputs for integrity checking of image content)
    - SPEC: specs/standards/wim.md section 13 (OPEN-WIM-5, OPEN-WIM-6
      samples S11 and S12, OPEN-WIM-7, OPEN-WIM-10);
      specs/standards/wim-compression.md sections 3.4 and 7 (OPEN-WIMC-1);
      specs/preinstall-env.md REQ-PE-017 (apply fidelity, through S16)
    - Decision 0006 items 1 and 3; decision 0014; plan M3 section 1.4
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
    [ValidateSet('Standard', 'Incompressible', 'Large', 'LongRun', 'Service', 'Metadata', 'Mixed')]
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
function New-TextBytes([int] $Lines, [System.Random] $Rng) {
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
    # The comma keeps PowerShell from unrolling the array.
    return , $Ascii.GetBytes($sb.ToString())
}

function Write-TextFile([string] $File, [int] $Lines, [System.Random] $Rng) {
    [System.IO.File]::WriteAllBytes($File, (New-TextBytes $Lines $Rng))
}

function Write-AsciiFile([string] $File, [string] $Text) {
    [System.IO.File]::WriteAllBytes($File, $Ascii.GetBytes($Text))
}

# Metadata profile: runs a native tool, prints it as a "cmd:" line, and
# throws on a non-zero exit code (fail closed). Arguments are passed as an
# array, so paths with spaces stay one argument.
function Invoke-Native([string] $Exe, [string[]] $ArgList) {
    Write-Output ('cmd: {0} {1}' -f $Exe, ($ArgList -join ' '))
    $out = & $Exe @ArgList 2>&1 | ForEach-Object { $_.ToString() }
    $code = $LASTEXITCODE
    if ($code -ne 0) {
        throw ('{0} exited {1}: {2}' -f $Exe, $code, (($out | Out-String).Trim()))
    }
}

# Writes a named stream through the "file:stream" path form (NTFS).
function Write-NamedStream([string] $Target, [string] $Stream, [byte[]] $Bytes) {
    [System.IO.File]::WriteAllBytes(($Target + ':' + $Stream), $Bytes)
}

function Assert-Attribute([string] $Item, [System.IO.FileAttributes] $Want) {
    $have = [System.IO.File]::GetAttributes($Item)
    if (($have -band $Want) -ne $Want) {
        throw "$Item has attributes '$have', expected '$Want' to be set"
    }
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

# Metadata profile (M-11): distinct times per item and per field, so that
# creation (2021), last access (2022) and last write (2023) can be told
# apart, each with a sub-second part (1234567 ticks of 100 ns). Item k, in
# ordinal order of the path below the root (root first), gets k seconds.
# Reparse points are skipped: setting a time through a link could reach its
# target. Hard links share one file, so the last name set wins; the tree
# listing records what each name really has.
function Set-DistinctTimes([string] $Root) {
    $found = @(Get-ChildItem -LiteralPath $Root -Recurse -Force |
            Where-Object { ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 })
    [string[]] $keys = @($found | ForEach-Object { $_.FullName.Substring($Root.Length) })
    [object[]] $items = $found
    if ($items.Count -gt 1) { [Array]::Sort($keys, $items, [System.StringComparer]::Ordinal) }
    $all = @(Get-Item -LiteralPath $Root -Force) + $items
    $at = {
        param([int] $Year, [int] $K)
        [datetime]::new($Year, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc).AddTicks([long]$K * 10000000L + 1234567L)
    }
    $order = for ($k = 0; $k -lt $all.Count; $k++) { [pscustomobject]@{ K = $k; Item = $all[$k] } }
    # Files first, then directories deepest first (as Set-FixedTimes).
    $files = @($order | Where-Object { -not $_.Item.PSIsContainer })
    $dirs = @($order | Where-Object { $_.Item.PSIsContainer } | Sort-Object { $_.Item.FullName.Length } -Descending)
    foreach ($o in @($files + $dirs)) {
        $o.Item.CreationTimeUtc = & $at 2021 $o.K
        $o.Item.LastAccessTimeUtc = & $at 2022 $o.K
        $o.Item.LastWriteTimeUtc = & $at 2023 $o.K
    }
}

function New-MetadataTree([string] $Root, [int] $Seed, [System.Random] $Rng) {
    $volume = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($Root))
    if ($volume.DriveFormat -ne 'NTFS') {
        throw "profile Metadata needs an NTFS volume; $Root is on '$($volume.DriveFormat)'"
    }
    $principal = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'profile Metadata needs an elevated shell (links, short names, owners)'
    }

    # links\: hard links, symbolic links (relative and absolute, in-tree),
    # a junction (M-12, M-13).
    $d = Join-Path $Root 'links'
    New-Dir (Join-Path $d 'sub')
    New-Dir (Join-Path $d 'target-dir')
    $original = Join-Path $d 'hard-original.txt'
    Write-AsciiFile $original "hard link group, seed $Seed`r`n"
    foreach ($l in @('hard-two.txt', 'sub\hard-three.txt')) {
        Invoke-Native 'fsutil.exe' @('hardlink', 'create', (Join-Path $d $l), $original)
    }
    Write-AsciiFile (Join-Path $d 'target-file.txt') "symbolic link target file, seed $Seed`r`n"
    Write-AsciiFile (Join-Path $d 'target-dir\inside.txt') "symbolic link target directory content, seed $Seed`r`n"
    $links = @(
        @{ Name = 'sym-file-rel.txt'; Target = 'target-file.txt'; Dir = $false },
        @{ Name = 'sym-file-abs.txt'; Target = (Join-Path $d 'target-file.txt'); Dir = $false },
        @{ Name = 'sym-dir-rel'; Target = 'target-dir'; Dir = $true },
        @{ Name = 'sym-dir-abs'; Target = (Join-Path $d 'target-dir'); Dir = $true }
    )
    foreach ($l in $links) {
        $p = Join-Path $d $l.Name
        Write-Output ('op: symbolic link {0} -> {1} (directory: {2})' -f $p, $l.Target, $l.Dir)
        if ($l.Dir) { [void][System.IO.Directory]::CreateSymbolicLink($p, $l.Target) }
        else { [void][System.IO.File]::CreateSymbolicLink($p, $l.Target) }
    }
    Invoke-Native 'cmd.exe' @('/d', '/c', 'mklink', '/J', (Join-Path $d 'junction'), (Join-Path $d 'target-dir'))

    # attrs\: one attribute each (M-10). SetAttributes replaces the set, so
    # each file has only the attribute named (archive cleared); the
    # archive-cleared file has none.
    $d = Join-Path $Root 'attrs'
    New-Dir $d
    $attrFiles = @(
        @('read-only.txt', [System.IO.FileAttributes]::ReadOnly),
        @('hidden.txt', [System.IO.FileAttributes]::Hidden),
        @('system.txt', [System.IO.FileAttributes]::System),
        @('not-indexed.txt', [System.IO.FileAttributes]::NotContentIndexed),
        @('archive-cleared.txt', [System.IO.FileAttributes]::Normal),
        @('archive-set.txt', [System.IO.FileAttributes]::Archive)
    )
    foreach ($a in $attrFiles) {
        $f = Join-Path $d $a[0]
        Write-AsciiFile $f "attribute sample $($a[1]), seed $Seed`r`n"
        [System.IO.File]::SetAttributes($f, $a[1])
    }
    $hs = Join-Path $d 'hidden-system-dir'
    New-Dir $hs
    Write-AsciiFile (Join-Path $hs 'inside.txt') "inside a hidden system directory, seed $Seed`r`n"
    $hsInfo = [System.IO.DirectoryInfo]::new($hs)
    $hsInfo.Attributes = [System.IO.FileAttributes]::Directory -bor [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System

    # acl\: four descriptor variants, well-known SIDs only (M-14):
    # S-1-5-32-544 Administrators, S-1-5-32-545 Users, S-1-5-18 SYSTEM,
    # S-1-1-0 Everyone. protected.txt and protected-twin.txt get the same
    # commands, so the same descriptor. The deny ACE is write-data only, so
    # the times can still be set afterwards.
    $d = Join-Path $Root 'acl'
    New-Dir $d
    foreach ($n in @('protected.txt', 'protected-twin.txt')) {
        $f = Join-Path $d $n
        Write-AsciiFile $f "protected explicit DACL ($n), seed $Seed`r`n"
        Invoke-Native 'icacls.exe' @($f, '/inheritance:r', '/grant:r', '*S-1-5-32-544:(F)', '*S-1-5-18:(F)')
    }
    $f = Join-Path $d 'owner-system.txt'
    Write-AsciiFile $f "explicit owner, seed $Seed`r`n"
    Invoke-Native 'icacls.exe' @($f, '/setowner', '*S-1-5-18')
    Invoke-Native 'icacls.exe' @($f, '/grant', '*S-1-5-32-545:(R)')
    $f = Join-Path $d 'deny-ace.txt'
    Write-AsciiFile $f "deny ACE, seed $Seed`r`n"
    Invoke-Native 'icacls.exe' @($f, '/inheritance:r', '/grant:r', '*S-1-5-32-544:(F)')
    Invoke-Native 'icacls.exe' @($f, '/deny', '*S-1-1-0:(WD)')
    $inh = Join-Path $d 'inherit-dir'
    New-Dir $inh
    Invoke-Native 'icacls.exe' @($inh, '/inheritance:r', '/grant:r', '*S-1-5-32-544:(OI)(CI)(F)', '*S-1-5-32-545:(OI)(CI)(RX)')
    Write-AsciiFile (Join-Path $inh 'child.txt') "inherits from inherit-dir, seed $Seed`r`n"

    # shortnames\: generated short names, an explicit one, and names that
    # need none (M-05).
    $d = Join-Path $Root 'shortnames'
    New-Dir (Join-Path $d 'Long Directory Name')
    foreach ($n in @('Long File Name Number One.txt', 'Long File Name Number Two.txt',
            'name.with.several.dots.txt', 'SHORT.TXT', 'lower.txt',
            'explicit-short-name-target.txt', 'Long Directory Name\inside.txt')) {
        Write-AsciiFile (Join-Path $d $n) "short name sample, seed $Seed`r`n"
    }
    Invoke-Native 'fsutil.exe' @('file', 'setshortname', (Join-Path $d 'explicit-short-name-target.txt'), 'EXPLICIT.TXT')

    # streams\: named streams (M-09).
    $d = Join-Path $Root 'streams'
    New-Dir $d
    $f = Join-Path $d 'two-streams.txt'
    Write-AsciiFile $f "main stream with two named streams, seed $Seed`r`n"
    Write-NamedStream $f 'usgp-one' ($Ascii.GetBytes("named stream one, seed $Seed"))
    Write-NamedStream $f 'usgp-two' ($Ascii.GetBytes("named stream two, seed $Seed, longer than one"))
    $sd = Join-Path $d 'dir-with-stream'
    New-Dir $sd
    Write-NamedStream $sd 'usgp-dir-stream' ($Ascii.GetBytes("stream on a directory, seed $Seed"))
    $f = Join-Path $d 'zero-length-stream.txt'
    Write-AsciiFile $f "main stream with a zero-length named stream, seed $Seed`r`n"
    Write-NamedStream $f 'usgp-zero' ([byte[]]::new(0))
    $f = Join-Path $d 'empty-main.txt'
    [System.IO.File]::WriteAllBytes($f, [byte[]]::new(0))
    Write-NamedStream $f 'usgp-named' ($Ascii.GetBytes("named stream on an empty main stream, seed $Seed"))

    # special\: sparse, NTFS-compressed and EFS files (M-15).
    $d = Join-Path $Root 'special'
    New-Dir $d
    $f = Join-Path $d 'sparse-196608.bin'
    $buf = [byte[]]::new(196608)
    $half = [byte[]]::new(65536)
    $Rng.NextBytes($half)
    [Array]::Copy($half, 0, $buf, 0, 65536)
    $Rng.NextBytes($half)
    [Array]::Copy($half, 0, $buf, 131072, 65536)
    [System.IO.File]::WriteAllBytes($f, $buf)
    Invoke-Native 'fsutil.exe' @('sparse', 'setflag', $f)
    Invoke-Native 'fsutil.exe' @('sparse', 'setrange', $f, '65536', '65536')
    Assert-Attribute $f ([System.IO.FileAttributes]::SparseFile)
    $f = Join-Path $d 'compressed.txt'
    Write-TextFile $f 2000 $Rng
    Invoke-Native 'compact.exe' @('/c', '/q', $f)
    Assert-Attribute $f ([System.IO.FileAttributes]::Compressed)
    $f = Join-Path $d 'encrypted.txt'
    Write-AsciiFile $f "EFS sample, seed $Seed`r`n"
    Write-Output ('op: File.Encrypt {0}' -f $f)
    try {
        [System.IO.File]::Encrypt($f)
        Assert-Attribute $f ([System.IO.FileAttributes]::Encrypted)
    }
    catch {
        Write-Output ('NOTE: EFS not applied to special\encrypted.txt (the file stays plain): {0}' -f $_.Exception.Message)
    }

    # longpath\: a path over 300 UTF-16 units below the root (M-16). .NET
    # handles long paths itself; no native tool touches this directory.
    $p = Join-Path $Root 'longpath'
    for ($i = 1; $i -le 6; $i++) {
        $p = Join-Path $p (('segment-{0:d2}-' -f $i) + ('x' * 39))
    }
    New-Dir $p
    $f = Join-Path $p 'file-at-the-end-of-a-long-path.txt'
    Write-AsciiFile $f "long path sample, seed $Seed`r`n"
    $rel = $f.Length - $Root.Length - 1
    if ($rel -le 300) { throw "long path below the root is $rel units, expected over 300" }

    # many\: 3000 small files with distinct content (M-17). Names start
    # with a word picked by -Seed, so name order and creation order differ;
    # mixed case, so ordinal and case-insensitive orders differ too.
    $d = Join-Path $Root 'many'
    New-Dir $d
    $words = @('Zulu', 'alpha', 'Bravo', 'charlie', 'Delta', 'echo', 'Foxtrot', 'golf')
    for ($i = 0; $i -lt 3000; $i++) {
        $n = '{0}-{1:d4}.txt' -f $words[$Rng.Next(0, $words.Count)], $i
        Write-AsciiFile (Join-Path $d $n) "many entry $i, seed $Seed`r`n"
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
    'Metadata' {
        New-MetadataTree $Root $Seed $rng
    }
    'Mixed' {
        # One compressible chunk and one pseudorandom chunk (32768 bytes
        # each, wim.md section 4), in both orders.
        $text = New-TextBytes 700 $rng
        if ($text.Length -lt 32768) { throw "text part is $($text.Length) bytes, need 32768" }
        $rand = [byte[]]::new(32768)
        $rng.NextBytes($rand)
        $buf = [byte[]]::new(65536)
        [Array]::Copy($text, 0, $buf, 0, 32768)
        [Array]::Copy($rand, 0, $buf, 32768, 32768)
        [System.IO.File]::WriteAllBytes((Join-Path $Root 'mixed-65536.bin'), $buf)
        [Array]::Copy($rand, 0, $buf, 0, 32768)
        [Array]::Copy($text, 0, $buf, 32768, 32768)
        [System.IO.File]::WriteAllBytes((Join-Path $Root 'mixed-reverse-65536.bin'), $buf)
    }
}

if ($TreeProfile -eq 'Metadata') {
    Set-DistinctTimes $Root
}
else {
    Set-FixedTimes $Root
}

$files = @(Get-ChildItem -LiteralPath $Root -Recurse -Force -File)
$total = ($files | Measure-Object -Property Length -Sum).Sum
if ($null -eq $total) { $total = 0 }
Write-Output ("New-SampleTree: {0} profile={1} seed={2} files={3} bytes={4}" -f
    $Root, $TreeProfile, $Seed, $files.Count, $total)
