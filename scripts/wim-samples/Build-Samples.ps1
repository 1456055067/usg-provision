#Requires -Version 7.2
#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Builds the DISM sample WIM files and their observation records (plan
    WU-W, decision 0006). Windows only; needs an elevated shell for DISM.

.DESCRIPTION
    Every capture source is a tree written by New-SampleTree.ps1 from our own
    generated content. Every DISM command runs with /English and is logged
    verbatim, with its exit code, to commands.log before and after it runs.

    Set Standard (job "generate"; uploaded, every file under 64 MiB):

      ID   Command                                              Source
      S01  /Capture-Image /Compress:none                        tree-01
      S02  /Capture-Image /Compress:fast                        tree-01
      S03  /Capture-Image /Compress:max                         tree-01
      S04  /Capture-Image /Compress:fast, /Append-Image x 11    tree-01..tree-12
      S05  /Capture-Image /Compress:fast /CheckIntegrity        tree-01
      S06  /Split-Image of S04, /FileSize:1                     S04.wim
      S07  /Export-Image of S02 index 1, /Compress:recovery     S02.wim
      S09  /Capture-Image /Compress:fast                        tree-inc
      S10  /Capture-Image /Compress:fast                        tree-long
      S11A /Capture-Image /Compress:fast, /Append-Image of the  tree-01 twice
           same tree
      S11B /Export-Image of S02 index 1, twice into one new     S02.wim
           file
      S12A copy of S04; /Mount-Image index 1, add files,        S04.wim,
           /Unmount-Image /Commit                               tree-service
      S12B copy of S04; /Delete-Image index 1, /Append-Image    S04.wim,
                                                                tree-01

    S11 (BOOT-011) and S12 (BOOT-012) asked what DISM writes. Run
    40599556702 answered (docs/formats/wim-observed.md OBS-018 to
    OBS-023), so their rows now carry expected "accept". If DISM itself
    refuses the second S11 step, the row's status is "dism-refused" and
    the partial file is deleted; the verify job then fails, because that
    differs from the recorded observation.

    Set Large (job "generate-large"; observations only, the WIM is deleted):

      S08  /Capture-Image /Compress:fast                        tree-large
      S08B /Capture-Image /Compress:fast                        tree-large-text
           (compressible, over 4 GiB: OPEN-WIM-10; WIM deleted too)

    Set Metadata (job "generate-metadata"; plan M3 section 1.4, OPEN-WIM-7;
    uploaded as its own artifact, every file under 64 MiB):

      S13  /Capture-Image /Compress:none                        tree-meta
      S14  /Capture-Image /Compress:fast                        tree-meta
      S15  /Capture-Image /Compress:none of the volume root     the VHD
           that holds tree-meta                                 volume
      S17  /Capture-Image /Compress:fast                        tree-mixed
      S13B /Capture-Image /Compress:none                        tree-meta2
      S13C /Capture-Image /Compress:none /NoRpFix               tree-meta2
      S17B /Capture-Image /Compress:fast                        tree-mixed-tail

    tree-meta2 (profile Metadata2, seed 602; the R3 follow-up requests in
    docs/formats/wim-observed.md) is written on a second VHD volume
    lettered T:, with its out-of-tree link targets in T:\outside-tree.

    tree-meta (profile Metadata, seed 601) is written on a fresh NTFS
    volume of an expandable VHD that this script creates and attaches with
    DiskPart, with short-name generation enabled on that volume (fsutil
    8dot3name). The VHD is detached at the end and never uploaded.
    tree-mixed (profile Mixed, seed 701) is written in -WorkDir.

    Set Reference (job "reference"; text only, never a sample or a disk
    image):

      S16  /Apply-Image of S13 index 1 (from -SampleDir, the     S13.wim
           generate-metadata artifact of the same run) to the
           root of a fresh NTFS VHD volume, then a tree manifest
           of the result
      S16B S13B index 1 to the root of a volume lettered S:      S13B.wim
      S16C S13B index 1 to U:\deep\apply-here (subdirectory)    S13B.wim
      S16D S13C index 1 to the root of a volume lettered V:      S13C.wim

    Tree manifests (tree-meta, the volume root, S16) are written by this
    script (Save-TreeManifest): one row per item with its type, attributes,
    the three times as FILETIME values, length, SHA-256, named streams,
    SDDL, link target, hard-link names and reparse tag. Short names come
    from "dir /x" per directory, reparse data from "fsutil reparsepoint
    query". They stand in for WU-5's tree_manifest tool until it exists.

    Outputs in -OutDir:
      host.txt            OS build, DISM version, runner image, run identity
      commands.log        every DISM command line, UTC time, exit code
      trees.txt           every source file: path, length, SHA-1, SHA-256;
                          alternate streams; hex at chunk boundaries of the
                          incompressible file
      Sxx.wiminfo.txt     dism /Get-WimInfo, whole file and each index
      Sxx*.dump.txt       Dump-WimStructure.ps1 output for each file or part
      manifest.tsv        id, file, bytes, sha256, compression, images,
                          expected (the consumer contract, README.md)
      editions.tsv        id, index, name, description as DISM reported them
      SHA256SUMS          sha256sum-format list of every sample file
      observations.txt    all of the above text, concatenated in order
      the sample files    (Standard and Metadata sets)
      <tree>.manifest.tsv tree manifests (Metadata and Reference sets)
      <tree>.dirx.txt     dir /x of every directory (short names)
      <tree>.reparse.txt  fsutil reparsepoint query of every reparse point
      Sxx.diskpart.txt    DiskPart and fsutil output of the VHD helpers

    Fail closed: any failed command, any DISM report that differs from the
    names and descriptions we asked for, or any sample over the size cap
    makes the script exit 1 after writing what it has. A sample whose input
    failed is recorded as "not-produced", never silently dropped.

.PARAMETER OutDir
    Artifact directory (created; must be empty if it exists).

.PARAMETER WorkDir
    Scratch directory for the source trees and the Large WIM.

.PARAMETER Set
    Standard, Large, Metadata or Reference.

.PARAMETER SampleDir
    Reference set only: the downloaded generate-metadata artifact (holds
    manifest.tsv, SHA256SUMS and S13.wim).

.PARAMETER LargeBytes
    Size of the S08 source file (default 4.5 GiB).

.NOTES
    COMPLIANCE MAPPING:
    - NIST 800-53: SA-11 (Developer Testing and Evaluation), SR-4
      (Provenance: every sample's command, tool version and host recorded),
      SI-7 (test inputs for image integrity checks)
    - SPEC: specs/standards/wim.md section 13 (OPEN-WIM-1 to 7, 10, 11;
      samples S11 and S12); section 6 (metadata, samples S13 to S17);
      specs/standards/wim-compression.md section 7 (OPEN-WIMC-1);
      specs/os-images.md REQ-IMG-042 (12 indexes);
      specs/preinstall-env.md REQ-PE-017 (apply fidelity reference, S16)
    - Decision 0006 items 1 to 4; decision 0014; plan M3 section 1.4
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutDir,

    [Parameter(Mandatory = $true)]
    [string] $WorkDir,

    [ValidateSet('Standard', 'Large', 'Metadata', 'Reference')]
    [string] $Set = 'Standard',

    [long] $LargeBytes = 4831838208,

    [string] $SampleDir = ''
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$MaxUploadBytes = 64MB
$VhdMegabytes = 2048
# Top-level folders of a volume that the tree manifests list but do not
# enter (Windows creates them; their content is not ours).
$VolumeNoDescend = @('System Volume Information', '$RECYCLE.BIN')
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$Here = $PSScriptRoot

foreach ($d in @($OutDir, $WorkDir)) {
    if ((Test-Path -LiteralPath $d) -and @(Get-ChildItem -LiteralPath $d -Force).Count -ne 0) {
        throw "refusing to use non-empty directory: $d"
    }
    [void][System.IO.Directory]::CreateDirectory($d)
}
if ($Set -eq 'Reference' -and ($SampleDir.Length -eq 0 -or -not (Test-Path -LiteralPath $SampleDir -PathType Container))) {
    throw "-Set Reference needs -SampleDir, the generate-metadata artifact directory"
}
$OutDir = (Resolve-Path -LiteralPath $OutDir).ProviderPath
$WorkDir = (Resolve-Path -LiteralPath $WorkDir).ProviderPath
$CommandsLog = Join-Path $OutDir 'commands.log'
$Failures = [System.Collections.Generic.List[string]]::new()
$Manifest = [System.Collections.Generic.List[string]]::new()
$Editions = [System.Collections.Generic.List[string]]::new()
$Manifest.Add("id`tfile`tbytes`tsha256`tcompression`timages`texpected`tstatus")
$Editions.Add("id`tindex`tname`tdescription")

function Add-Text([string] $File, [string] $Text) {
    [System.IO.File]::AppendAllText($File, $Text + "`r`n", $Utf8NoBom)
}

# LF line endings, UTF-8 without BOM: these files are read on Linux
# (sha256sum -c, the WU-5 consumer). WriteAllLines would use CRLF here.
function Write-LfLines([string] $File, [string[]] $Lines) {
    $text = if ($Lines.Count -eq 0) { '' } else { ($Lines -join "`n") + "`n" }
    [System.IO.File]::WriteAllText($File, $text, $Utf8NoBom)
}

function Get-Sha256([string] $File) {
    (Get-FileHash -LiteralPath $File -Algorithm SHA256).Hash.ToLowerInvariant()
}

# Runs dism.exe /English <args>; logs the command line and exit code; writes
# the output to $OutFile. Arguments must not contain spaces or quotes, so the
# logged line is exactly the command line DISM receives.
function Invoke-Dism([string] $Id, [string[]] $DismArgs, [string] $OutFile, [switch] $AllowFailure) {
    $full = @('/English') + $DismArgs
    foreach ($a in $full) {
        if ($a -match '[\s"]') { throw "DISM argument with space or quote: $a" }
    }
    $line = 'dism.exe ' + ($full -join ' ')
    Add-Text $CommandsLog ('{0} {1} RUN  {2}' -f [datetime]::UtcNow.ToString('o'), $Id, $line)
    $out = & dism.exe @full 2>&1 | ForEach-Object { $_.ToString() }
    $code = $LASTEXITCODE
    Add-Text $CommandsLog ('{0} {1} EXIT {2}' -f [datetime]::UtcNow.ToString('o'), $Id, $code)
    Add-Text $OutFile ('> ' + $line)
    Add-Text $OutFile (($out | Out-String -Width 4096).TrimEnd())
    Add-Text $OutFile ('exit ' + $code)
    Add-Text $OutFile ''
    if ($code -ne 0 -and -not $AllowFailure) {
        throw "$Id`: dism exited $code ($line)"
    }
    return $code
}

# Runs another Windows tool (DiskPart, fsutil) the way Invoke-Dism runs
# DISM: the command line and exit code go to commands.log, the output to
# $OutFile. Arguments must not contain spaces or quotes.
function Invoke-Tool([string] $Id, [string] $Exe, [string[]] $ToolArgs, [string] $OutFile, [switch] $AllowFailure) {
    foreach ($a in $ToolArgs) {
        if ($a -match '[\s"]') { throw "$Exe argument with space or quote: $a" }
    }
    $line = $Exe + ' ' + ($ToolArgs -join ' ')
    Add-Text $CommandsLog ('{0} {1} RUN  {2}' -f [datetime]::UtcNow.ToString('o'), $Id, $line)
    $out = & $Exe @ToolArgs 2>&1 | ForEach-Object { $_.ToString() }
    $code = $LASTEXITCODE
    Add-Text $CommandsLog ('{0} {1} EXIT {2}' -f [datetime]::UtcNow.ToString('o'), $Id, $code)
    Add-Text $OutFile ('> ' + $line)
    Add-Text $OutFile (($out | Out-String -Width 4096).TrimEnd())
    Add-Text $OutFile ('exit ' + $code)
    Add-Text $OutFile ''
    if ($code -ne 0 -and -not $AllowFailure) {
        throw "$Id`: $Exe exited $code ($line)"
    }
    return $code
}

# Runs a DiskPart script; every script line is logged to commands.log
# before it runs. DiskPart stops at the first failing line and exits
# non-zero.
function Invoke-DiskPart([string] $Id, [string[]] $Lines, [string] $OutFile, [switch] $AllowFailure) {
    $scriptFile = Join-Path $WorkDir "$Id.diskpart.tmp"
    [System.IO.File]::WriteAllLines($scriptFile, $Lines, [System.Text.ASCIIEncoding]::new())
    foreach ($l in $Lines) {
        Add-Text $CommandsLog ('{0} {1} DISKPART {2}' -f [datetime]::UtcNow.ToString('o'), $Id, $l)
        Add-Text $OutFile ('diskpart script: ' + $l)
    }
    try {
        return (Invoke-Tool $Id 'diskpart.exe' @('/s', $scriptFile) $OutFile -AllowFailure:$AllowFailure)
    }
    finally {
        Remove-Item -LiteralPath $scriptFile -ErrorAction SilentlyContinue
    }
}

# A drive letter no volume uses, from the end of the alphabet.
function Get-FreeLetter {
    $used = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
    foreach ($l in 'RSTUVWXYP'.ToCharArray()) {
        if ([string]$l -notin $used) { return [string]$l }
    }
    throw 'no free drive letter for the sample VHD'
}

# VHD helper: creates an expandable VHD file in -WorkDir, attaches it, makes
# one NTFS partition (GPT disk), assigns a free letter and enables
# short-name generation on that volume only. Returns "X:". The VHD is a
# scratch disk image of our own content; it is never uploaded.
function New-SampleVhd([string] $Id, [string] $File, [string] $Label, [string] $Letter = '') {
    if (-not $File.StartsWith($WorkDir, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "$Id`: VHD file must be under -WorkDir: $File"
    }
    if (Test-Path -LiteralPath $File) { throw "$Id`: VHD file already exists: $File" }
    # A fixed -Letter makes capture and apply letters differ on purpose
    # (S16B: apply to another letter than the capture's).
    if ($Letter.Length -gt 0) {
        $used = @([System.IO.DriveInfo]::GetDrives() | ForEach-Object { $_.Name.Substring(0, 1).ToUpperInvariant() })
        if ($Letter -notmatch '^[A-Z]$' -or $Letter -in $used) { throw "$Id`: drive letter $Letter is not free" }
        $letter = $Letter
    }
    else {
        $letter = Get-FreeLetter
    }
    $out = Join-Path $OutDir "$Id.diskpart.txt"
    [void](Invoke-DiskPart "$Id-vhd-create" @(
            "create vdisk file=`"$File`" maximum=$VhdMegabytes type=expandable",
            "select vdisk file=`"$File`"",
            'attach vdisk',
            'convert gpt',
            'create partition primary',
            "format fs=ntfs quick label=$Label",
            "assign letter=$letter") $out)
    $root = "$letter`:\"
    for ($i = 0; $i -lt 60 -and -not (Test-Path -LiteralPath $root); $i++) { Start-Sleep -Seconds 1 }
    if (-not (Test-Path -LiteralPath $root)) { throw "$Id`: volume $root did not appear" }
    [void](Invoke-Tool "$Id-8dot3-set" 'fsutil.exe' @('8dot3name', 'set', "$letter`:", '0') $out)
    [void](Invoke-Tool "$Id-8dot3-query" 'fsutil.exe' @('8dot3name', 'query', "$letter`:") $out)
    [void](Invoke-Tool "$Id-fsinfo" 'fsutil.exe' @('fsinfo', 'ntfsinfo', "$letter`:") $out -AllowFailure)
    return "$letter`:"
}

# Detaches a VHD made by New-SampleVhd. A failure is recorded, not thrown,
# so it never hides the error that led here.
function Dismount-SampleVhd([string] $Id, [string] $File) {
    $out = Join-Path $OutDir "$Id.diskpart.txt"
    try {
        $code = Invoke-DiskPart "$Id-vhd-detach" @("select vdisk file=`"$File`"", 'detach vdisk') $out -AllowFailure
        if ($code -ne 0) { $Failures.Add("$Id`: detaching $File failed (exit $code)") }
    }
    catch {
        $Failures.Add("$Id`: detaching $File failed: $($_.Exception.Message)")
    }
}

# Every item below $Root (not $Root itself), not entering reparse points or
# the top-level folders in $NoDescend. Returns one array object: assign
# the result before piping it.
function Get-TreeItems([string] $Root, [string[]] $NoDescend) {
    $items = [System.Collections.Generic.List[object]]::new()
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push($Root)
    $top = $true
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        foreach ($c in @(Get-ChildItem -LiteralPath $dir -Force)) {
            $items.Add($c)
            $isReparse = ($c.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
            if ($c.PSIsContainer -and -not $isReparse -and -not ($top -and $c.Name -in $NoDescend)) {
                $stack.Push($c.FullName)
            }
        }
        $top = $false
    }
    return , $items.ToArray()
}

function Get-RelPath([string] $Base, [string] $Full) {
    $b = $Base.TrimEnd('\')
    $r = $Full.Substring([Math]::Min($b.Length, $Full.Length)).TrimStart('\')
    if ($r.Length -eq 0) { return '.' }
    return $r
}

# One TSV field: no tab or line break.
function Format-Field([string] $Text) {
    if ($null -eq $Text -or $Text.Length -eq 0) { return '-' }
    return ($Text -replace '[\t\r\n]+', ' ')
}

# Tree manifest (M-20): one row per item, $Root itself first as ".", the
# rest sorted by path (ordinal); UTF-8 without BOM, LF, tab-separated.
# Columns: path, type (dir, file, reparse:<LinkType>), attributes (hex),
# creation, last-access and last-write as FILETIME (100 ns units since
# 1601-01-01 UTC), length (files), sha256 (main stream), streams
# (name:length:sha256 for each named stream, ";"-separated), sddl (owner,
# group, DACL), link-target, hard-links (fsutil hardlink list, "|"-
# separated, only for files with more than one name), reparse-tag (fsutil
# reparsepoint query; its full output goes to <OutFile without
# .manifest.tsv>.reparse.txt), then (added for R4, BOOT-003) sd-binary
# (hex of the owner, group and DACL descriptor as .NET's Get-Acl returns it
# in binary form; not reparse points) and link-dacl (for reparse points
# only: the DACL of the link itself in SDDL, from "icacls /save /L").
# -NoContent skips sha256 and streams (no file
# content is read, so no last-access time is touched by this script).
# A value that cannot be read is "error: <message>", never dropped.
function Save-TreeManifest([string] $Id, [string] $Root, [string] $OutFile, [string[]] $NoDescend = @(), [switch] $NoContent) {
    $reparseFile = $OutFile -replace '\.manifest\.tsv$', '.reparse.txt'
    $found = Get-TreeItems $Root $NoDescend
    [string[]] $keys = @($found | ForEach-Object { Get-RelPath $Root $_.FullName })
    [object[]] $items = $found
    if ($items.Count -gt 1) { [Array]::Sort($keys, $items, [System.StringComparer]::Ordinal) }
    $all = @(Get-Item -LiteralPath $Root -Force) + $items
    $rows = [System.Collections.Generic.List[string]]::new()
    $rows.Add("path`ttype`tattributes`tcreation`tlast-access`tlast-write`tlength`tsha256`tstreams`tsddl`tlink-target`thard-links`treparse-tag`tsd-binary`tlink-dacl")
    $aclTmp = Join-Path $WorkDir "$Id.icacls.tmp"
    foreach ($i in $all) {
        $rel = Get-RelPath $Root $i.FullName
        $isReparse = ($i.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        $isDir = $i.PSIsContainer
        $type = if ($isReparse) { 'reparse:' + (Format-Field ([string]$i.LinkType)) } elseif ($isDir) { 'dir' } else { 'file' }
        $length = if ($isDir) { '-' } else { [string]$i.Length }
        $sha = '-'
        $streams = '-'
        if (-not $NoContent -and -not $isReparse) {
            if (-not $isDir) {
                try { $sha = (Get-FileHash -LiteralPath $i.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
                catch { $sha = 'error: ' + (Format-Field $_.Exception.Message) }
            }
            try {
                # Run 40752616665: stream listing of paths over 260
                # characters failed with "path not found"; such paths use
                # the \\?\ form.
                $sp = $i.FullName
                if ($sp.Length -ge 248 -and -not $sp.StartsWith('\\?\')) { $sp = '\\?\' + $sp }
                $named = @(Get-Item -LiteralPath $sp -Stream * -Force -ErrorAction Stop |
                        Where-Object { $_.Stream -ne ':$DATA' } | Sort-Object Stream)
                $parts = foreach ($n in $named) {
                    $b = [System.IO.File]::ReadAllBytes($sp + ':' + $n.Stream)
                    '{0}:{1}:{2}' -f $n.Stream, $b.Length, ([Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($b))).ToLowerInvariant()
                }
                $streams = Format-Field (@($parts) -join ';')
            }
            catch { $streams = 'error: ' + (Format-Field $_.Exception.Message) }
        }
        $sddl = '-'
        $sdBin = '-'
        $linkDacl = '-'
        if (-not $isReparse) {
            try {
                $acl = Get-Acl -LiteralPath $i.FullName
                $sddl = Format-Field $acl.Sddl
                $sdBin = [Convert]::ToHexString($acl.GetSecurityDescriptorBinaryForm()).ToLowerInvariant()
            }
            catch { $sddl = 'error: ' + (Format-Field $_.Exception.Message) }
        }
        else {
            # icacls /save writes UTF-16 text: the name, then the SDDL line.
            Remove-Item -LiteralPath $aclTmp -ErrorAction SilentlyContinue
            $o = @(& icacls.exe $i.FullName /save $aclTmp /L 2>&1 | ForEach-Object { $_.ToString() })
            if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $aclTmp)) {
                $lines = @([System.IO.File]::ReadAllLines($aclTmp, [System.Text.Encoding]::Unicode) | Where-Object { $_ })
                $linkDacl = if ($lines.Count -ge 2) { Format-Field $lines[1] } else { 'error: icacls /save gave ' + $lines.Count + ' lines' }
            }
            else {
                $linkDacl = 'error: ' + (Format-Field ($o -join ' '))
            }
        }
        $target = Format-Field ([string]$i.LinkTarget)
        $links = '-'
        if (-not $isDir -and -not $isReparse -and [string]$i.LinkType -eq 'HardLink') {
            $o = @(& fsutil.exe hardlink list $i.FullName 2>&1 | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ })
            $links = if ($LASTEXITCODE -eq 0) { Format-Field ((@($o) | Sort-Object -CaseSensitive) -join '|') } else { 'error: ' + (Format-Field ($o -join ' ')) }
        }
        $tag = '-'
        if ($isReparse) {
            $o = @(& fsutil.exe reparsepoint query $i.FullName 2>&1 | ForEach-Object { $_.ToString() })
            Add-Text $reparseFile ("== $Id $rel (exit $LASTEXITCODE)")
            Add-Text $reparseFile ($o -join "`r`n")
            $m = [regex]::Match(($o -join "`n"), 'Reparse Tag Value\s*:\s*(0x[0-9A-Fa-f]+)')
            $tag = if ($LASTEXITCODE -eq 0 -and $m.Success) { $m.Groups[1].Value.ToLowerInvariant() } else { 'error: see reparse.txt' }
        }
        $rows.Add(("{0}`t{1}`t0x{2:x8}`t{3}`t{4}`t{5}`t{6}`t{7}`t{8}`t{9}`t{10}`t{11}`t{12}`t{13}`t{14}" -f
                (Format-Field $rel), $type, [int]$i.Attributes,
                $i.CreationTimeUtc.ToFileTimeUtc(), $i.LastAccessTimeUtc.ToFileTimeUtc(), $i.LastWriteTimeUtc.ToFileTimeUtc(),
                $length, $sha, $streams, $sddl, $target, $links, $tag, $sdBin, $linkDacl))
    }
    Remove-Item -LiteralPath $aclTmp -ErrorAction SilentlyContinue
    Write-LfLines $OutFile $rows.ToArray()
    Add-Text $CommandsLog ('{0} {1} manifest of {2}: {3} rows{4}' -f [datetime]::UtcNow.ToString('o'), $Id, $Root,
        ($rows.Count - 1), $(if ($NoContent) { ' (no content read)' } else { '' }))
}

# Short names (M-05): "dir /x /a" of $Root and of every directory below it
# that Get-TreeItems enters. cmd cannot open paths over 260 characters;
# such a directory gets its error text, which is recorded too.
function Save-ShortNames([string] $Id, [string] $Root, [string] $OutFile, [string[]] $NoDescend = @()) {
    # Assigned first: Get-TreeItems returns its array as one object
    # (", $array"), so piping the call directly would give Where-Object the
    # whole array as $_.
    $found = Get-TreeItems $Root $NoDescend
    $dirs = @($Root) + @($found | Where-Object {
            $_.PSIsContainer -and ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
            -not ((Split-Path -Parent $_.FullName).TrimEnd('\') -eq $Root.TrimEnd('\') -and $_.Name -in $NoDescend)
        } | ForEach-Object { $_.FullName } | Sort-Object -CaseSensitive)
    foreach ($d in $dirs) {
        $o = @(& cmd.exe /d /c dir /x /a $d 2>&1 | ForEach-Object { $_.ToString() })
        Add-Text $OutFile ("== $Id $(Get-RelPath $Root $d) (exit $LASTEXITCODE)")
        Add-Text $OutFile ($o -join "`r`n")
    }
}

# Parses "Index : n", "Name : x", "Description : y" from /Get-WimInfo output.
function Get-WimInfoImages([string] $Text) {
    $images = [System.Collections.Generic.List[object]]::new()
    $cur = $null
    foreach ($raw in ($Text -split "`r?`n")) {
        if ($raw -match '^\s*Index\s*:\s*(\d+)\s*$') {
            $cur = [pscustomobject]@{ Index = [int]$Matches[1]; Name = $null; Description = $null }
            $images.Add($cur)
        }
        elseif ($null -ne $cur -and $raw -match '^\s*Name\s*:\s*(.*?)\s*$' -and $null -eq $cur.Name) {
            $cur.Name = $Matches[1]
        }
        elseif ($null -ne $cur -and $raw -match '^\s*Description\s*:\s*(.*?)\s*$' -and $null -eq $cur.Description) {
            $cur.Description = $Matches[1]
        }
    }
    return , $images.ToArray()
}

# Records /Get-WimInfo for the whole file; when $Expected is given, also per
# index, and checks DISM reports exactly the names and descriptions we asked
# for.
function Save-WimInfo([string] $Id, [string] $File, $Expected) {
    $info = Join-Path $OutDir "$Id.wiminfo.txt"
    $tmp = Join-Path $WorkDir "$Id.wiminfo.tmp"
    $allow = ($null -eq $Expected)
    [void](Invoke-Dism "$Id-info" @('/Get-WimInfo', "/WimFile:$File") $tmp -AllowFailure:$allow)
    $text = [System.IO.File]::ReadAllText($tmp, $Utf8NoBom)
    Add-Text $info $text
    Remove-Item -LiteralPath $tmp
    if ($null -eq $Expected) { return }
    $got = Get-WimInfoImages $text
    if ($got.Count -ne $Expected.Count) {
        throw "$Id`: DISM reports $($got.Count) images, expected $($Expected.Count)"
    }
    for ($i = 0; $i -lt $Expected.Count; $i++) {
        $e = $Expected[$i]
        $g = $got[$i]
        if ($g.Index -ne $i + 1 -or $g.Name -cne $e.Name -or $g.Description -cne $e.Description) {
            throw "$Id`: DISM reports index $($g.Index) '$($g.Name)' '$($g.Description)', expected $($i + 1) '$($e.Name)' '$($e.Description)'"
        }
        [void](Invoke-Dism "$Id-info-$($i + 1)" @('/Get-WimInfo', "/WimFile:$File", "/Index:$($i + 1)") $info)
        $Editions.Add("$Id`t$($i + 1)`t$($g.Name)`t$($g.Description)")
    }
}

function Save-Dump([string] $File) {
    $name = [System.IO.Path]::GetFileName($File)
    $dump = Join-Path $OutDir ($name + '.dump.txt')
    $text = & (Join-Path $Here 'Dump-WimStructure.ps1') -Path $File | Out-String -Width 4096
    [System.IO.File]::WriteAllText($dump, $text, $Utf8NoBom)
}

function Add-ManifestRow([string] $Id, [string] $File, [string] $Compression, [int] $Images,
    [string] $Expected, [string] $Status) {
    if ($Status -like 'produced*') {
        $len = (Get-Item -LiteralPath $File).Length
        $sha = Get-Sha256 $File
        $Manifest.Add("$Id`t$([System.IO.Path]::GetFileName($File))`t$len`t$sha`t$Compression`t$Images`t$Expected`t$Status")
    }
    else {
        $Manifest.Add("$Id`t$([System.IO.Path]::GetFileName($File))`t-`t-`t$Compression`t$Images`t$Expected`t$Status")
    }
}

# Writes a source tree under $Parent (default -WorkDir). Every line the
# tree script prints (its summary, and for profile Metadata each native
# command and any NOTE) goes to commands.log.
function New-Tree([string] $Name, [int] $Seed, [string] $TreeProfile, [string] $Parent = $WorkDir,
    [string] $Outside = '', [long] $Bytes = $LargeBytes) {
    $p = Join-Path $Parent $Name
    $msg = @(& (Join-Path $Here 'New-SampleTree.ps1') -Path $p -Seed $Seed -TreeProfile $TreeProfile -LargeBytes $Bytes -OutsidePath $Outside)
    foreach ($m in $msg) {
        Add-Text $CommandsLog ('{0} tree {1}: {2}' -f [datetime]::UtcNow.ToString('o'), $Name, $m)
    }
    return $p
}

function Save-TreeListing([string] $Name, [string] $Root, [switch] $NoHash) {
    $f = Join-Path $OutDir 'trees.txt'
    Add-Text $f "== tree $Name =="
    Get-ChildItem -LiteralPath $Root -Recurse -Force | Sort-Object FullName | ForEach-Object {
        $rel = $_.FullName.Substring($Root.Length).TrimStart('\')
        if ($_.PSIsContainer) {
            Add-Text $f "dir   $rel"
        }
        elseif ($NoHash) {
            Add-Text $f ("file  {0}  length={1}" -f $rel, $_.Length)
        }
        else {
            $sha1 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA1).Hash.ToLowerInvariant()
            $sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            Add-Text $f ("file  {0}  length={1}  sha1={2}  sha256={3}" -f $rel, $_.Length, $sha1, $sha256)
            foreach ($s in @(Get-Item -LiteralPath $_.FullName -Stream * | Where-Object { $_.Stream -ne ':$DATA' })) {
                Add-Text $f ("      stream {0}  length={1}" -f $s.Stream, $s.Length)
            }
        }
    }
}

function Save-HostEvidence {
    $f = Join-Path $OutDir 'host.txt'
    $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    # Strict mode throws on a missing property; read each one defensively.
    $prop = { param($n) $p = $cv.PSObject.Properties[$n]; if ($null -eq $p) { '(absent)' } else { $p.Value } }
    $dismExe = Join-Path $env:SystemRoot 'System32\Dism.exe'
    Add-Text $f ('utc: ' + [datetime]::UtcNow.ToString('o'))
    Add-Text $f ('Environment.OSVersion: ' + [Environment]::OSVersion.VersionString)
    Add-Text $f ('ver: ' + ((cmd.exe /d /c ver | Out-String).Trim()))
    Add-Text $f ('CurrentBuild.UBR: {0}.{1}  DisplayVersion: {2}  EditionID: {3}' -f
        (& $prop 'CurrentBuild'), (& $prop 'UBR'), (& $prop 'DisplayVersion'), (& $prop 'EditionID'))
    Add-Text $f ('Dism.exe FileVersion: ' + (Get-Item -LiteralPath $dismExe).VersionInfo.FileVersion)
    Add-Text $f ('Dism.exe ProductVersion: ' + (Get-Item -LiteralPath $dismExe).VersionInfo.ProductVersion)
    Add-Text $f ('PowerShell: ' + $PSVersionTable.PSVersion.ToString())
    foreach ($v in @('ImageOS', 'ImageVersion', 'RUNNER_OS', 'RUNNER_ARCH', 'GITHUB_REPOSITORY',
            'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT', 'GITHUB_SHA', 'GITHUB_JOB')) {
        Add-Text $f ('{0}: {1}' -f $v, [Environment]::GetEnvironmentVariable($v))
    }
    # Last-access updates and short-name settings change what a capture
    # can see (M-05, M-11); recorded, never changed.
    foreach ($q in @(@('behavior', 'query', 'disablelastaccess'), @('8dot3name', 'query'))) {
        $o = @(& fsutil.exe @q 2>&1 | ForEach-Object { $_.ToString().Trim() } | Where-Object { $_ })
        Add-Text $f ('fsutil {0} (exit {1}): {2}' -f ($q -join ' '), $LASTEXITCODE, ($o -join ' / '))
    }
    $banner = Join-Path $WorkDir 'dism-help.tmp'
    [void](Invoke-Dism 'host' @('/?') $banner -AllowFailure)
    $head = @([System.IO.File]::ReadAllLines($banner, $Utf8NoBom) | Select-Object -First 8)
    Add-Text $f 'dism /English /? (first lines):'
    foreach ($l in $head) { Add-Text $f ('  ' + $l) }
    Remove-Item -LiteralPath $banner
}

# Runs one sample step; a failure is recorded, and the script continues so
# that the evidence gathered so far is still written.
function Invoke-Sample([string] $Id, [scriptblock] $Body) {
    try {
        & $Body
        return $true
    }
    catch {
        $Failures.Add("$Id`: $($_.Exception.Message)")
        Add-Text $CommandsLog ('{0} {1} FAILED {2}' -f [datetime]::UtcNow.ToString('o'), $Id, $_.Exception.Message)
        return $false
    }
}

function Get-Expect([string] $Prefix, [int] $Index, [string] $What) {
    [pscustomobject]@{
        Name        = ('USGP-{0}-{1:d2}' -f $Prefix, $Index)
        Description = ('usgp-sample-{0}-index-{1:d2}-{2}' -f $Prefix, $Index, $What)
    }
}

function Invoke-Capture([string] $Id, [string] $Wim, [string] $Dir, $Expect, [string] $Compress, [switch] $Integrity,
    [string[]] $Extra = @()) {
    $a = @('/Capture-Image', "/ImageFile:$Wim", "/CaptureDir:$Dir", "/Name:$($Expect.Name)",
        "/Description:$($Expect.Description)", "/Compress:$Compress")
    if ($Integrity) { $a += '/CheckIntegrity' }
    $a += $Extra
    [void](Invoke-Dism $Id $a (Join-Path $OutDir "$Id.dism.txt"))
}

Save-HostEvidence

if ($Set -eq 'Standard') {
    $trees = @{}
    for ($i = 1; $i -le 12; $i++) {
        $trees[$i] = New-Tree ('tree-{0:d2}' -f $i) (100 + $i) 'Standard'
    }
    $treeInc = New-Tree 'tree-inc' 201 'Incompressible'
    $treeLong = New-Tree 'tree-long' 401 'LongRun'
    $treeSvc = New-Tree 'tree-service' 501 'Service'
    Save-TreeListing 'tree-01' $trees[1]
    for ($i = 2; $i -le 12; $i++) { Save-TreeListing ('tree-{0:d2}' -f $i) $trees[$i] }
    Save-TreeListing 'tree-inc' $treeInc
    Save-TreeListing 'tree-long' $treeLong
    Save-TreeListing 'tree-service' $treeSvc
    $incBytes = [System.IO.File]::ReadAllBytes((Join-Path $treeInc 'random-65536.bin'))
    $tl = Join-Path $OutDir 'trees.txt'
    foreach ($o in @(0, 32768)) {
        Add-Text $tl ('tree-inc random-65536.bin bytes {0}..{1}: {2}' -f $o, ($o + 31),
            (($incBytes[$o..($o + 31)] | ForEach-Object { '{0:x2}' -f $_ }) -join ' '))
    }

    $single = @(
        @{ Id = 'S01'; Compress = 'none'; What = 'uncompressed'; Integrity = $false; Exp = 'accept'; Comp = 'none' },
        @{ Id = 'S02'; Compress = 'fast'; What = 'fast'; Integrity = $false; Exp = 'accept'; Comp = 'xpress' },
        @{ Id = 'S03'; Compress = 'max'; What = 'max'; Integrity = $false; Exp = 'refuse:lzx'; Comp = 'lzx' },
        @{ Id = 'S05'; Compress = 'fast'; What = 'fast-integrity'; Integrity = $true; Exp = 'accept'; Comp = 'xpress' }
    )
    $ok = @{}
    foreach ($s in $single) {
        $id = $s.Id
        $wim = Join-Path $OutDir "$id.wim"
        $exp = Get-Expect $id 1 $s.What
        $ok[$id] = Invoke-Sample $id {
            Invoke-Capture $id $wim $trees[1] $exp $s.Compress -Integrity:$s.Integrity
            Save-WimInfo $id $wim @($exp)
            Save-Dump $wim
        }
        Add-ManifestRow $id $wim $s.Comp 1 $s.Exp $(if ($ok[$id]) { 'produced' } else { 'not-produced' })
    }

    # S04: 12 indexes, distinct names and descriptions (REQ-IMG-042).
    $s04 = Join-Path $OutDir 'S04.wim'
    $s04Expect = @(for ($i = 1; $i -le 12; $i++) { Get-Expect 'S04' $i 'fast' })
    $ok['S04'] = Invoke-Sample 'S04' {
        Invoke-Capture 'S04' $s04 $trees[1] $s04Expect[0] 'fast'
        for ($i = 2; $i -le 12; $i++) {
            $e = $s04Expect[$i - 1]
            [void](Invoke-Dism ('S04-append-{0:d2}' -f $i) @('/Append-Image', "/ImageFile:$s04",
                    "/CaptureDir:$($trees[$i])", "/Name:$($e.Name)", "/Description:$($e.Description)") (Join-Path $OutDir 'S04.dism.txt'))
        }
        Save-WimInfo 'S04' $s04 $s04Expect
        Save-Dump $s04
    }
    Add-ManifestRow 'S04' $s04 'xpress' 12 'accept' $(if ($ok['S04']) { 'produced' } else { 'not-produced' })

    # S06: split S04 into 1 MB parts (refusal: spanned).
    $s06 = Join-Path $OutDir 'S06.swm'
    $ok['S06'] = $false
    if ($ok['S04']) {
        $ok['S06'] = Invoke-Sample 'S06' {
            [void](Invoke-Dism 'S06' @('/Split-Image', "/ImageFile:$s04", "/SWMFile:$s06", '/FileSize:1') (Join-Path $OutDir 'S06.dism.txt'))
            Save-WimInfo 'S06' $s06 $null
            $parts = @(Get-ChildItem -LiteralPath $OutDir -Filter 'S06*.swm' | Sort-Object Name)
            if ($parts.Count -lt 2) { throw "S06: expected at least 2 parts, found $($parts.Count)" }
            foreach ($p in $parts) { Save-Dump $p.FullName }
        }
    }
    else {
        $Failures.Add('S06: not produced because S04 failed')
    }
    if ($ok['S06']) {
        foreach ($p in @(Get-ChildItem -LiteralPath $OutDir -Filter 'S06*.swm' | Sort-Object Name)) {
            Add-ManifestRow 'S06' $p.FullName 'xpress' 12 'refuse:spanned' 'produced'
        }
    }
    else {
        Add-ManifestRow 'S06' $s06 'xpress' 12 'refuse:spanned' 'not-produced'
    }

    # S07: export S02 index 1 with recovery compression (.esd).
    $s07 = Join-Path $OutDir 'S07.esd'
    $ok['S07'] = $false
    if ($ok['S02']) {
        $ok['S07'] = Invoke-Sample 'S07' {
            [void](Invoke-Dism 'S07' @('/Export-Image', "/SourceImageFile:$(Join-Path $OutDir 'S02.wim')", '/SourceIndex:1',
                    "/DestinationImageFile:$s07", '/Compress:recovery') (Join-Path $OutDir 'S07.dism.txt'))
            Save-WimInfo 'S07' $s07 $null
            Save-Dump $s07
        }
    }
    else {
        $Failures.Add('S07: not produced because S02 failed')
    }
    Add-ManifestRow 'S07' $s07 'recovery' 1 'refuse:compression-unsupported' $(if ($ok['S07']) { 'produced' } else { 'not-produced' })

    # S09: one incompressible 64 KiB file (OPEN-WIM-5).
    $s09 = Join-Path $OutDir 'S09.wim'
    $s09Expect = Get-Expect 'S09' 1 'incompressible'
    $ok['S09'] = Invoke-Sample 'S09' {
        Invoke-Capture 'S09' $s09 $treeInc $s09Expect 'fast'
        Save-WimInfo 'S09' $s09 @($s09Expect)
        Save-Dump $s09
    }
    Add-ManifestRow 'S09' $s09 'xpress' 1 'accept' $(if ($ok['S09']) { 'produced' } else { 'not-produced' })

    # S10: long runs (BOOT-004): long XPRESS matches and multi-chunk tables.
    $s10 = Join-Path $OutDir 'S10.wim'
    $s10Expect = Get-Expect 'S10' 1 'long-runs'
    $ok['S10'] = Invoke-Sample 'S10' {
        Invoke-Capture 'S10' $s10 $treeLong $s10Expect 'fast'
        Save-WimInfo 'S10' $s10 @($s10Expect)
        Save-Dump $s10
    }
    Add-ManifestRow 'S10' $s10 'xpress' 1 'accept' $(if ($ok['S10']) { 'produced' } else { 'not-produced' })

    # S11 (BOOT-011): two images with identical content. Run 40599556702:
    # DISM names one metadata resource from two equal lookup entries
    # (OBS-018). A DISM refusal of the second step is recorded as status
    # "dism-refused" (and now fails verify).
    # $state is a hashtable so the sample blocks can set it.
    $state = @{}

    # S11A: tree-01 captured, then the same tree appended again.
    $s11a = Join-Path $OutDir 'S11A.wim'
    $s11aExpect = @((Get-Expect 'S11A' 1 'same-tree'), (Get-Expect 'S11A' 2 'same-tree'))
    $state['S11A'] = 'produced'
    $ok['S11A'] = Invoke-Sample 'S11A' {
        $log = Join-Path $OutDir 'S11A.dism.txt'
        Invoke-Capture 'S11A' $s11a $trees[1] $s11aExpect[0] 'fast'
        $code = Invoke-Dism 'S11A-append-02' @('/Append-Image', "/ImageFile:$s11a", "/CaptureDir:$($trees[1])",
            "/Name:$($s11aExpect[1].Name)", "/Description:$($s11aExpect[1].Description)") $log -AllowFailure
        if ($code -ne 0) {
            $state['S11A'] = 'dism-refused'
            Remove-Item -LiteralPath $s11a
            return
        }
        Save-WimInfo 'S11A' $s11a $s11aExpect
        Save-Dump $s11a
    }
    Add-ManifestRow 'S11A' $s11a 'xpress' 2 'accept' $(if ($ok['S11A']) { $state['S11A'] } else { 'not-produced' })

    # S11B: S02 index 1 exported twice into one new file (the second under
    # another name, so only the metadata question differs).
    $s11b = Join-Path $OutDir 'S11B.wim'
    $state['S11B'] = 'produced'
    $state['S11B-images'] = 0
    $ok['S11B'] = $false
    if ($ok['S02']) {
        $ok['S11B'] = Invoke-Sample 'S11B' {
            $src = Join-Path $OutDir 'S02.wim'
            $log = Join-Path $OutDir 'S11B.dism.txt'
            [void](Invoke-Dism 'S11B-export-01' @('/Export-Image', "/SourceImageFile:$src", '/SourceIndex:1',
                    "/DestinationImageFile:$s11b", '/Compress:fast') $log)
            $code = Invoke-Dism 'S11B-export-02' @('/Export-Image', "/SourceImageFile:$src", '/SourceIndex:1',
                "/DestinationImageFile:$s11b", '/DestinationName:USGP-S11B-02') $log -AllowFailure
            if ($code -ne 0) {
                $state['S11B'] = 'dism-refused'
                Remove-Item -LiteralPath $s11b
                return
            }
            # Names and descriptions of exported images are DISM's choice;
            # recorded, not checked. The image count is DISM's report.
            Save-WimInfo 'S11B' $s11b $null
            $text = [System.IO.File]::ReadAllText((Join-Path $OutDir 'S11B.wiminfo.txt'), $Utf8NoBom)
            $state['S11B-images'] = (Get-WimInfoImages $text).Count
            Save-Dump $s11b
        }
    }
    else {
        $Failures.Add('S11B: not produced because S02 failed')
    }
    Add-ManifestRow 'S11B' $s11b 'xpress' $state['S11B-images'] 'accept' $(if ($ok['S11B']) { $state['S11B'] } else { 'not-produced' })

    # S12 (BOOT-012): a multi-image file changed after capture. Run
    # 40599556702: a commit moves the committed image's metadata after
    # every other resource (OBS-021); superseded data stays in the file
    # (OBS-020, OBS-022). Copies of S04 (12 images).
    # S12A: mount index 1, add the tree-service files, commit.
    $s12a = Join-Path $OutDir 'S12A.wim'
    $ok['S12A'] = $false
    # S12B: delete index 1, then append tree-01 again as the new last index.
    $s12b = Join-Path $OutDir 'S12B.wim'
    $s12bExpect = @($s04Expect[1..11]) + @(Get-Expect 'S12B' 12 'appended')
    $ok['S12B'] = $false
    if ($ok['S04']) {
        $ok['S12A'] = Invoke-Sample 'S12A' {
            $log = Join-Path $OutDir 'S12A.dism.txt'
            Copy-Item -LiteralPath $s04 -Destination $s12a
            Add-Text $CommandsLog ('{0} S12A copy S04.wim to S12A.wim' -f [datetime]::UtcNow.ToString('o'))
            $mount = Join-Path $WorkDir 'mount-S12A'
            [void][System.IO.Directory]::CreateDirectory($mount)
            [void](Invoke-Dism 'S12A-mount' @('/Mount-Image', "/ImageFile:$s12a", '/Index:1', "/MountDir:$mount") $log)
            $committed = $false
            try {
                $dest = Join-Path $mount 'usgp-serviced'
                [void][System.IO.Directory]::CreateDirectory($dest)
                Copy-Item -Path (Join-Path $treeSvc '*') -Destination $dest
                Add-Text $CommandsLog ('{0} S12A copy tree-service to mount\usgp-serviced' -f [datetime]::UtcNow.ToString('o'))
                [void](Invoke-Dism 'S12A-commit' @('/Unmount-Image', "/MountDir:$mount", '/Commit') $log)
                $committed = $true
            }
            finally {
                if (-not $committed) {
                    [void](Invoke-Dism 'S12A-discard' @('/Unmount-Image', "/MountDir:$mount", '/Discard') $log -AllowFailure)
                }
            }
            Save-WimInfo 'S12A' $s12a $s04Expect
            Save-Dump $s12a
        }
        $ok['S12B'] = Invoke-Sample 'S12B' {
            $log = Join-Path $OutDir 'S12B.dism.txt'
            Copy-Item -LiteralPath $s04 -Destination $s12b
            Add-Text $CommandsLog ('{0} S12B copy S04.wim to S12B.wim' -f [datetime]::UtcNow.ToString('o'))
            [void](Invoke-Dism 'S12B-delete-01' @('/Delete-Image', "/ImageFile:$s12b", '/Index:1') $log)
            $e = $s12bExpect[11]
            [void](Invoke-Dism 'S12B-append-12' @('/Append-Image', "/ImageFile:$s12b", "/CaptureDir:$($trees[1])",
                    "/Name:$($e.Name)", "/Description:$($e.Description)") $log)
            Save-WimInfo 'S12B' $s12b $s12bExpect
            Save-Dump $s12b
        }
    }
    else {
        $Failures.Add('S12A, S12B: not produced because S04 failed')
    }
    Add-ManifestRow 'S12A' $s12a 'xpress' 12 'accept' $(if ($ok['S12A']) { 'produced' } else { 'not-produced' })
    Add-ManifestRow 'S12B' $s12b 'xpress' 12 'accept' $(if ($ok['S12B']) { 'produced' } else { 'not-produced' })

    # Upload cap and checksums over every sample file actually written.
    $samples = @(Get-ChildItem -LiteralPath $OutDir -File | Where-Object { $_.Extension -in '.wim', '.swm', '.esd' } | Sort-Object Name)
    foreach ($f in $samples) {
        if ($f.Length -gt $MaxUploadBytes) { $Failures.Add("$($f.Name): $($f.Length) bytes exceeds the $MaxUploadBytes-byte cap") }
    }
    $sums = [System.Collections.Generic.List[string]]::new()
    foreach ($f in $samples) { $sums.Add(('{0}  {1}' -f (Get-Sha256 $f.FullName), $f.Name)) }
    Write-LfLines (Join-Path $OutDir 'SHA256SUMS') $sums.ToArray()
}
elseif ($Set -eq 'Large') {
    # S08: one large pseudorandom file; the WIM stays in WorkDir and is
    # deleted after it is dumped (never uploaded). Needs room for the source
    # file and a WIM of about the same size (pseudorandom data does not
    # shrink); too little space is NOT RUN, which fails the script.
    $s08 = Join-Path $WorkDir 'S08.wim'
    $drive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($WorkDir))
    $need = 2 * $LargeBytes + 1GB
    Add-Text (Join-Path $OutDir 'host.txt') ('work drive {0}: free {1} bytes, S08 needs {2}' -f $drive.Name, $drive.AvailableFreeSpace, $need)
    if ($drive.AvailableFreeSpace -lt $need) {
        $Failures.Add("S08: NOT RUN: $($drive.AvailableFreeSpace) bytes free on $($drive.Name), $need needed")
        Add-ManifestRow 'S08' $s08 'xpress' 1 'accept' 'not-produced'
    }
    else {
        $tree = New-Tree 'tree-large' 301 'Large'
        Save-TreeListing 'tree-large' $tree
        $s08Expect = Get-Expect 'S08' 1 'large'
        $ok08 = Invoke-Sample 'S08' {
            Invoke-Capture 'S08' $s08 $tree $s08Expect 'fast'
            Save-WimInfo 'S08' $s08 @($s08Expect)
            Save-Dump $s08
        }
        # Recorded before deletion so the manifest holds its length and hash.
        Add-ManifestRow 'S08' $s08 'xpress' 1 'accept' $(if ($ok08) { 'produced (not uploaded)' } else { 'not-produced' })
        foreach ($p in @($s08, $tree)) {
            if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force }
        }
    }

    # S08B (OPEN-WIM-10, M-22): a compressible file over 4 GiB, so DISM
    # keeps the resource compressed and writes a chunk table for an
    # original size over 2^32. Runs after S08's files are deleted. The
    # dump's chunk section reads the table with 4- and 8-byte entries.
    $s08b = Join-Path $WorkDir 'S08B.wim'
    $drive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($WorkDir))
    $need = 2 * $LargeBytes + 1GB
    Add-Text (Join-Path $OutDir 'host.txt') ('work drive {0}: free {1} bytes, S08B needs {2}' -f $drive.Name, $drive.AvailableFreeSpace, $need)
    if ($drive.AvailableFreeSpace -lt $need) {
        $Failures.Add("S08B: NOT RUN: $($drive.AvailableFreeSpace) bytes free on $($drive.Name), $need needed")
        Add-ManifestRow 'S08B' $s08b 'xpress' 1 'accept' 'not-produced'
    }
    else {
        $treeB = New-Tree 'tree-large-text' 302 'LargeText'
        Save-TreeListing 'tree-large-text' $treeB
        $s08bExpect = Get-Expect 'S08B' 1 'large-text'
        $ok08b = Invoke-Sample 'S08B' {
            Invoke-Capture 'S08B' $s08b $treeB $s08bExpect 'fast'
            Save-WimInfo 'S08B' $s08b @($s08bExpect)
            Save-Dump $s08b
        }
        Add-ManifestRow 'S08B' $s08b 'xpress' 1 'accept' $(if ($ok08b) { 'produced (not uploaded)' } else { 'not-produced' })
        foreach ($p in @($s08b, $treeB)) {
            if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Recurse -Force }
        }
    }
}
elseif ($Set -eq 'Metadata') {
    # S13 to S15 (OPEN-WIM-7, plan M3 section 1.4): tree-meta on a fresh
    # NTFS VHD volume with short names enabled. The VHD stays in -WorkDir
    # and is detached in every case.
    $state = @{}
    $ok = @{}
    $vhdMeta = Join-Path $WorkDir 'tree-meta.vhdx'
    $s13Expect = Get-Expect 'S13' 1 'metadata-uncompressed'
    $s14Expect = Get-Expect 'S14' 1 'metadata-fast'
    $s15Expect = Get-Expect 'S15' 1 'volume-root'
    $metaRows = @(
        @{ Id = 'S13'; Compress = 'none'; Comp = 'none'; Exp = $s13Expect; Root = $false },
        @{ Id = 'S14'; Compress = 'fast'; Comp = 'xpress'; Exp = $s14Expect; Root = $false },
        @{ Id = 'S15'; Compress = 'none'; Comp = 'none'; Exp = $s15Expect; Root = $true }
    )
    foreach ($r in $metaRows) { $ok[$r.Id] = $false }
    try {
        $treeOk = Invoke-Sample 'tree-meta' {
            $state['vol'] = New-SampleVhd 'VHD-META' $vhdMeta 'USGPMETA'
            $state['tree'] = New-Tree 'tree-meta' 601 'Metadata' "$($state['vol'])\"
            # Before any capture or hash reads a file (M-11: last access).
            Save-TreeManifest 'tree-meta-before' $state['tree'] (Join-Path $OutDir 'tree-meta-before.manifest.tsv') -NoContent
        }
        if ($treeOk) {
            foreach ($r in $metaRows) {
                $id = $r.Id
                $wim = Join-Path $OutDir "$id.wim"
                $dir = if ($r.Root) { "$($state['vol'])\" } else { $state['tree'] }
                $ok[$id] = Invoke-Sample $id {
                    Invoke-Capture $id $wim $dir $r.Exp $r.Compress
                    Save-WimInfo $id $wim @($r.Exp)
                    Save-Dump $wim
                }
            }
            [void](Invoke-Sample 'tree-meta manifests' {
                    Save-TreeManifest 'tree-meta' $state['tree'] (Join-Path $OutDir 'tree-meta.manifest.tsv')
                    Save-ShortNames 'tree-meta' $state['tree'] (Join-Path $OutDir 'tree-meta.dirx.txt')
                    # S15's source (M-19): the volume root and what Windows
                    # put there; no content read.
                    Save-TreeManifest 'volume-root' "$($state['vol'])\" (Join-Path $OutDir 'volume-root.manifest.tsv') $VolumeNoDescend -NoContent
                })
        }
        else {
            $Failures.Add('S13, S14, S15: not produced because tree-meta failed')
        }
    }
    finally {
        # Also after a partial New-SampleVhd (file made, letter not yet
        # returned).
        if (Test-Path -LiteralPath $vhdMeta) { Dismount-SampleVhd 'VHD-META' $vhdMeta }
    }
    foreach ($r in $metaRows) {
        Add-ManifestRow $r.Id (Join-Path $OutDir "$($r.Id).wim") $r.Comp 1 'accept' $(if ($ok[$r.Id]) { 'produced' } else { 'not-produced' })
    }

    # S17 (OPEN-WIM-5 chunk level, M-21): mixed compressibility.
    $treeMixed = New-Tree 'tree-mixed' 701 'Mixed'
    Save-TreeListing 'tree-mixed' $treeMixed
    $s17 = Join-Path $OutDir 'S17.wim'
    $s17Expect = Get-Expect 'S17' 1 'mixed'
    $ok['S17'] = Invoke-Sample 'S17' {
        Invoke-Capture 'S17' $s17 $treeMixed $s17Expect 'fast'
        Save-WimInfo 'S17' $s17 @($s17Expect)
        Save-Dump $s17
    }
    Add-ManifestRow 'S17' $s17 'xpress' 1 'accept' $(if ($ok['S17']) { 'produced' } else { 'not-produced' })

    # S13B, S13C (R3 follow-up requests): tree-meta2 (profile Metadata2,
    # seed 602) on its own VHD volume, lettered T: so that S16B can apply
    # it to another letter. S13B is captured as DISM does by default;
    # S13C with /NoRpFix. Both hold in-tree and out-of-tree absolute
    # targets. The out-of-tree targets live in T:\outside-tree.
    $vhdMeta2 = Join-Path $WorkDir 'tree-meta2.vhdx'
    $s13bExpect = Get-Expect 'S13B' 1 'reparse-rpfix'
    $s13cExpect = Get-Expect 'S13C' 1 'reparse-norpfix'
    $meta2Rows = @(
        @{ Id = 'S13B'; Exp = $s13bExpect; Extra = @() },
        @{ Id = 'S13C'; Exp = $s13cExpect; Extra = @('/NoRpFix') }
    )
    foreach ($r in $meta2Rows) { $ok[$r.Id] = $false }
    $state2 = @{}
    try {
        $tree2Ok = Invoke-Sample 'tree-meta2' {
            $state2['vol'] = New-SampleVhd 'VHD-META2' $vhdMeta2 'USGPMETA2' 'T'
            $state2['outside'] = Join-Path "$($state2['vol'])\" 'outside-tree'
            $state2['tree'] = New-Tree 'tree-meta2' 602 'Metadata2' "$($state2['vol'])\" $state2['outside']
            Save-TreeManifest 'tree-meta2-before' $state2['tree'] (Join-Path $OutDir 'tree-meta2-before.manifest.tsv') -NoContent
        }
        if ($tree2Ok) {
            foreach ($r in $meta2Rows) {
                $id = $r.Id
                $wim = Join-Path $OutDir "$id.wim"
                $ok[$id] = Invoke-Sample $id {
                    Invoke-Capture $id $wim $state2['tree'] $r.Exp 'none' -Extra $r.Extra
                    Save-WimInfo $id $wim @($r.Exp)
                    Save-Dump $wim
                }
            }
            [void](Invoke-Sample 'tree-meta2 manifests' {
                    Save-TreeManifest 'tree-meta2' $state2['tree'] (Join-Path $OutDir 'tree-meta2.manifest.tsv')
                    Save-ShortNames 'tree-meta2' $state2['tree'] (Join-Path $OutDir 'tree-meta2.dirx.txt')
                    Save-TreeManifest 'outside-tree' $state2['outside'] (Join-Path $OutDir 'outside-tree.manifest.tsv')
                })
        }
        else {
            $Failures.Add('S13B, S13C: not produced because tree-meta2 failed')
        }
    }
    finally {
        if (Test-Path -LiteralPath $vhdMeta2) { Dismount-SampleVhd 'VHD-META2' $vhdMeta2 }
    }
    foreach ($r in $meta2Rows) {
        Add-ManifestRow $r.Id (Join-Path $OutDir "$($r.Id).wim") 'none' 1 'accept' $(if ($ok[$r.Id]) { 'produced' } else { 'not-produced' })
    }

    # S17B (OPEN-WIM-5): short final chunks that do not shrink.
    $treeTail = New-Tree 'tree-mixed-tail' 702 'MixedTail'
    Save-TreeListing 'tree-mixed-tail' $treeTail
    $s17b = Join-Path $OutDir 'S17B.wim'
    $s17bExpect = Get-Expect 'S17B' 1 'mixed-tail'
    $ok['S17B'] = Invoke-Sample 'S17B' {
        Invoke-Capture 'S17B' $s17b $treeTail $s17bExpect 'fast'
        Save-WimInfo 'S17B' $s17b @($s17bExpect)
        Save-Dump $s17b
    }
    Add-ManifestRow 'S17B' $s17b 'xpress' 1 'accept' $(if ($ok['S17B']) { 'produced' } else { 'not-produced' })

    # Upload cap and checksums over every sample file actually written.
    $samples = @(Get-ChildItem -LiteralPath $OutDir -File | Where-Object { $_.Extension -eq '.wim' } | Sort-Object Name)
    foreach ($f in $samples) {
        if ($f.Length -gt $MaxUploadBytes) { $Failures.Add("$($f.Name): $($f.Length) bytes exceeds the $MaxUploadBytes-byte cap") }
    }
    $sums = [System.Collections.Generic.List[string]]::new()
    foreach ($f in $samples) { $sums.Add(('{0}  {1}' -f (Get-Sha256 $f.FullName), $f.Name)) }
    Write-LfLines (Join-Path $OutDir 'SHA256SUMS') $sums.ToArray()
}
else {
    # Reference (M-20 and the R3 follow-ups): DISM's own apply of our
    # samples to fresh NTFS VHD volumes, recorded as text only. Each source
    # comes from -SampleDir (the generate-metadata artifact of the same
    # run) and must match the SHA-256 recorded there in both manifest.tsv
    # and SHA256SUMS.
    #   S16  S13 index 1 to the root of a volume (free letter, R: in R3)
    #   S16B S13B index 1 to the root of a volume lettered S: (captured on T:)
    #   S16C S13B index 1 to U:\deep\apply-here (a subdirectory)
    #   S16D S13C (/NoRpFix) index 1 to the root of a volume lettered V:
    $src = (Resolve-Path -LiteralPath $SampleDir).ProviderPath
    $sourceRows = @([System.IO.File]::ReadAllLines((Join-Path $src 'manifest.tsv'), $Utf8NoBom) |
            Select-Object -Skip 1 | ForEach-Object { , ($_ -split "`t") })
    $sumLines = @([System.IO.File]::ReadAllLines((Join-Path $src 'SHA256SUMS'), $Utf8NoBom))
    $applies = @(
        @{ Id = 'S16'; Source = 'S13'; Letter = ''; Sub = '' },
        @{ Id = 'S16B'; Source = 'S13B'; Letter = 'S'; Sub = '' },
        @{ Id = 'S16C'; Source = 'S13B'; Letter = 'U'; Sub = 'deep\apply-here' },
        @{ Id = 'S16D'; Source = 'S13C'; Letter = 'V'; Sub = '' }
    )
    $sums = [System.Collections.Generic.List[string]]::new()
    foreach ($ap in $applies) {
        $id = $ap.Id
        $out = Join-Path $OutDir "$id.manifest.tsv"
        $state = @{}
        $okAp = Invoke-Sample $id {
            $rows = @($sourceRows | Where-Object { $_[0] -eq $ap.Source })
            if ($rows.Count -ne 1) { throw "$id`: expected one $($ap.Source) row in the sample manifest, found $($rows.Count)" }
            $row = $rows[0]
            if ($row.Count -ne 8 -or $row[7] -ne 'produced') { throw "$id`: $($ap.Source) row is not 'produced': $($row -join ' | ')" }
            if ($row[1] -cne "$($ap.Source).wim") { throw "$id`: unexpected file name '$($row[1])'" }
            $wim = Join-Path $src $row[1]
            $sha = Get-Sha256 $wim
            if ($sha -ne $row[3]) { throw "$id`: $($row[1]) SHA-256 $sha differs from the manifest's $($row[3])" }
            if (@($sumLines | Where-Object { $_ -ceq ('{0}  {1}' -f $sha, $row[1]) }).Count -ne 1) {
                throw "$id`: $($row[1]) is not listed with this SHA-256 in SHA256SUMS"
            }
            Add-Text $CommandsLog ('{0} {1} source {2} sha256 {3}' -f [datetime]::UtcNow.ToString('o'), $id, $row[1], $sha)
            Save-WimInfo "$id-source" $wim $null
            $vhd = Join-Path $WorkDir ("apply-{0}.vhdx" -f $id.ToLowerInvariant())
            try {
                $state['vol'] = New-SampleVhd $id $vhd ('USGP' + $id) $ap.Letter
                $root = "$($state['vol'])\"
                $noDescend = $VolumeNoDescend
                if ($ap.Sub.Length -gt 0) {
                    $root = Join-Path $root $ap.Sub
                    [void][System.IO.Directory]::CreateDirectory($root)
                    Add-Text $CommandsLog ('{0} {1} created apply directory {2}' -f [datetime]::UtcNow.ToString('o'), $id, $root)
                    $noDescend = @()
                }
                [void](Invoke-Dism "$id-apply" @('/Apply-Image', "/ImageFile:$wim", '/Index:1', "/ApplyDir:$root") (Join-Path $OutDir "$id.dism.txt"))
                Save-TreeManifest $id $root $out $noDescend
                Save-ShortNames $id $root (Join-Path $OutDir "$id.dirx.txt") $noDescend
            }
            finally {
                if (Test-Path -LiteralPath $vhd) { Dismount-SampleVhd $id $vhd }
            }
        }
        Add-ManifestRow $id $out 'none' 1 'reference' $(if ($okAp) { 'produced' } else { 'not-produced' })
        if ($okAp) { $sums.Add(('{0}  {1}' -f (Get-Sha256 $out), "$id.manifest.tsv")) }
    }
    Write-LfLines (Join-Path $OutDir 'SHA256SUMS') $sums.ToArray()
}

Write-LfLines (Join-Path $OutDir 'manifest.tsv') $Manifest.ToArray()
Write-LfLines (Join-Path $OutDir 'editions.tsv') $Editions.ToArray()

# observations.txt: every text record, in a fixed order.
$obs = Join-Path $OutDir 'observations.txt'
$order = @('host.txt', 'commands.log', 'manifest.tsv', 'editions.tsv', 'SHA256SUMS', 'trees.txt')
$rest = @(Get-ChildItem -LiteralPath $OutDir -File -Filter '*.txt' |
        Where-Object { $_.Name -notin $order -and $_.Name -ne 'observations.txt' } | Sort-Object Name | ForEach-Object { $_.Name })
foreach ($n in @($order + $rest)) {
    $p = Join-Path $OutDir $n
    if (-not (Test-Path -LiteralPath $p)) { continue }
    Add-Text $obs "######## $n ########"
    Add-Text $obs ([System.IO.File]::ReadAllText($p, $Utf8NoBom))
}

# The Reference set uploads text only: never a sample, a disk image or
# anything DISM applied.
if ($Set -eq 'Reference') {
    $notText = @(Get-ChildItem -LiteralPath $OutDir -Recurse -Force |
            Where-Object { $_.PSIsContainer -or ($_.Extension -notin '.txt', '.tsv', '.log' -and $_.Name -ne 'SHA256SUMS') })
    foreach ($n in $notText) { $Failures.Add("reference upload holds a non-text item: $($n.Name)") }
}

if ($Failures.Count -gt 0) {
    Write-Output 'Build-Samples: FAILED'
    foreach ($f in $Failures) { Write-Output "  $f" }
    exit 1
}
Write-Output "Build-Samples: set $Set complete; outputs in $OutDir"
exit 0
