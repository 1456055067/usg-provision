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

    S11 (BOOT-011) and S12 (BOOT-012) ask what DISM writes, so their
    manifest rows carry expected "observe": the consumer records the
    parser's result and does not judge it. If DISM itself refuses the
    second S11 step, that refusal is the observation: the row's status is
    "dism-refused", the partial file is deleted, and the run does not fail.

    Set Large (job "generate-large"; observations only, the WIM is deleted):

      S08  /Capture-Image /Compress:fast                        tree-large

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
      the sample files    (Standard set only)

    Fail closed: any failed command, any DISM report that differs from the
    names and descriptions we asked for, or any sample over the size cap
    makes the script exit 1 after writing what it has. A sample whose input
    failed is recorded as "not-produced", never silently dropped.

.PARAMETER OutDir
    Artifact directory (created; must be empty if it exists).

.PARAMETER WorkDir
    Scratch directory for the source trees and the Large WIM.

.PARAMETER Set
    Standard or Large.

.PARAMETER LargeBytes
    Size of the S08 source file (default 4.5 GiB).

.NOTES
    COMPLIANCE MAPPING:
    - NIST 800-53: SA-11 (Developer Testing and Evaluation), SR-4
      (Provenance: every sample's command, tool version and host recorded),
      SI-7 (test inputs for image integrity checks)
    - SPEC: specs/standards/wim.md section 13 (OPEN-WIM-1 to 6, 10, 11;
      samples S11 and S12);
      specs/standards/wim-compression.md section 7 (OPEN-WIMC-1);
      specs/os-images.md REQ-IMG-042 (12 indexes)
    - Decision 0006 items 1 to 4; decision 0014
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $OutDir,

    [Parameter(Mandatory = $true)]
    [string] $WorkDir,

    [ValidateSet('Standard', 'Large')]
    [string] $Set = 'Standard',

    [long] $LargeBytes = 4831838208
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$MaxUploadBytes = 64MB
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$Here = $PSScriptRoot

foreach ($d in @($OutDir, $WorkDir)) {
    if ((Test-Path -LiteralPath $d) -and @(Get-ChildItem -LiteralPath $d -Force).Count -ne 0) {
        throw "refusing to use non-empty directory: $d"
    }
    [void][System.IO.Directory]::CreateDirectory($d)
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

function New-Tree([string] $Name, [int] $Seed, [string] $TreeProfile) {
    $p = Join-Path $WorkDir $Name
    $msg = & (Join-Path $Here 'New-SampleTree.ps1') -Path $p -Seed $Seed -TreeProfile $TreeProfile -LargeBytes $LargeBytes
    Add-Text $CommandsLog ('{0} tree {1}: {2}' -f [datetime]::UtcNow.ToString('o'), $Name, ($msg -join ' '))
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

function Invoke-Capture([string] $Id, [string] $Wim, [string] $Dir, $Expect, [string] $Compress, [switch] $Integrity) {
    $a = @('/Capture-Image', "/ImageFile:$Wim", "/CaptureDir:$Dir", "/Name:$($Expect.Name)",
        "/Description:$($Expect.Description)", "/Compress:$Compress")
    if ($Integrity) { $a += '/CheckIntegrity' }
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

    # S11 (BOOT-011): two images with identical content. Does DISM write
    # two metadata resources with one hash, share one, or refuse? A DISM
    # refusal of the second step is recorded as status "dism-refused".
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
    Add-ManifestRow 'S11A' $s11a 'xpress' 2 'observe' $(if ($ok['S11A']) { $state['S11A'] } else { 'not-produced' })

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
    Add-ManifestRow 'S11B' $s11b 'xpress' $state['S11B-images'] 'observe' $(if ($ok['S11B']) { $state['S11B'] } else { 'not-produced' })

    # S12 (BOOT-012): a multi-image file changed after capture. Does a
    # commit or an append put metadata out of lookup order, or leave
    # unused space? Copies of S04 (12 images).
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
    Add-ManifestRow 'S12A' $s12a 'xpress' 12 'observe' $(if ($ok['S12A']) { 'produced' } else { 'not-produced' })
    Add-ManifestRow 'S12B' $s12b 'xpress' 12 'observe' $(if ($ok['S12B']) { 'produced' } else { 'not-produced' })

    # Upload cap and checksums over every sample file actually written.
    $samples = @(Get-ChildItem -LiteralPath $OutDir -File | Where-Object { $_.Extension -in '.wim', '.swm', '.esd' } | Sort-Object Name)
    foreach ($f in $samples) {
        if ($f.Length -gt $MaxUploadBytes) { $Failures.Add("$($f.Name): $($f.Length) bytes exceeds the $MaxUploadBytes-byte cap") }
    }
    $sums = [System.Collections.Generic.List[string]]::new()
    foreach ($f in $samples) { $sums.Add(('{0}  {1}' -f (Get-Sha256 $f.FullName), $f.Name)) }
    Write-LfLines (Join-Path $OutDir 'SHA256SUMS') $sums.ToArray()
}
else {
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

if ($Failures.Count -gt 0) {
    Write-Output 'Build-Samples: FAILED'
    foreach ($f in $Failures) { Write-Output "  $f" }
    exit 1
}
Write-Output "Build-Samples: set $Set complete; outputs in $OutDir"
exit 0
