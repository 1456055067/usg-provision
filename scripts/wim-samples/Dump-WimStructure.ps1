#Requires -Version 7.2
<#
.SYNOPSIS
    Prints the raw structure regions of a WIM file as hex, with a labelled
    reading of each field, for black-box observation (plan WU-W, decision
    0006).

.DESCRIPTION
    Pure PowerShell and .NET base classes; no WIM library and no product
    code. The script only reads the file. It is an observation aid: every
    decoded value is printed next to the raw bytes it came from, so the
    recorder (docs/formats/wim-observed.md) cites bytes, not this script's
    reading.

    Field offsets follow specs/standards/wim.md, where most of them are
    [derived] from field order; values are read little-endian, which is
    itself OPEN-WIM-1 and is confirmed or refuted by the raw bytes printed
    beside them.

    Sections printed:
      file         path, length, SHA-256
      header       hex of the first cbSize bytes (at most 4096), then fields
      lookup       hex of the lookup table region (at most 65536 bytes) and
                   50-byte entries (at most 4096) when the region is not
                   flagged compressed
      metadata     first 128 bytes of each metadata-flagged resource (at most
                   16 resources)
      xml          hex of the first 256 bytes, then the UTF-16LE text when it
                   starts with FF FE (at most 4 MiB)
      integrity    hex of the table head and first entries, the stored
                   fields, and SHA-1 of the first chunks of the range
                   [cbSize, end of lookup table) compared with the entries
      chunks       for the first compressed resource and for the compressed
                   resource with the largest original size: the chunk table
                   read with 4-byte and with 8-byte entries, a consistency
                   check for each width, each chunk's size and first bytes
                   (first chunk: 288 bytes, which covers a 256-byte table)

    Every offset and length taken from the file is checked against the file
    length and the caps above before it is read. A section that fails prints
    "SECTION ERROR: <reason>" and the dump continues with the next section.

.PARAMETER Path
    WIM, SWM or ESD file to dump.

.PARAMETER NoFileHash
    Skip the SHA-256 of the whole file (for very large files).

.NOTES
    COMPLIANCE MAPPING:
    - NIST 800-53: SA-11 (Developer Testing and Evaluation), SI-10 (input
      lengths checked before use, also in test tooling)
    - SPEC: specs/standards/wim.md sections 2 to 9, section 13;
      specs/standards/wim-compression.md section 7 (OPEN-WIMC-1)
    - Decision 0006 items 1 to 3
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $Path,

    [switch] $NoFileHash
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

if (-not [BitConverter]::IsLittleEndian) {
    throw 'this dump reads fields with BitConverter and needs a little-endian host'
}

$ChunkSize = 32768L
$Cap = @{
    HeaderBytes   = 4096
    LookupBytes   = 65536
    LookupEntries = 4096
    MetadataRes   = 16
    MetadataBytes = 128
    XmlBytes      = 4194304
    IntegrityHead = 12 + 20 * 8
    IntegrityHash = 64
    ChunkTable    = 16777216
    ChunksShown   = 64
}

$HeaderFlagNames = [ordered]@{
    0x00000001 = 'FLAG_HEADER_RESERVED'
    0x00000002 = 'FLAG_HEADER_COMPRESSION'
    0x00000004 = 'FLAG_HEADER_READONLY'
    0x00000008 = 'FLAG_HEADER_SPANNED'
    0x00000010 = 'FLAG_HEADER_RESOURCE_ONLY'
    0x00000020 = 'FLAG_HEADER_METADATA_ONLY'
    0x00000040 = 'FLAG_HEADER_WRITE_IN_PROGRESS'
    0x00000080 = 'FLAG_HEADER_RP_FIX'
    0x00010000 = 'FLAG_HEADER_COMPRESS_RESERVED'
    0x00020000 = 'FLAG_HEADER_COMPRESS_XPRESS'
    0x00040000 = 'FLAG_HEADER_COMPRESS_LZX'
}
$ResFlagNames = [ordered]@{
    0x01 = 'FREE'
    0x02 = 'METADATA'
    0x04 = 'COMPRESSED'
    0x08 = 'SPANNED'
}

$script:Fs = $null
$script:FileLength = 0L

function Out-Line([string] $Text = '') { Write-Output $Text }

function Out-Section([string] $Name) {
    Out-Line ''
    Out-Line ('== ' + $Name + ' ==')
}

# Reads exactly $Count bytes at $Offset, or throws if any part lies outside
# the file.
function Read-At([long] $Offset, [long] $Count) {
    if ($Offset -lt 0 -or $Count -lt 0 -or $Count -gt [int]::MaxValue) {
        throw "read out of range: offset $Offset count $Count"
    }
    if ($Offset -gt $script:FileLength -or $Count -gt ($script:FileLength - $Offset)) {
        throw "read past end of file: offset $Offset count $Count file length $($script:FileLength)"
    }
    $buf = [byte[]]::new([int]$Count)
    [void]$script:Fs.Seek($Offset, [System.IO.SeekOrigin]::Begin)
    $got = 0
    while ($got -lt $Count) {
        $n = $script:Fs.Read($buf, $got, [int]$Count - $got)
        if ($n -le 0) { throw "short read at offset $($Offset + $got)" }
        $got += $n
    }
    return , $buf
}

function Get-U16([byte[]] $B, [int] $O) { [BitConverter]::ToUInt16($B, $O) }
function Get-U32([byte[]] $B, [int] $O) { [BitConverter]::ToUInt32($B, $O) }
function Get-U64([byte[]] $B, [int] $O) { [BitConverter]::ToUInt64($B, $O) }

function ConvertTo-HexText([byte[]] $B, [int] $Start, [int] $Count) {
    if ($Count -le 0) { return '' }
    $parts = for ($i = $Start; $i -lt $Start + $Count; $i++) { '{0:x2}' -f $B[$i] }
    return ($parts -join ' ')
}

# Classic hex dump; $Base is the file offset of $B[0].
function Out-HexDump([byte[]] $B, [long] $Base, [int] $Count = -1) {
    if ($Count -lt 0 -or $Count -gt $B.Length) { $Count = $B.Length }
    for ($row = 0; $row -lt $Count; $row += 16) {
        $n = [Math]::Min(16, $Count - $row)
        $ascii = [System.Text.StringBuilder]::new()
        for ($i = 0; $i -lt $n; $i++) {
            $c = $B[$row + $i]
            if ($c -ge 0x20 -and $c -le 0x7e) { [void]$ascii.Append([char]$c) } else { [void]$ascii.Append('.') }
        }
        Out-Line ('{0:x10}  {1,-47}  |{2}|' -f ($Base + $row), (ConvertTo-HexText $B $row $n), $ascii.ToString())
    }
}

function Format-Flags([uint64] $Value, $Names) {
    $set = @()
    $known = [uint64]0
    # GetEnumerator, not $Names[$k]: an ordered dictionary indexed with an
    # int returns the entry at that position, not the entry with that key.
    foreach ($entry in $Names.GetEnumerator()) {
        $bit = [uint64]$entry.Key
        $known = $known -bor $bit
        if (($Value -band $bit) -ne 0) { $set += $entry.Value }
    }
    $unknown = $Value -band (-bnot $known)
    if ($unknown -ne 0) { $set += ('UNDEFINED(0x{0:x})' -f $unknown) }
    if ($set.Count -eq 0) { return 'none' }
    return ($set -join ' | ')
}

# Resource header (wim.md section 3): 7-byte stored size, 1 flag byte,
# 8-byte offset, 8-byte original size. Returns $null fields when a 64-bit
# value does not fit a signed 64-bit offset.
function Read-ResHdr([byte[]] $B, [int] $O) {
    $first = Get-U64 $B $O
    $off = Get-U64 $B ($O + 8)
    $orig = Get-U64 $B ($O + 16)
    $max = [uint64][long]::MaxValue
    return [pscustomobject]@{
        Raw      = (ConvertTo-HexText $B $O 24)
        Stored   = [long]($first -band [uint64]72057594037927935)
        Flags    = [int]$B[$O + 7]
        Offset   = $(if ($off -le $max) { [long]$off } else { $null })
        Original = $(if ($orig -le $max) { [long]$orig } else { $null })
        OffsetU  = $off
        OrigU    = $orig
    }
}

function Format-ResHdr($R) {
    return ('stored={0} flags=0x{1:x2} [{2}] offset={3} original={4}  raw: {5}' -f
        $R.Stored, $R.Flags, (Format-Flags ([uint64]$R.Flags) $ResFlagNames),
        $R.OffsetU, $R.OrigU, $R.Raw)
}

function Test-ResInFile($R) {
    if ($null -eq $R.Offset -or $null -eq $R.Original) { return $false }
    return ($R.Offset -le $script:FileLength -and $R.Stored -le ($script:FileLength - $R.Offset))
}

function Invoke-Section([string] $Name, [scriptblock] $Body) {
    Out-Section $Name
    try {
        & $Body
    }
    catch {
        Out-Line ('SECTION ERROR: ' + $_.Exception.Message)
    }
}

function Get-CeilDiv([long] $A, [long] $B) {
    $t = [Math]::DivRem([long]$A, [long]$B)
    if ($t.Item2 -ne 0) { return $t.Item1 + 1 }
    return $t.Item1
}

$item = Get-Item -LiteralPath $Path
$script:FileLength = [long]$item.Length
$script:Fs = [System.IO.File]::Open($item.FullName, [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)

$hdr = $null
$lookupEntries = @()

try {
    Invoke-Section 'file' {
        Out-Line ('path: ' + $item.Name)
        Out-Line ('length: ' + $script:FileLength)
        if (-not $NoFileHash) {
            Out-Line ('sha256: ' + (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant())
        }
        Out-Line 'reading: fields little-endian (OPEN-WIM-1); offsets per specs/standards/wim.md ([derived] where marked there)'
    }

    Invoke-Section 'header' {
        $head = Read-At 0 ([Math]::Min(12L, $script:FileLength))
        if ($head.Length -lt 12) { throw 'file shorter than 12 bytes' }
        $cb = [long](Get-U32 $head 8)
        $n = [Math]::Min([Math]::Min($cb, [long]$Cap.HeaderBytes), $script:FileLength)
        if ($n -lt 208) {
            Out-Line ("cbSize={0}; dumping the first {1} bytes" -f $cb, [Math]::Min(208L, $script:FileLength))
            $n = [Math]::Min(208L, $script:FileLength)
        }
        $b = Read-At 0 $n
        Out-HexDump $b 0
        if ($b.Length -lt 208) { throw "header shorter than the 208 bytes of wim.md section 2: $($b.Length)" }
        $script:hdr = [pscustomobject]@{
            CbSize      = $cb
            Flags       = [uint64](Get-U32 $b 16)
            ImageCount  = [long](Get-U32 $b 44)
            Lookup      = Read-ResHdr $b 48
            Xml         = Read-ResHdr $b 72
            BootMeta    = Read-ResHdr $b 96
            BootIndex   = [long](Get-U32 $b 120)
            Integrity   = Read-ResHdr $b 124
        }
        Out-Line ''
        Out-Line ('@0   ImageTag          ' + (ConvertTo-HexText $b 0 8) + '  ascii: ' + [System.Text.Encoding]::ASCII.GetString($b, 0, 5))
        Out-Line ('@8   cbSize            {0}  ({1})' -f $cb, (ConvertTo-HexText $b 8 4))
        Out-Line ('@12  dwVersion         0x{0:x8}  ({1})' -f (Get-U32 $b 12), (ConvertTo-HexText $b 12 4))
        Out-Line ('@16  dwFlags           0x{0:x8} [{1}]  ({2})' -f (Get-U32 $b 16), (Format-Flags $script:hdr.Flags $HeaderFlagNames), (ConvertTo-HexText $b 16 4))
        Out-Line ('@20  dwCompressionSize {0}  ({1})' -f (Get-U32 $b 20), (ConvertTo-HexText $b 20 4))
        Out-Line ('@24  gWIMGuid          ' + (ConvertTo-HexText $b 24 16))
        Out-Line ('@40  usPartNumber      {0}  ({1})' -f (Get-U16 $b 40), (ConvertTo-HexText $b 40 2))
        Out-Line ('@42  usTotalParts      {0}  ({1})' -f (Get-U16 $b 42), (ConvertTo-HexText $b 42 2))
        Out-Line ('@44  dwImageCount      {0}  ({1})' -f $script:hdr.ImageCount, (ConvertTo-HexText $b 44 4))
        Out-Line ('@48  rhOffsetTable     ' + (Format-ResHdr $script:hdr.Lookup))
        Out-Line ('@72  rhXmlData         ' + (Format-ResHdr $script:hdr.Xml))
        Out-Line ('@96  rhBootMetadata    ' + (Format-ResHdr $script:hdr.BootMeta))
        Out-Line ('@120 dwBootIndex       {0}  ({1})' -f $script:hdr.BootIndex, (ConvertTo-HexText $b 120 4))
        Out-Line ('@124 rhIntegrity       ' + (Format-ResHdr $script:hdr.Integrity))
        $nonzero = 0
        for ($i = 148; $i -lt 208; $i++) { if ($b[$i] -ne 0) { $nonzero++ } }
        Out-Line ('@148 bUnused (60)      non-zero bytes: {0}' -f $nonzero)
        if ($cb -gt 208 -and $b.Length -gt 208) {
            Out-Line ('bytes 208..{0} (beyond the 208-byte layout) are in the hex dump above' -f ($b.Length - 1))
        }
    }

    Invoke-Section 'lookup' {
        if ($null -eq $script:hdr) { throw 'no header' }
        $r = $script:hdr.Lookup
        Out-Line ('resource: ' + (Format-ResHdr $r))
        if (-not (Test-ResInFile $r)) { throw 'lookup table region lies outside the file' }
        $show = [Math]::Min($r.Stored, [long]$Cap.LookupBytes)
        $b = Read-At $r.Offset $show
        Out-HexDump $b $r.Offset
        if ($show -lt $r.Stored) { Out-Line ("(hex capped at {0} of {1} bytes)" -f $show, $r.Stored) }
        if (($r.Flags -band 0x04) -ne 0) {
            Out-Line 'lookup region has the COMPRESSED resource flag; entries not decoded'
            return
        }
        $t = [Math]::DivRem([long]$r.Stored, 50L)
        Out-Line ('size/50 = {0} remainder {1}  (50-byte entries are [derived], OPEN-WIM-6)' -f $t.Item1, $t.Item2)
        $count = [Math]::Min($t.Item1, [long]$Cap.LookupEntries)
        # Plain assignments: an if-expression would unroll the byte array.
        $all = $b
        if ($count * 50 -gt $show) { $all = Read-At $r.Offset ($count * 50) }
        $list = [System.Collections.Generic.List[object]]::new()
        for ($i = 0; $i -lt $count; $i++) {
            $o = [int]($i * 50)
            $e = [pscustomobject]@{
                Index    = $i
                Res      = Read-ResHdr $all $o
                Part     = [int](Get-U16 $all ($o + 24))
                RefCount = [long](Get-U32 $all ($o + 26))
                Sha1     = ((ConvertTo-HexText $all ($o + 30) 20) -replace ' ', '')
            }
            $list.Add($e)
            Out-Line ('[{0}] {1} part={2} refcount={3} sha1={4}' -f $i, (Format-ResHdr $e.Res), $e.Part, $e.RefCount, $e.Sha1)
        }
        if ($count -lt $t.Item1) { Out-Line ("(entries capped at {0} of {1})" -f $count, $t.Item1) }
        $script:lookupEntries = $list.ToArray()
        $meta = @($script:lookupEntries | Where-Object { ($_.Res.Flags -band 0x02) -ne 0 })
        Out-Line ('metadata-flagged entries, table order: ' + (($meta | ForEach-Object { $_.Index }) -join ', '))
        Out-Line ('metadata-flagged count {0}; dwImageCount {1}' -f $meta.Count, $script:hdr.ImageCount)
    }

    Invoke-Section 'metadata' {
        $meta = @($script:lookupEntries | Where-Object { ($_.Res.Flags -band 0x02) -ne 0 })
        if ($meta.Count -eq 0) { Out-Line 'no metadata-flagged lookup entries'; return }
        $shown = 0
        foreach ($e in $meta) {
            if ($shown -ge $Cap.MetadataRes) { Out-Line '(metadata resources capped)'; break }
            $shown++
            Out-Line ('lookup [{0}] {1}' -f $e.Index, (Format-ResHdr $e.Res))
            if (-not (Test-ResInFile $e.Res)) { Out-Line '  outside this file (another part?)'; continue }
            $n = [Math]::Min($e.Res.Stored, [long]$Cap.MetadataBytes)
            Out-HexDump (Read-At $e.Res.Offset $n) $e.Res.Offset
        }
    }

    Invoke-Section 'xml' {
        if ($null -eq $script:hdr) { throw 'no header' }
        $r = $script:hdr.Xml
        Out-Line ('resource: ' + (Format-ResHdr $r))
        if ($r.Stored -eq 0) { Out-Line 'no XML resource'; return }
        if (-not (Test-ResInFile $r)) { throw 'XML region lies outside the file' }
        $n = [Math]::Min($r.Stored, [long]$Cap.XmlBytes)
        $b = Read-At $r.Offset $n
        Out-HexDump $b $r.Offset ([Math]::Min(256, $b.Length))
        if (($r.Flags -band 0x04) -ne 0) { Out-Line 'XML region has the COMPRESSED resource flag; text not decoded'; return }
        if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) {
            $len = $b.Length - 2
            if (($len % 2) -ne 0) { Out-Line 'odd byte count after the BOM; last byte ignored'; $len-- }
            Out-Line ('UTF-16LE text after the BOM ({0} bytes{1}):' -f $len, $(if ($n -lt $r.Stored) { ', capped' } else { '' }))
            Out-Line ([System.Text.Encoding]::Unicode.GetString($b, 2, $len))
        }
        else {
            Out-Line 'does not start with FF FE; text not decoded'
        }
    }

    Invoke-Section 'integrity' {
        if ($null -eq $script:hdr) { throw 'no header' }
        $r = $script:hdr.Integrity
        Out-Line ('resource: ' + (Format-ResHdr $r))
        if ($r.Stored -eq 0) { Out-Line 'no integrity table'; return }
        if (-not (Test-ResInFile $r)) { throw 'integrity region lies outside the file' }
        $n = [Math]::Min($r.Stored, [long]$Cap.IntegrityHead)
        $b = Read-At $r.Offset $n
        Out-HexDump $b $r.Offset
        if ($b.Length -lt 12) { throw 'integrity table shorter than 12 bytes' }
        $total = [long](Get-U32 $b 0)
        $entries = [long](Get-U32 $b 4)
        $chunk = [long](Get-U32 $b 8)
        Out-Line ('size field {0}; entry count {1}; chunk size {2} (0x{2:x})' -f $total, $entries, $chunk)
        Out-Line ('stored size {0}; 12 + 20 * count = {1}' -f $r.Stored, (12 + 20 * $entries))
        $lk = $script:hdr.Lookup
        if ($null -eq $lk.Offset) { throw 'lookup offset invalid; hashed range unknown' }
        $from = $script:hdr.CbSize
        $to = $lk.Offset + $lk.Stored
        Out-Line ('candidate hashed range [cbSize, end of lookup) = [{0}, {1}), {2} bytes' -f $from, $to, ($to - $from))
        if ($chunk -le 0 -or $to -le $from) { throw 'chunk size or range not usable' }
        Out-Line ('ceil(range / chunk size) = {0}' -f (Get-CeilDiv ($to - $from) $chunk))
        $check = [Math]::Min($entries, [long]$Cap.IntegrityHash)
        if ((12 + 20 * $check) -gt $r.Stored) { throw 'entry count exceeds the stored size' }
        $hashes = Read-At ($r.Offset + 12) (20 * $check)
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        try {
            for ($i = 0L; $i -lt $check; $i++) {
                $s = $from + $i * $chunk
                if ($s -ge $to) { Out-Line ("entry {0}: beyond the candidate range" -f $i); continue }
                $len = [Math]::Min($chunk, $to - $s)
                $digest = $sha1.ComputeHash((Read-At $s $len))
                $stored = (ConvertTo-HexText $hashes ([int]($i * 20)) 20) -replace ' ', ''
                $calc = ([Convert]::ToHexString($digest)).ToLowerInvariant()
                Out-Line ('entry {0}: stored {1} computed {2} over [{3}, {4}) {5}' -f
                    $i, $stored, $calc, $s, ($s + $len), $(if ($stored -eq $calc) { 'MATCH' } else { 'DIFFER' }))
            }
        }
        finally {
            $sha1.Dispose()
        }
    }

    Invoke-Section 'chunks' {
        $comp = @($script:lookupEntries | Where-Object { ($_.Res.Flags -band 0x04) -ne 0 })
        if ($comp.Count -eq 0) { Out-Line 'no lookup entry has the COMPRESSED resource flag'; return }
        $targets = @($comp[0])
        $largest = $comp | Sort-Object { $_.Res.Original } -Descending | Select-Object -First 1
        if ($largest.Index -ne $comp[0].Index) { $targets += $largest }
        foreach ($e in $targets) {
            $r = $e.Res
            Out-Line ''
            Out-Line ('-- lookup [{0}] {1}' -f $e.Index, (Format-ResHdr $r))
            if (-not (Test-ResInFile $r)) { Out-Line 'outside this file'; continue }
            if ($r.Original -le 0) { Out-Line 'original size 0'; continue }
            $chunks = Get-CeilDiv $r.Original $ChunkSize
            $tableEntries = $chunks - 1
            Out-Line ('chunks ceil(original / 32768) = {0}; table entries = {1}; original > 2^32: {2}' -f
                $chunks, $tableEntries, ($r.Original -gt 4294967296))
            foreach ($w in @(4, 8)) {
                $tsize = $tableEntries * $w
                Out-Line ''
                Out-Line ("width {0}: table size {1}" -f $w, $tsize)
                if ($tsize -gt $r.Stored -or $tsize -gt $Cap.ChunkTable) { Out-Line '  table larger than the resource or the cap'; continue }
                $tb = [byte[]]::new(0)
                if ($tsize -gt 0) { $tb = Read-At $r.Offset $tsize }
                Out-Line '  first table bytes:'
                Out-HexDump $tb $r.Offset ([Math]::Min(128, $tb.Length))
                if ($tb.Length -gt 128) {
                    Out-Line '  last table bytes:'
                    $tail = [Math]::Min(64, $tb.Length - 128)
                    $seg = [byte[]]::new($tail)
                    [Array]::Copy($tb, $tb.Length - $tail, $seg, 0, $tail)
                    Out-HexDump $seg ($r.Offset + $tb.Length - $tail)
                }
                # Starts relative to the end of the table (wim.md section 4,
                # [reading]); chunk 0 starts at 0.
                $starts = [long[]]::new([int]$chunks)
                $ok = $true
                for ($k = 1; $k -lt $chunks; $k++) {
                    $v = if ($w -eq 4) { [long](Get-U32 $tb ([int](($k - 1) * 4))) } else {
                        $u = Get-U64 $tb ([int](($k - 1) * 8))
                        if ($u -gt [uint64][long]::MaxValue) { $ok = $false; -1L } else { [long]$u }
                    }
                    $starts[$k] = $v
                    if ($v -le $starts[$k - 1]) { $ok = $false }
                }
                $dataLen = $r.Stored - $tsize
                $last = $dataLen - $starts[$chunks - 1]
                if ($last -le 0) { $ok = $false }
                Out-Line ('  increasing entries and positive last chunk: {0}; data after table {1}; last chunk stored {2}' -f $ok, $dataLen, $last)
                if (-not $ok) { continue }
                $show = @()
                if ($chunks -le $Cap.ChunksShown) { $show = 0..($chunks - 1) }
                else { $show = @(0, 1, 2, 3) + @(($chunks - 4)..($chunks - 1)) }
                foreach ($k in $show) {
                    $size = if ($k -lt $chunks - 1) { $starts[$k + 1] - $starts[$k] } else { $last }
                    $expect = if ($k -lt $chunks - 1) { $ChunkSize } else { $r.Original - ($chunks - 1) * $ChunkSize }
                    $at = $r.Offset + $tsize + $starts[$k]
                    Out-Line ('  chunk {0}: file offset {1} stored {2} expands to {3}{4}' -f
                        $k, $at, $size, $expect, $(if ($size -eq $expect) { ' (stored size equals expanded size)' } else { '' }))
                    $peek = [Math]::Min($size, $(if ($k -eq 0) { 288L } else { 32L }))
                    if ($peek -gt 0) { Out-HexDump (Read-At $at $peek) $at }
                }
            }
        }
    }
}
finally {
    $script:Fs.Dispose()
}
