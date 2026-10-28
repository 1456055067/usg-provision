//! Field offsets of the Windows structures parsed in [`crate::parse`],
//! computed from the `windows-sys` declarations.
//!
//! No offset or size here is written by hand: each comes from
//! `core::mem::offset_of!` or `size_of` over the `windows-sys` type, which
//! is generated from Microsoft's published API metadata (OPEN-WAPI-1;
//! decision 0019). This is safe code; nothing is read through a pointer.

// COMPLIANCE MAPPING:
// - NIST 800-53: SI-16 (Memory Protection) - no hand-written layouts
// - SPEC: specs/standards/windows-storage-firmware-api.md §12 OPEN-WAPI-1
// - DECISION: docs/decisions/0019-windows-api-binding.md

use core::mem::{offset_of, size_of};

use windows_sys::Win32::System::Ioctl::{
    DISK_DETECTION_INFO, DISK_EXTENT, DISK_GEOMETRY, DISK_GEOMETRY_EX, DISK_PARTITION_INFO,
    DRIVE_LAYOUT_INFORMATION_EX, DRIVE_LAYOUT_INFORMATION_GPT, DRIVE_LAYOUT_INFORMATION_MBR,
    PARTITION_INFORMATION_EX, PARTITION_INFORMATION_GPT, PARTITION_INFORMATION_MBR,
    PARTITION_STYLE_GPT, PARTITION_STYLE_MBR, STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR,
    STORAGE_DESCRIPTOR_HEADER, STORAGE_DEVICE_DESCRIPTOR, STORAGE_DEVICE_NUMBER,
    VOLUME_DISK_EXTENTS,
};

use crate::parse::{
    AlignmentLayout, DeviceDescriptorLayout, DeviceNumberLayout, DriveLayoutLayout, ExtentsLayout,
    GeometryLayout, HeaderLayout, NameFields, PartitionEntryLayout, ReparseLayout,
    SecurityDescriptorLayout,
};

pub(crate) const HEADER: HeaderLayout = HeaderLayout {
    size: offset_of!(STORAGE_DESCRIPTOR_HEADER, Size),
    len: size_of::<STORAGE_DESCRIPTOR_HEADER>(),
};

pub(crate) const DEVICE_DESCRIPTOR: DeviceDescriptorLayout = DeviceDescriptorLayout {
    size: offset_of!(STORAGE_DEVICE_DESCRIPTOR, Size),
    device_type: offset_of!(STORAGE_DEVICE_DESCRIPTOR, DeviceType),
    removable_media: offset_of!(STORAGE_DEVICE_DESCRIPTOR, RemovableMedia),
    vendor_id_offset: offset_of!(STORAGE_DEVICE_DESCRIPTOR, VendorIdOffset),
    product_id_offset: offset_of!(STORAGE_DEVICE_DESCRIPTOR, ProductIdOffset),
    product_revision_offset: offset_of!(STORAGE_DEVICE_DESCRIPTOR, ProductRevisionOffset),
    serial_number_offset: offset_of!(STORAGE_DEVICE_DESCRIPTOR, SerialNumberOffset),
    bus_type: offset_of!(STORAGE_DEVICE_DESCRIPTOR, BusType),
    fixed_len: offset_of!(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties),
};

pub(crate) const ALIGNMENT: AlignmentLayout = AlignmentLayout {
    size: offset_of!(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR, Size),
    logical: offset_of!(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR, BytesPerLogicalSector),
    physical: offset_of!(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR, BytesPerPhysicalSector),
    fixed_len: size_of::<STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR>(),
};

/// Bytes requested for the geometry query: the fixed fields plus room for
/// the partition and detection information that follow them (spec §4).
/// Only the fixed fields are parsed; the extra room is so that a driver
/// that insists on the full structure does not refuse the call.
pub(crate) const GEOMETRY_LEN: usize = offset_of!(DISK_GEOMETRY_EX, Data)
    + size_of::<DISK_PARTITION_INFO>()
    + size_of::<DISK_DETECTION_INFO>();

pub(crate) const GEOMETRY: GeometryLayout = GeometryLayout {
    media_type: offset_of!(DISK_GEOMETRY_EX, Geometry) + offset_of!(DISK_GEOMETRY, MediaType),
    bytes_per_sector: offset_of!(DISK_GEOMETRY_EX, Geometry)
        + offset_of!(DISK_GEOMETRY, BytesPerSector),
    disk_size: offset_of!(DISK_GEOMETRY_EX, DiskSize),
};

pub(crate) const DEVICE_NUMBER_LEN: usize = size_of::<STORAGE_DEVICE_NUMBER>();

pub(crate) const DEVICE_NUMBER: DeviceNumberLayout = DeviceNumberLayout {
    device_type: offset_of!(STORAGE_DEVICE_NUMBER, DeviceType),
    device_number: offset_of!(STORAGE_DEVICE_NUMBER, DeviceNumber),
    partition_number: offset_of!(STORAGE_DEVICE_NUMBER, PartitionNumber),
};

/// The length field of `GET_LENGTH_INFORMATION` is its only member.
pub(crate) const LENGTH_INFO_LEN: usize =
    size_of::<windows_sys::Win32::System::Ioctl::GET_LENGTH_INFORMATION>();
pub(crate) const LENGTH_INFO_LENGTH: usize = offset_of!(
    windows_sys::Win32::System::Ioctl::GET_LENGTH_INFORMATION,
    Length
);

const LAYOUT_UNION: usize = offset_of!(DRIVE_LAYOUT_INFORMATION_EX, Anonymous);
const ENTRY_UNION: usize = offset_of!(PARTITION_INFORMATION_EX, Anonymous);

pub(crate) const DRIVE_LAYOUT: DriveLayoutLayout = DriveLayoutLayout {
    style: offset_of!(DRIVE_LAYOUT_INFORMATION_EX, PartitionStyle),
    count: offset_of!(DRIVE_LAYOUT_INFORMATION_EX, PartitionCount),
    gpt_disk_id: LAYOUT_UNION + offset_of!(DRIVE_LAYOUT_INFORMATION_GPT, DiskId),
    gpt_starting_usable: LAYOUT_UNION
        + offset_of!(DRIVE_LAYOUT_INFORMATION_GPT, StartingUsableOffset),
    gpt_usable_length: LAYOUT_UNION + offset_of!(DRIVE_LAYOUT_INFORMATION_GPT, UsableLength),
    gpt_max_partition_count: LAYOUT_UNION
        + offset_of!(DRIVE_LAYOUT_INFORMATION_GPT, MaxPartitionCount),
    mbr_signature: LAYOUT_UNION + offset_of!(DRIVE_LAYOUT_INFORMATION_MBR, Signature),
    entries: offset_of!(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry),
    entry_stride: size_of::<PARTITION_INFORMATION_EX>(),
    entry: PartitionEntryLayout {
        style: offset_of!(PARTITION_INFORMATION_EX, PartitionStyle),
        starting_offset: offset_of!(PARTITION_INFORMATION_EX, StartingOffset),
        length: offset_of!(PARTITION_INFORMATION_EX, PartitionLength),
        number: offset_of!(PARTITION_INFORMATION_EX, PartitionNumber),
        gpt_type: ENTRY_UNION + offset_of!(PARTITION_INFORMATION_GPT, PartitionType),
        gpt_id: ENTRY_UNION + offset_of!(PARTITION_INFORMATION_GPT, PartitionId),
        gpt_attributes: ENTRY_UNION + offset_of!(PARTITION_INFORMATION_GPT, Attributes),
        gpt_name: ENTRY_UNION + offset_of!(PARTITION_INFORMATION_GPT, Name),
        // `Name` is the last field; the test below checks the width.
        gpt_name_units: (size_of::<PARTITION_INFORMATION_GPT>()
            - offset_of!(PARTITION_INFORMATION_GPT, Name))
            / size_of::<u16>(),
        mbr_type: ENTRY_UNION + offset_of!(PARTITION_INFORMATION_MBR, PartitionType),
        mbr_boot_indicator: ENTRY_UNION + offset_of!(PARTITION_INFORMATION_MBR, BootIndicator),
    },
    style_gpt: PARTITION_STYLE_GPT,
    style_mbr: PARTITION_STYLE_MBR,
};

/// Bytes for a drive-layout buffer with room for `n` entries.
pub(crate) const fn drive_layout_len(n: usize) -> usize {
    DRIVE_LAYOUT.entries + n * DRIVE_LAYOUT.entry_stride
}

pub(crate) const EXTENTS: ExtentsLayout = ExtentsLayout {
    count: offset_of!(VOLUME_DISK_EXTENTS, NumberOfDiskExtents),
    entries: offset_of!(VOLUME_DISK_EXTENTS, Extents),
    stride: size_of::<DISK_EXTENT>(),
    disk_number: offset_of!(DISK_EXTENT, DiskNumber),
    starting_offset: offset_of!(DISK_EXTENT, StartingOffset),
    length: offset_of!(DISK_EXTENT, ExtentLength),
};

pub(crate) const SECURITY_DESCRIPTOR: SecurityDescriptorLayout = {
    use windows_sys::Win32::Security::{
        ACE_HEADER, ACL, SE_DACL_PRESENT, SE_SACL_PRESENT, SE_SELF_RELATIVE,
        SECURITY_DESCRIPTOR_RELATIVE, SID,
    };
    use windows_sys::Win32::System::SystemServices::{
        SECURITY_DESCRIPTOR_REVISION, SID_MAX_SUB_AUTHORITIES, SID_REVISION,
    };
    SecurityDescriptorLayout {
        revision: offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Revision),
        control: offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Control),
        owner: offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Owner),
        group: offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Group),
        sacl: offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Sacl),
        dacl: offset_of!(SECURITY_DESCRIPTOR_RELATIVE, Dacl),
        fixed_len: size_of::<SECURITY_DESCRIPTOR_RELATIVE>(),
        // The revision constants are u32 in windows-sys and fit in a byte;
        // checked at compile time below.
        sd_revision: SECURITY_DESCRIPTOR_REVISION as u8,
        self_relative: SE_SELF_RELATIVE,
        sacl_present: SE_SACL_PRESENT,
        dacl_present: SE_DACL_PRESENT,
        sid_revision_field: offset_of!(SID, Revision),
        sid_revision: SID_REVISION as u8,
        sid_count: offset_of!(SID, SubAuthorityCount),
        sid_max_sub_authorities: SID_MAX_SUB_AUTHORITIES as u8,
        sid_sub_authority: offset_of!(SID, SubAuthority),
        acl_size: offset_of!(ACL, AclSize),
        acl_ace_count: offset_of!(ACL, AceCount),
        acl_fixed_len: size_of::<ACL>(),
        ace_size: offset_of!(ACE_HEADER, AceSize),
        ace_header_len: size_of::<ACE_HEADER>(),
    }
};

pub(crate) const REPARSE: ReparseLayout = {
    use windows_sys::Wdk::Storage::FileSystem::{
        REPARSE_DATA_BUFFER, REPARSE_DATA_BUFFER_0_0, REPARSE_DATA_BUFFER_0_1,
        SYMLINK_FLAG_RELATIVE,
    };
    use windows_sys::Win32::System::SystemServices::{
        IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK,
    };
    ReparseLayout {
        tag: offset_of!(REPARSE_DATA_BUFFER, ReparseTag),
        data_length: offset_of!(REPARSE_DATA_BUFFER, ReparseDataLength),
        reserved: offset_of!(REPARSE_DATA_BUFFER, Reserved),
        data: offset_of!(REPARSE_DATA_BUFFER, Anonymous),
        symlink: NameFields {
            sub_offset: offset_of!(REPARSE_DATA_BUFFER_0_0, SubstituteNameOffset),
            sub_length: offset_of!(REPARSE_DATA_BUFFER_0_0, SubstituteNameLength),
            print_offset: offset_of!(REPARSE_DATA_BUFFER_0_0, PrintNameOffset),
            print_length: offset_of!(REPARSE_DATA_BUFFER_0_0, PrintNameLength),
            path_buffer: offset_of!(REPARSE_DATA_BUFFER_0_0, PathBuffer),
        },
        symlink_flags: offset_of!(REPARSE_DATA_BUFFER_0_0, Flags),
        mount_point: NameFields {
            sub_offset: offset_of!(REPARSE_DATA_BUFFER_0_1, SubstituteNameOffset),
            sub_length: offset_of!(REPARSE_DATA_BUFFER_0_1, SubstituteNameLength),
            print_offset: offset_of!(REPARSE_DATA_BUFFER_0_1, PrintNameOffset),
            print_length: offset_of!(REPARSE_DATA_BUFFER_0_1, PrintNameLength),
            path_buffer: offset_of!(REPARSE_DATA_BUFFER_0_1, PathBuffer),
        },
        symlink_tag: IO_REPARSE_TAG_SYMLINK,
        mount_point_tag: IO_REPARSE_TAG_MOUNT_POINT,
        relative_flag: SYMLINK_FLAG_RELATIVE,
    }
};

const _: () = {
    use windows_sys::Win32::System::SystemServices::{
        SECURITY_DESCRIPTOR_REVISION, SID_MAX_SUB_AUTHORITIES, SID_REVISION,
    };
    assert!(SECURITY_DESCRIPTOR_REVISION <= 0xFF);
    assert!(SID_REVISION <= 0xFF);
    assert!(SID_MAX_SUB_AUTHORITIES <= 0xFF);
    // Topic 24 §2 to §4: 8-byte header; path buffers at data + 12
    // (symbolic link) and data + 8 (mount point).
    assert!(REPARSE.data == 8);
    assert!(REPARSE.symlink.path_buffer == 12 && REPARSE.mount_point.path_buffer == 8);
};

// Compile-time checks that each field read lies inside its structure.
const _: () = {
    assert!(HEADER.size + 4 <= HEADER.len);
    assert!(DEVICE_DESCRIPTOR.bus_type + 4 <= DEVICE_DESCRIPTOR.fixed_len);
    assert!(DEVICE_DESCRIPTOR.serial_number_offset + 4 <= DEVICE_DESCRIPTOR.fixed_len);
    assert!(ALIGNMENT.physical + 4 <= ALIGNMENT.fixed_len);
    assert!(GEOMETRY.disk_size + 8 <= GEOMETRY_LEN);
    assert!(DEVICE_NUMBER.partition_number + 4 <= DEVICE_NUMBER_LEN);
    assert!(LENGTH_INFO_LENGTH + 8 <= LENGTH_INFO_LEN);
    assert!(DRIVE_LAYOUT.gpt_max_partition_count + 4 <= DRIVE_LAYOUT.entries);
    assert!(
        DRIVE_LAYOUT.entry.gpt_name + 2 * DRIVE_LAYOUT.entry.gpt_name_units
            <= DRIVE_LAYOUT.entry_stride
    );
    assert!(EXTENTS.length + 8 <= EXTENTS.stride);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpt_name_field_is_36_units() {
        // `Name` is the last field of the GPT part, so its width is the
        // structure size less its offset, if there is no tail padding.
        let entry = PARTITION_INFORMATION_GPT::default();
        assert_eq!(DRIVE_LAYOUT.entry.gpt_name_units, entry.Name.len());
    }
}
