meta:
  id: windows_lnk_file
  title: Windows shell link file
  file-extension: lnk
  xref:
    forensicswiki: LNK
    justsolve: Windows_Shortcut
    mime: application/x-ms-shortcut
    pronom: x-fmt/428
    wikidata: Q29000599
  license: CC0-1.0
#  imports:
#    - windows_shell_items
  encoding: cp437
  endian: le
doc: |
  Windows .lnk files (AKA "shell link" file) are most frequently used
  in Windows shell to create "shortcuts" to another files, usually for
  purposes of running a program from some other directory, sometimes
  with certain preconfigured arguments and some other options.
doc-ref: 'https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf'
seq:
  - id: shell_link_header
    -orig-id: ShellLinkHeader
    type: shell_link_header

  - id: link_target_id_list
    -orig-id: LinkTargetIDList
    type: link_target_id_list
    if: shell_link_header.link_flags.has_link_target_id_list

  - id: link_info
    -orig-id: LinkInfo
    type: link_info
    if: shell_link_header.link_flags.has_link_info

  - id: name_string
    -orig-id: NAME_STRING
    type: string_data
    if: shell_link_header.link_flags.has_name

  - id: relative_path
    -orig-id: RELATIVE_PATH
    type: string_data
    if: shell_link_header.link_flags.has_rel_path

  - id: working_dir
    -orig-id: WORKING_DIR
    type: string_data
    if: shell_link_header.link_flags.has_work_dir

  - id: command_line_arguments
    -orig-id: COMMAND_LINE_ARGUMENTS
    type: string_data
    if: shell_link_header.link_flags.has_arguments

  - id: icon_location
    -orig-id: ICON_LOCATION
    type: string_data
    if: shell_link_header.link_flags.has_icon_location

  - id: extra
    -orig-id: Extra
    size-eos: true

types:
  shell_link_header:
    doc-ref: 'https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf Section 2.1'
    seq:
      - id: header_size
        -orig-id: HeaderSize
        contents: [0x4c, 0, 0, 0]
        doc: |
          Technically, a size of the header, but in reality, it's
          fixed by standard.
      - id: link_clsid
        -orig-id: LinkCLSID
        contents: [0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46]
        doc: |
          16-byte class identified (CLSID), reserved for Windows shell link files.
      - id: link_flags
        -orig-id: LinkFlags
        type: link_flags
        size: 4
      - id: file_attributes
        -orig-id: FileAttributes
        type: file_attributes
      - id: creation_time
        -orig-id: CreationTime
        type: file_time
      - id: access_time
        -orig-id: AccessTime
        type: file_time
      - id: write_time
        -orig-id: WriteTime
        type: file_time
      - id: file_size
        -orig-id: FileSize
        type: u4
        doc: Lower 32 bits of the size of the file that this link targets
      - id: icon_index
        -orig-id: IconIndex
        type: s4
        doc: Index of an icon to use from target file
      - id: show_command
        -orig-id: ShowCommand
        type: u4
        enum: window_state
        doc: Window state to set after the launch of target executable
      - id: hot_key
        -orig-id: HotKey
        type: u2
      - id: reserved
        contents: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    types:
      link_flags:
        doc-ref: 'https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf Section 2.1.1'
        seq:
          # Byte #0
          - id: is_unicode
            -orig-id: IsUnicode (H)
            type: b1
            doc: |
              The shell link contains Unicode encoded strings. This bit SHOULD be set.
              If this bit is set, the StringData section contains Unicode-encoded string;
              otherwise, it contains strings that are encoded using the system default code page.
              ### If this bit is not set, the encoding of StringData is the default encoding and depends on the environment,
              ### in which the .lnk file was created.
              ### Therefore, correct decoding is impossible.
          - id: has_icon_location
            -orig-id: HasIconLocation (G)
            type: b1
          - id: has_arguments
            -orig-id: HasArguments (F)
            type: b1
          - id: has_work_dir
            -orig-id: HasWorkingDir (E)
            type: b1
          - id: has_rel_path
            -orig-id: HasRelativePath (D)
            type: b1
          - id: has_name
            -orig-id: HasName (C)
            type: b1
          - id: has_link_info
            -orig-id: HasLinkInfo (B)
            type: b1
          - id: has_link_target_id_list
            -orig-id: HasLinkTargetIDList (A)
            type: b1
          # Byte #1
          - id: no_pidl_alias
            -orig-id: NoPidlAlias (P)
            type: b1
          - id: has_exp_icon
            -orig-id: HasExpIcon (O)
            type: b1
          - id: run_as_user
            -orig-id: RunAsUser (N)
            type: b1
          - id: has_darwin_id
            -orig-id: HasDarwinID (M)
            type: b1
          - id: unused1
            -orig-id: Unused1 (L)
            type: b1
          - id: run_in_separate_process
            -orig-id: RunInSeparateProcess (K)
            type: b1
          - id: has_exp_string
            -orig-id: HasExpString (J)
            type: b1
          - id: force_no_link_info
            -orig-id: ForceNoLinkInfo (I)
            type: b1
          # Byte #2
          - id: allow_link_to_link
            -orig-id: AllowLinkToLink (X)
            type: b1
          - id: disable_known_folder_alias
            -orig-id: DisableKnownFolderAlias (W)
            type: b1
          - id: disable_known_folder_tracking
            -orig-id: DisableKnownFolderTracking (V)
            type: b1
          - id: disable_link_path_tracking
            -orig-id: DisableLinkPathTracking (U)
            type: b1
          - id: enable_tagerget_metadata
            -orig-id: EnableTargetMetadata (T)
            type: b1
          - id: force_no_link_track
            -orig-id: ForceNoLinkTrack (S)
            type: b1
          - id: run_with_shim_layer
            -orig-id: RunWithShimLayer (R)
            type: b1
          - id: unused2
            -orig-id: Unused2 (Q)
            type: b1
          # Byte #3
          - id: reserved
            type: b5
          - id: keep_local_id_list_for_unc_target
            -orig-id: KeepLocalIDListForUNCTarget (AA)
            type: b1
          - id: prefer_environment_path
            -orig-id: PreferEnvironmentPath (Z)
            type: b1
          - id: unalias_on_save
            -orig-id: UnaliasOnSave (Y)
            type: b1

      file_attributes:
        -orig-id: FileAttributesFlags
        doc-ref: 'https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf Section 2.1.2'
        seq:
          # Byte #0
          - id: file_attribute_normal
            -orig-id: FILE_ATTRIBUTE_NORMAL (H)
            type: b1
          - id: reserved2
            -orig-id: Reserved2 (G)
            type: b1
          - id: file_attribute_archive
            -orig-id: FILE_ATTRIBUTE_ARCHIVE (F)
            type: b1
          - id: file_attribute_directory
            -orig-id: FILE_ATTRIBUTE_DIRECTORY (E)
            type: b1
          - id: reserved1
            -orig-id: Reserved1 (D)
            type: b1
          - id: file_attribute_system
            -orig-id: FILE_ATTRIBUTE_SYSTEM (C)
            type: b1
          - id: file_attribute_hidden
            -orig-id: FILE_ATTRIBUTE_HIDDEN (B)
            type: b1
          - id: file_attribute_readonly
            -orig-id: FILE_ATTRIBUTE_READONLY (A)
            type: b1

          # Byte #1
          - id: reserved
            type: b1
          - id: file_attribute_encrypted
            -orig-id: FILE_ATTRIBUTE_ENCRYPTED (O)
            type: b1
          - id: file_attribute_not_content_indexed
            -orig-id: FILE_ATTRIBUTE_NOT_CONTENT_INDEXED (N)
            type: b1
          - id: file_attribute_offline
            -orig-id: FILE_ATTRIBUTE_OFFLINE (M)
            type: b1
          - id: file_attribute_compressed
            -orig-id: FILE_ATTRIBUTE_COMPRESSED (L)
            type: b1
          - id: file_attribute_reparse_point
            -orig-id: FILE_ATTRIBUTE_REPARSE_POINT (K)
            type: b1
          - id: file_attribute_sparse_file
            -orig-id: FILE_ATTRIBUTE_SPARSE_FILE (J)
            type: b1
          - id: file_attribute_temporary
            -orig-id: FILE_ATTRIBUTE_TEMPORARY (I)
            type: b1

          # Byte #2,3
          - id: reserved23
            type: b16

  link_target_id_list:
    doc-ref: 'https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf Section 2.2'
    seq:
      - id: id_list_size
        -orig-id: IDListSize
        type: u2
      # variable
      - id: id_list
        -orig-id: IDList # ItemIDList(variable) + TerminalID
        size: id_list_size
        type: id_list
    types:
      id_list:
        seq:
          - id: item_id_list
            type: item_id
            repeat: eos
        types:
          item_id:
            seq:
              - id: id_list_size
                type: u2
              - id: id_list_data
                size: id_list_size - 2
                if: id_list_size != 0

  link_info:
    -orig-id: LinkInfo
    doc-ref: 'https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf Section 2.3'
    seq:
      - id: link_info_size
        -orig-id: LinkInfoSize
        type: u4
      - id: link_info_header_size
        -orig-id: LinkInfoHeaderSize
        type: u4
      - id: link_info_flags
        -orig-id: LinkInfoFlags
        type: link_info_flags
      - id: volume_id_offset
        -orig-id: VolumeIDOffset
        type: u4
      - id: local_base_path_offset
        -orig-id: LocalBasePathOffset
        type: u4
      - id: common_network_relative_link_offset
        -orig-id: CommonNetworkRelativeLinkOffset
        type: u4
      - id: common_path_suffix_offset
        -orig-id: CommonPathSuffixOffset
        type: u4

      # optional
      - id: local_base_path_offset_unicode
        -orig-id: LocalBasePathOffsetUnicode
        type: u4
        if: link_info_header_size > 0x24
      # optional
      - id: common_path_suffix_offset_unicode
        -orig-id: CommonPathSuffixOffsetUnicode
        type: u4
        if: link_info_header_size > 0x24

      # variable
      - id: volume_id
        -orig-id: VolumeID
        type: volume_id
        if: link_info_flags.volume_id_and_local_base_path

      # variable
      - id: local_base_path
        -orig-id: LocalBasePath
        type: strz
        encoding: ASCII
        if: link_info_flags.volume_id_and_local_base_path
                
      # variable
      - id: common_network_relative_link
        -orig-id: CommonNetworkRelativeLink
        type: common_network_relative_link
        if: link_info_flags.common_network_relative_link_and_path_suffix
        
      # variable
      - id: common_path_suffix
        -orig-id: CommonPathSuffix
        type: strz
        encoding: ASCII
        
      # variable
      - id: local_base_path_unicode
        -orig-id: LocalBasePathUnicode
        type: strz
        encoding: UTF-16LE
        if: link_info_flags.volume_id_and_local_base_path and link_info_header_size >= 0x24
        
      # variable
      - id: common_path_suffix_unicode
        -orig-id: CommonPathSuffixUnicode
        type: strz
        encoding: UTF-16LE
        if: link_info_header_size >= 0x24

    types:
      link_info_flags:
        -orig-id: LinkInfoFlags
        doc-ref: 'https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf Section 2.3'
        seq:
          # Byte #0
          - id: reserved0
            type: b6
          - id: common_network_relative_link_and_path_suffix
            -orig-id: CommonNetworkRelativeLinkAndPathSuffix (B)
            type: b1
          - id: volume_id_and_local_base_path
            -orig-id: VolumeIDAndLocalBasePath (A)
            type: b1
          # Byte #1,2,3
          - id: reserved123
            type: b24

      volume_id:
        -orig-id: VolumeID
        doc-ref: 'https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf Section 2.3.1'
        seq:
          - id: volume_id_size
            -orig-id: VolumeIDSize
            type: u4
          - id: drive_type
            -orig-id: DriveType
            type: u4
            enum: drive_types
          - id: drive_serial_number
            -orig-id: DriveSerialNumber
            type: u4
          - id: volume_label_offset
            -orig-id: VolumeLabelOffset
            type: u4
          # optional
          - id: volume_label_offset_unicode
            -orig-id: VolumeLabelOffsetUnicode
            type: u4
            if: volume_label_offset == 0x14
          # variable
          - id: data
            -orig-id: Data
            size: volume_id_size - volume_label_offset
            type: strz
            encoding: ASCII

      common_network_relative_link:
        -orig-id: CommonNetworkRelativeLink
        doc-ref: 'https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SHLLINK/[MS-SHLLINK].pdf Section 2.3.2'
        seq:
          - id: common_network_relative_link_size
            -orig-id: CommonNetworkRelativeLinkSize
            type: u4
          - id: common_network_relative_link_flags
            -orig-id: CommonNetworkRelativeLinkFlags
            type: common_network_relative_link_flags
          - id: net_name_offset
            -orig-id: NetNameOffset
            type: u4
          - id: device_name_offset
            -orig-id: DeviceNameOffset
            type: u4
          - id: network_provider_type
            -orig-id: NetworkProviderType
            type: u4
          # optional
          - id: net_name_offset_unicode
            -orig-id: NetNameOffsetUnicode
            type: u4
            if: net_name_offset > 0x14
          # optional
          - id: device_name_offset_unicode
            -orig-id: DeviceNameOffsetUnicode
            type: u4
            if: net_name_offset > 0x14
          # variable
          - id: net_name
            -orig-id: NetName
            type: strz
            encoding: ASCII
            ### It's not specified in the spec, but it's probably what it should be.
            if: common_network_relative_link_flags.valid_net_type
          # variable
          - id: device_name
            -orig-id: DeviceName
            type: strz
            encoding: ASCII
            ### It's not specified in the spec, but it's probably what it should be.
            if: common_network_relative_link_flags.valid_device
          # variable
          - id: net_name_unicode
            -orig-id: NetNameUnicode
            type: strz
            encoding: UTF-16LE
            if: net_name_offset > 0x14
          # variable
          - id: device_name_unicode
            -orig-id: DeviceNameUnicode
            type: strz
            encoding: UTF-16LE
            if: net_name_offset > 0x14
          
      common_network_relative_link_flags:
        -orig-id: CommonNetworkRelativeLinkFlags
        seq:
          # Byte #0
          - id: reserved0
            type: b6
          - id: valid_net_type
            -orig-id: ValidNetType (B)
            type: b1
          - id: valid_device
            -orig-id: ValidDevice (A)
            type: b1
          # Byte #1,2,3
          - id: reserved123
            type: b24

  string_data:
    seq:
      - id: count_characters
        -orig-id: CountCharacters
        type: u2
      # variable
      - id: string
        type: str
        size: count_characters * 2
        encoding: UTF-16LE
        
  file_time:
    seq:
      - id: dw_low_date_time
        -orig-id: dwLowDateTime
        type: u4
      - id: dw_high_date_time
        -orig-id: dwHighDateTime
        type: u4
        
enums:
  window_state:
    1: sw_shownormal
    3: sw_showmaximized
    7: sw_showminnoactive
  drive_types:
    0: drive_unkown
    1: drive_no_roor_dir
    2: drive_removable
    3: drive_fixed
    4: drive_remote
    5: drive_cdrom
    6: drive_ramdisk
