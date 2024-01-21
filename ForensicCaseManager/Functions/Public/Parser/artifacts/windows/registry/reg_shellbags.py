import logging
from typing import Optional
from datetime import datetime
from pydantic import ValidationError

from dissect.cstruct import cstruct
from dissect.target.exceptions import RegistryKeyNotFoundError
from dissect.target.plugins.os.windows.regf.shellbags import (
    DELEGATE_ITEM_IDENTIFIER,
    UNKNOWN,
    UNKNOWN0,
    UNKNOWN1,
    ROOT_FOLDER,
    VOLUME,
    FILE_ENTRY,
    NETWORK,
    COMPRESSED_FOLDER,
    URI,
    CONTROL_PANEL,
    CONTROL_PANEL_CATEGORY,
    CDBURN,
    GAME_FOLDER,
    CONTROL_PANEL_CPL_FILE,
    MTP_FILE_ENTRY,
    MTP_VOLUME,
    USERS_PROPERTY_VIEW,
    UNKNOWN_0x74,
    DELEGATE,
    EXTENSION_BLOCK,
    EXTENSION_BLOCK_BEEF0004,
    EXTENSION_BLOCK_BEEF0005,
)

from forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings.artifacts import Tables, ArtifactSchema

logger = logging.getLogger(__name__)

bag_def = """
enum ROOTFOLDER_ID : uint8 {
    INTERNET_EXPLORER   = 0x00,
    LIBRARIES           = 0x42,
    USERS               = 0x44,
    MY_DOCUMENTS        = 0x48,
    MY_COMPUTER         = 0x50,
    NETWORK             = 0x58,
    RECYCLE_BIN         = 0x60,
    INTERNET_EXPLORER   = 0x68,
    UNKNOWN             = 0x70,
    MY_GAMES            = 0x80
};

struct SHITEM_UNKNOWN0 {
    uint16  size;
    uint8   type;
};

struct SHITEM_UNKNOWN1 {
    uint16  size;
    uint8   type;
};

struct SHITEM_ROOT_FOLDER {
    uint16          size;
    uint8           type;
    ROOTFOLDER_ID   folder_id;
    char            guid[16];
};

struct SHITEM_VOLUME {
    uint16  size;
    uint8   type;
};

struct SHITEM_FILE_ENTRY {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint32  file_size;
    uint32  modification_time;
    uint16  file_attribute_flags;
};

struct SHITEM_NETWORK {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint8   flags;
    char    location[];
};

struct SHITEM_COMPRESSED_FOLDER {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint16  unk1;
};

struct SHITEM_URI {
    uint16  size;
    uint8   type;
    uint8   flags;
    uint16  data_size;
};

struct SHITEM_CONTROL_PANEL {
    uint16  size;
    uint8   type;
    uint8   unk0;
    char    unk1[10];
    char    guid[16];
};

struct SHITEM_CONTROL_PANEL_CATEGORY {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint32  signature;
    uint32  category;
};

struct SHITEM_CDBURN {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint32  signature;
    uint32  unk1;
    uint32  unk2;
};

struct SHITEM_GAME_FOLDER {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint32  signature;
    char    identifier[16];
    uint64  unk1;
};

struct SHITEM_CONTROL_PANEL_CPL_FILE {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint32  signature;
    uint32  unk1;
    uint32  unk2;
    uint32  unk3;
    uint16  name_offset;
    uint16  comments_offset;
    wchar   cpl_path[];
    wchar   name[];
    wchar   comments[];
};

struct SHITEM_MTP_PROPERTY {
    char    format_identifier[16];
    uint32  value_identifier;
    uint32  value_type;
};

struct SHITEM_MTP_FILE_ENTRY {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint16  data_size;
    uint32  data_signature;
    uint32  unk1;
    uint16  unk2;
    uint16  unk3;
    uint16  unk4;
    uint16  unk5;
    uint32  unk6;
    uint64  modification_time;
    uint64  creation_time;
    char    content_type_folder[16];
    uint32  unk7;
    uint32  folder_name_size_1;
    uint32  folder_name_size_2;
    uint32  folder_identifier_size;
    wchar   folder_name_1[folder_name_size_1];
    wchar   folder_name_2[folder_name_size_2];
    uint32  unk8;
    char    class_identifier[16];
    uint32  num_properties;
};

struct SHITEM_MTP_VOLUME_GUID {
    wchar   guid[39];
};

struct SHITEM_MTP_VOLUME {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint16  data_size;
    uint32  data_signature;
    uint32  unk1;
    uint16  unk2;
    uint16  unk3;
    uint16  unk4;
    uint16  unk5;
    uint32  unk6;
    uint64  unk7;
    uint32  unk8;
    uint32  name_size;
    uint32  identifier_size;
    uint32  filesystem_size;
    uint32  num_guid;
    wchar   name[name_size];
    wchar   identifier[identifier_size];
    wchar   filesystem[filesystem_size];
    SHITEM_MTP_VOLUME_GUID     guids[num_guid];
    uint32  unk9;
    char    class_identifier[16];
    uint32  num_properties;
};

struct SHITEM_USERS_PROPERTY_VIEW {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint16  data_size;
    uint32  data_signature;
    uint16  property_store_size;
    uint16  identifier_size;
    char    identifier[identifier_size];
    char    property_store[property_store_size];
    uint16  unk1;
};

struct SHITEM_UNKNOWN_0x74 {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint16  data_size;
    uint32  data_signature;
    uint16  subitem_size;
};

struct SHITEM_UNKNOWN_0x74_SUBITEM {
    uint8   type;
    uint8   unk1;
    uint32  file_size;
    uint32  modification_time;
    uint16  file_attribute_flags;
    char    primary_name[];
};

struct SHITEM_DELEGATE {
    uint16  size;
    uint8   type;
    uint8   unk0;
    uint16  data_size;
    char    data[data_size - 2];
    char    delegate_identifier[16];
    char    shell_identifier[16];
};

struct EXTENSION_BLOCK_HEADER {
    uint16  size;
    uint16  version;
    uint32  signature;
};
"""
c_bag = cstruct()
c_bag.load(bag_def)


class ShellBagRecord(ArtifactRecord):
    """Shellbag record."""

    path: str
    creation_time: Optional[datetime]
    modification_time: Optional[datetime]
    access_time: Optional[datetime]
    regf_modification_time: datetime
    user: str
    key: str

    class Config:
        table_name: str = Tables.REG_SHELLBAGS.value


class Shellbags(ForensicArtifact):
    """Windows Shellbags plugin.

    Resources:
        https://github.com/libyal/libfwsi
    """

    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    def parse(self, descending: bool = False):
        try:
            shellbags = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.shellbags())
                ),
                key=lambda record: record.path,
                reverse=descending,
            )
        except Exception as e:
            self.log_error(e)
            return

        self.records.append(shellbags)

    def shellbags(self):
        """Return Windows Shellbags.

        Shellbags are registry keys to improve user experience when using Windows Explorer. It stores information about
        for example file/folder creation time and access time.

        Sources:
            - https://www.hackingarticles.in/forensic-investigation-shellbags/
        """
        for reg_path in self.iter_entry():
            for regkey in self.src.source.registry.keys(reg_path):
                try:
                    bagsmru = regkey.subkey("BagMRU")

                    for r in self._walk_bags(bagsmru, None):
                        yield r
                except RegistryKeyNotFoundError as e:
                    self.log_error(e)
                    continue
                except Exception as e:  # noqa
                    self.log_error(e)
                    continue

    def _walk_bags(self, key, path_prefix):
        path_prefix = [] if path_prefix is None else [path_prefix]

        user = self.src.source.registry.get_user(key)

        for reg_val in key.values():
            name, value = reg_val.name, reg_val.value
            if not name.isdigit():
                continue
            path = None

            for item in parse_shell_item_list(value):
                try:
                    path = "\\".join(path_prefix + [item.name])
                except UnicodeDecodeError as e:
                    self.log_error(e)
                    continue
                except Exception as e:  # noqa
                    self.log_error(e)
                    continue

                # TODO: Handle errors
                """ ERROR Message
                path = "\\".join(path_prefix + [item.name])
                UnicodeDecodeError: 'utf-8' codec can't decode byte 0xc5 in position 17: invalid continuation byte

                ! error example
                My Computer\{01f256e4-53bd-301f-2975-1b9ac3670110}\<UNKNOWN size=0x0100 type=None>\<UNKNOWN size=0x00fa type=None>\<UNKNOWN size=0x00fc type=None>\<UNKNOWN size=0x0104 type=None>\<UNKNOWN size=0x0112 type=None>\<UNKNOWN size=0x0106 type=None>\<UNKNOWN size=0x011e type=None>\<UNKNOWN size=0x0120 type=None>
                """

                parsed_data = {
                    "path": path if path else "",
                    "creation_time": item.creation_time,
                    "modification_time": item.modification_time,
                    "access_time": item.access_time,
                    "regf_modification_time": key.ts,
                    "user": str(user),
                    "key": str(key),
                    "evidence_id": self.evidence_id,
                }

                try:
                    yield ShellBagRecord(**parsed_data)
                except ValidationError as e:
                    self.log_error(e)
                    continue

            for r in self._walk_bags(key.subkey(name), path):
                yield r


def parse_shell_item_list(buf):
    offset = 0
    end = len(buf)
    list_buf = memoryview(buf)

    parent = None
    while offset < end:
        size = c_bag.uint16(list_buf[offset : offset + 2])

        if size == 0:
            break

        item_buf = list_buf[offset : offset + size]

        entry = None
        if size >= 8:
            signature = c_bag.uint32(item_buf[4:8])
            if signature == 0x39DE2184:
                entry = CONTROL_PANEL_CATEGORY
            elif signature == 0x4D677541:
                entry = CDBURN
            elif signature == 0x49534647:
                entry = GAME_FOLDER
            elif signature == 0xFFFFFF38:
                entry = CONTROL_PANEL_CPL_FILE

        if size >= 10 and not entry:
            signature = c_bag.uint32(item_buf[6:10])
            if signature == 0x07192006:
                entry = MTP_FILE_ENTRY
            elif signature == 0x10312005:
                entry = MTP_VOLUME
            elif signature in (
                0x10141981,
                0x23A3DFD5,
                0x23FEBBEE,
                0x3B93AFBB,
                0xBEEBEE00,
            ):
                entry = USERS_PROPERTY_VIEW
            elif signature == 0x46534643:
                entry = UNKNOWN_0x74

        if size >= 38 and not entry:
            if item_buf[size - 32 : size] == DELEGATE_ITEM_IDENTIFIER:
                entry = DELEGATE

        if size >= 3 and not entry:
            class_type = item_buf[2]
            mask_type = class_type & 0x70

            if mask_type == 0x00:
                if class_type == 0x00:
                    entry = UNKNOWN0
                elif class_type == 0x01:
                    entry = UNKNOWN1

            elif mask_type == 0x10:
                if class_type == 0x1F:
                    entry = ROOT_FOLDER

            elif mask_type == 0x20:
                if class_type in (0x23, 0x25, 0x29, 0x2A, 0x2E, 0x2F):
                    entry = VOLUME

            elif mask_type == 0x30:
                if class_type in (0x30, 0x31, 0x32, 0x35, 0x36, 0xB1):
                    entry = FILE_ENTRY

            elif mask_type == 0x40:
                if class_type in (0x41, 0x42, 0x46, 0x47, 0x4C, 0xC3):
                    entry = NETWORK

            elif mask_type == 0x50:
                if class_type == 0x52:
                    entry = COMPRESSED_FOLDER

            elif mask_type == 0x60:
                if class_type == 0x61:
                    entry = URI

            elif mask_type == 0x70:
                if class_type == 0x71:
                    entry = CONTROL_PANEL
            else:
                if not entry:
                    # log.debug("No supported shell item found for size 0x%04x and type 0x%02x", size, class_type)
                    entry = UNKNOWN

        if not entry:
            # log.debug("No supported shell item found for size 0x%04x", size)
            entry = UNKNOWN

        entry = entry(item_buf)
        entry.parent = parent

        first_extension_block_offset = c_bag.uint16(item_buf[-2:])
        if 4 <= first_extension_block_offset < size - 2:
            extension_offset = first_extension_block_offset
            while extension_offset < size - 2:
                extension_size = c_bag.uint16(
                    item_buf[extension_offset : extension_offset + 2]
                )

                if extension_size == 0:
                    break

                if extension_size > size - extension_offset:
                    # log.debug(
                    #     "Extension size exceeds item size: 0x%04x > 0x%04x - 0x%04x",
                    #     extension_size,
                    #     size,
                    #     extension_offset,
                    # )
                    break  # Extension size too large

                extension_buf = item_buf[
                    extension_offset : extension_offset + extension_size
                ]
                extension_signature = c_bag.uint32(extension_buf[4:8])

                ext = None

                if extension_signature >> 16 != 0xBEEF:
                    # log.debug("Got unsupported extension signature 0x%08x from item %r", extension_signature, entry)
                    pass  # Unsupported

                elif extension_signature == 0xBEEF0000:
                    pass

                elif extension_signature == 0xBEEF0001:
                    pass

                elif extension_signature == 0xBEEF0003:
                    ext = EXTENSION_BLOCK_BEEF0004

                elif extension_signature == 0xBEEF0004:
                    ext = EXTENSION_BLOCK_BEEF0004

                elif extension_signature == 0xBEEF0005:
                    ext = EXTENSION_BLOCK_BEEF0005

                elif extension_signature == 0xBEEF0006:
                    pass

                elif extension_signature == 0xBEEF000A:
                    pass

                elif extension_signature == 0xBEEF0013:
                    pass

                elif extension_signature == 0xBEEF0014:
                    pass

                elif extension_signature == 0xBEEF0019:
                    pass

                elif extension_signature == 0xBEEF0025:
                    pass

                elif extension_signature == 0xBEEF0026:
                    pass

                else:
                    # log.debug(
                    #     "Got unsupported beef extension signature 0x%08x from item %r", extension_signature, entry
                    # )
                    pass

                if ext is None:
                    ext = EXTENSION_BLOCK
                    logger.debug(
                        "Unimplemented extension signature 0x%08x from item %r",
                        extension_signature,
                        entry,
                    )

                ext = ext(extension_buf)

                entry.extensions.append(ext)
                extension_offset += extension_size

        parent = entry
        yield entry

        offset += size
