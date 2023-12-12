import json

from dissect.target.exceptions import RegistryKeyNotFoundError
from dissect.target.plugins.os.windows.regf.shellbags import (
    c_bag,
    ShellBagRecord,
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

from forensic_artifact import Source, ForensicArtifact


class ShellBags(ForensicArtifact):
    """Windows Shellbags plugin.

    Resources:
        https://github.com/libyal/libfwsi
    """

    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self, descending: bool = False):
        shellbags = sorted(
            [
                json.dumps(
                    record._packdict(), indent=2, default=str, ensure_ascii=False
                )
                for record in self.shellbags()
            ],
            reverse=descending,
        )

        self.result = {
            "shellbags": shellbags,
        }

    def shellbags(self):
        """Return Windows Shellbags.

        Shellbags are registry keys to improve user experience when using Windows Explorer. It stores information about
        for example file/folder creation time and access time.

        Sources:
            - https://www.hackingarticles.in/forensic-investigation-shellbags/
        """
        for reg_path in self.iter_key():
            for regkey in self.src.source.registry.keys(reg_path):
                try:
                    bagsmru = regkey.subkey("BagMRU")

                    for r in self._walk_bags(bagsmru, None):
                        yield r
                except RegistryKeyNotFoundError:
                    continue
                except Exception:  # noqa
                    # self.target.log.exception("Exception while parsing shellbags")
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
                path = "\\".join(path_prefix + [item.name])
                yield ShellBagRecord(
                    path=path,
                    creation_time=item.creation_time,
                    modification_time=item.modification_time,
                    access_time=item.access_time,
                    regf_modification_time=key.ts,
                    _target=self._target,
                    _user=user,
                    _key=key,
                )

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
                    # log.debug("Unimplemented extension signature 0x%08x from item %r", extension_signature, entry)

                ext = ext(extension_buf)

                entry.extensions.append(ext)
                extension_offset += extension_size

        parent = entry
        yield entry

        offset += size
