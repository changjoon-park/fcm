import logging
import binascii
from datetime import datetime
from enum import IntEnum, auto
from io import BytesIO
from typing import Callable, Generator, Optional, Tuple, Union
from pydantic import ValidationError

from flow.record.fieldtypes import uri
from dissect.cstruct import Structure, cstruct
from dissect.util.ts import wintimestamp
from dissect.target.exceptions import Error, RegistryError

from core.forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings.tables import Tables
from settings.artifact_schema import ArtifactSchema

logger = logging.getLogger(__name__)


c_shimdef = """
struct NT61_HEADER {
    uint32 magic;
    uint32 num_entries;
};

struct NT61_64_ENTRY {
    uint16 len;
    uint16 maxlen;
    uint32 _align;
    uint64 offset;
    uint64 ts;
    uint32 fileflags;
    uint32 flags;
    uint64 blobsize;
    uint64 bloboffset;
};

struct NT52_HEADER {
    uint32 magic;
    uint32 num_entries;
};

struct NT52_ENTRY_32 {
    uint16 len;
    uint16 maxlen;
    uint32 offset;
    uint64 ts;
    uint64 filesize;
};


struct NT52_ENTRY_64 {
    uint16 len;
    uint16 maxlen;
    uint32 _padding;
    uint64 offset;
    uint64 ts;
    uint64 filesize;
};

struct WIN81_ENTRY {
    uint32 magic;
    uint32 crc;
    uint32 len;
    char data[len];
};

struct WIN81_ENTRY_DATA {
    uint16 path_len;
    wchar path[path_len/2];
    uint16 pkg_len;
    wchar pkg[pkg_len/2];
    uint32 flags;
    uint32 a;
    uint64 ts;
    uint32 b;
};

struct WIN81_ENTRY_DATA_SINGLE {
    uint16 path_len;
    wchar path[path_len/2];
    uint32 flags;
};

struct WIN10_ENTRY {
    uint32 magic;
    uint32 crc;
    uint32 len;
    char data[len];
};

struct WIN10_ENTRY_DATA {
    uint16 path_len;
    wchar path[path_len/2];
    uint64 ts;
};
"""
c_shim = cstruct()
c_shim.load(c_shimdef)

MAGIC_NT61 = 0xBADC0FEE
MAGIC_NT52 = 0xBADC0FFE
MAGIC_WIN81 = 0x73743031
MAGIC_WIN10 = 0x73743031


class ShimCacheRecord(ArtifactRecord):
    """Shimcache registry record."""

    last_modified: datetime
    name: str
    entry_index: int
    path: str

    class Config:
        table_name: str = Tables.REG_SHIMCACHE.value


class SHIMCACHE_WIN_TYPE(IntEnum):
    """Specific shimcache versions"""

    VERSION_WIN10_CREATORS = 0x1001
    VERSION_WIN10 = 0x1000
    VERSION_WIN81 = 0x0801
    VERSION_NT61 = 0x0601
    VERSION_NT52 = 0x0502

    VERSION_WIN81_NO_HEADER = auto()


def win_10_path(ed: Structure) -> str:
    return ed.path


def win_8_path(ed: Structure) -> str:
    if ed.path_len:
        path = ed.path
    else:
        path = ed.pkg
    return path


def nt52_entry_type(fh: bytes) -> Structure:
    entry = c_shim.NT52_ENTRY_32(fh)

    if entry.offset == 0:
        entry_type = c_shim.NT52_ENTRY_64
    else:
        entry_type = c_shim.NT52_ENTRY_32
    return entry_type


def nt61_entry_type(_) -> Structure:
    return c_shim.NT61_64_ENTRY


TYPE_VARIATIONS = {
    SHIMCACHE_WIN_TYPE.VERSION_WIN10: {
        "headers": (c_shim.WIN10_ENTRY, c_shim.WIN10_ENTRY_DATA),
        "offset": 0x30,
        "path_finder": win_10_path,
    },
    SHIMCACHE_WIN_TYPE.VERSION_WIN10_CREATORS: {
        "headers": (c_shim.WIN10_ENTRY, c_shim.WIN10_ENTRY_DATA),
        "offset": 0x34,
        "path_finder": win_10_path,
    },
    SHIMCACHE_WIN_TYPE.VERSION_WIN81: {
        "headers": (c_shim.WIN81_ENTRY, c_shim.WIN81_ENTRY_DATA),
        "offset": 0x80,
        "path_finder": win_8_path,
    },
    SHIMCACHE_WIN_TYPE.VERSION_WIN81_NO_HEADER: {
        "headers": (c_shim.WIN81_ENTRY, c_shim.WIN81_ENTRY_DATA_SINGLE),
        "offset": 0x0,
        "path_finder": win_8_path,
    },
    SHIMCACHE_WIN_TYPE.VERSION_NT61: {
        "header": c_shim.NT61_HEADER,
        "header_function": nt61_entry_type,
        "offset": 0x80,
    },
    SHIMCACHE_WIN_TYPE.VERSION_NT52: {
        "header": c_shim.NT52_HEADER,
        "header_function": nt52_entry_type,
        "offset": 0x8,
    },
}


class CRCMismatchException(Error):
    pass


ShimCacheGeneratorType = Union[CRCMismatchException, Tuple[Optional[datetime], str]]


class ShimCacheParser:
    def __init__(self, fh: BytesIO, ntversion: str, noheader: bool = False) -> None:
        self.fh = fh
        self.ntversion = ntversion
        self.noheader = noheader

        self.version = self.identify()

    def __iter__(self) -> Generator[ShimCacheGeneratorType, None, None]:
        if not (self.version in list(SHIMCACHE_WIN_TYPE)):
            raise NotImplementedError()

        arguments = TYPE_VARIATIONS.get(self.version)

        if self.version in (
            SHIMCACHE_WIN_TYPE.VERSION_NT61,
            SHIMCACHE_WIN_TYPE.VERSION_NT52,
        ):
            shimcache_iterator = self.iter_nt
        else:
            shimcache_iterator = self.iter_win_8_plus

        return shimcache_iterator(**arguments)

    def identify(self) -> SHIMCACHE_WIN_TYPE:
        """Identify which SHIMCACHE version to use."""
        self.fh.seek(0)
        d = self.fh.read(0x100)
        magic = c_shim.uint32(d[:4])

        if magic == MAGIC_NT52:
            return SHIMCACHE_WIN_TYPE.VERSION_NT52

        if magic == MAGIC_NT61:
            return SHIMCACHE_WIN_TYPE.VERSION_NT61

        if magic == MAGIC_WIN81 and self.ntversion == "6.3":
            self.noheader = True
            return SHIMCACHE_WIN_TYPE.VERSION_WIN81_NO_HEADER

        if len(d) >= 0x84 and c_shim.uint32(d[0x80:0x84]) == MAGIC_WIN81:
            return SHIMCACHE_WIN_TYPE.VERSION_WIN81

        if len(d) >= 0x34 and c_shim.uint32(d[0x30:0x34]) == MAGIC_WIN10:
            return SHIMCACHE_WIN_TYPE.VERSION_WIN10

        if len(d) >= 0x38 and c_shim.uint32(d[0x34:0x38]) == MAGIC_WIN10:
            return SHIMCACHE_WIN_TYPE.VERSION_WIN10_CREATORS

        if self.ntversion == "6.3":
            if self.noheader:
                return SHIMCACHE_WIN_TYPE.VERSION_WIN81_NO_HEADER
            else:
                return SHIMCACHE_WIN_TYPE.VERSION_WIN81

        raise NotImplementedError()

    def iter_win_8_plus(
        self, headers: Tuple[Structure, Structure], offset: int, path_finder: Callable
    ) -> ShimCacheGeneratorType:
        entry_header, data_header = headers

        self.fh.seek(offset)
        while True:
            try:
                entry = entry_header(self.fh)
            except EOFError:
                break

            if binascii.crc32(entry.data) & 0xFFFFFFFF != entry.crc:
                yield CRCMismatchException(
                    message=f"offset={self.fh.tell() - len(entry)}"
                )
                break

            ed = data_header(entry.data)
            path = path_finder(ed)

            yield wintimestamp(ed.ts) if hasattr(ed, "ts") else None, path

    def iter_nt(
        self, header: Structure, offset: int, header_function: Callable
    ) -> Generator[Tuple[datetime, str], None, None]:
        self.fh.seek(0)

        header = header(self.fh)
        entry_header = header_function(self.fh)

        self.fh.seek(offset)

        for _ in range(header.num_entries):
            pos = self.fh.tell()
            entry = entry_header(self.fh)

            self.fh.seek(entry.offset)
            path = self.fh.read(entry.len)

            try:
                path = path.decode("utf-16-le")
            except UnicodeDecodeError:
                break

            yield wintimestamp(entry.ts), path

            self.fh.seek(pos + len(entry_header))


class ShimCache(ForensicArtifact):
    """
    Shimcache plugin.
    """

    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    def parse(self, descending: bool = False):
        try:
            shimcache = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.shimcache())
                ),
                key=lambda record: record.last_modified,
                reverse=descending,
            )
        except Exception as e:
            self.log_error(e)
            return

        self.records.append(shimcache)

    def shimcache(self) -> Generator[dict, None, None]:
        """Return the shimcache.

        The ShimCache or AppCompatCache stores registry keys related to properties from older Windows versions for
        compatibility purposes. Since it contains information about files such as the last
        modified date and the file size, it can be useful in forensic investigations.

        Sources:
            - https://www.andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/

        Yields ShimcacheRecords with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            last_modified (datetime): The last modified date.
            name (string): The value name.
            index (varint): The index of the entry.
            path (uri): The parsed path.
        """
        for reg_path in self.iter_entry():
            for key in self.src.source.registry.keys(reg_path):
                for value_name in ("AppCompatCache", "CacheMainSdb"):
                    try:
                        data = key.value(value_name).value
                    except RegistryError as e:
                        self.log_error(e)
                        continue

                    try:
                        cache = ShimCacheParser(
                            BytesIO(data),
                            self.src.source.ntversion,
                            value_name != "AppCompatCache",
                        )
                    except NotImplementedError:
                        logger.error(
                            "Not implemented ShimCache version: %s %s", key, value_name
                        )
                        continue
                    except EOFError:
                        logger.error(
                            "Error parsing ShimCache entry: %s %s", key, value_name
                        )
                        continue

                    yield from self._get_records(value_name, cache)

    def _get_records(
        self, name: str, cache: Generator[ShimCacheGeneratorType, None, None]
    ) -> Generator[dict, None, None]:
        for index, item in enumerate(cache):
            if isinstance(item, CRCMismatchException):
                logger.warning("A CRC mismatch occured for entry: %s", item)
                continue

            last_modified, path = item

            if not last_modified:
                last_modified = self.ts.base_datetime_windows

            path = uri.from_windows(self.src.source.resolve(path))

            parsed_data = {
                "last_modified": last_modified,
                "name": name,
                "entry_index": index,
                "path": path,
                "evidence_id": self.evidence_id,
            }

            try:
                yield ShimCacheRecord(**parsed_data)
            except ValidationError as e:
                self.log_error(e)
                continue
