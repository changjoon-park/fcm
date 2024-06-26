import os
import logging
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass
from typing import Generator
from pydantic import ValidationError

from dissect import cstruct
from flow.record.fieldtypes import uri
from dissect.target.helpers.fsutil import TargetPath

from core.forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings.tables import Tables
from settings.artifact_schema import ArtifactSchema

logger = logging.getLogger(__name__)

c_recyclebin_i = """
struct header_v1 {
    int64    version;
    int64    file_size;
    int64    timestamp;
    wchar    filename[260];
};
struct header_v2 {
    int64    version;
    int64    file_size;
    int64    timestamp;
    int32    filename_length;
    wchar    filename[filename_length];
};
"""

recyclebin_parser = cstruct.cstruct()
recyclebin_parser.load(c_recyclebin_i)


class RecyclebinRecord(ArtifactRecord):
    """Recyclebin record."""

    ts: datetime
    path: str
    filename: str
    filesize: int
    deleted_path: str
    source: str

    class Config:
        table_name: str = Tables.WIN_RECYCLEBIN.value


@dataclass(kw_only=True)
class RecycleBinParser:
    path: Path

    def __post_init__(self):
        self.sid = self.find_sid(self.path)
        self.source_path = str(self.path).lstrip("/")
        self.deleted_path = str(
            self.path.parent / self.path.name.replace("/$i", "/$r")
        ).lstrip("/")
        self.parse()

    def parse(self):
        data = self.path.read_bytes()
        header = self.select_header(data)
        entry = header(data)
        self.timestamp = entry.timestamp
        self.filename = entry.filename
        self.file_size = entry.file_size

    def find_sid(self, path: TargetPath) -> str:
        parent_path = path.parent
        if parent_path.name.lower() == "$recycle.bin":
            return "unknown"
        return parent_path.name

    def select_header(self, data: bytes) -> cstruct.Structure:
        """Selects the correct header based on the version field in the header"""

        header_version = recyclebin_parser.uint64(data[:8])
        if header_version == 2:
            return recyclebin_parser.header_v2
        else:
            return recyclebin_parser.header_v1


class RecycleBin(ForensicArtifact):
    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    def parse(self, descending: bool = False) -> None:
        """
        Return files located in the recycle bin ($Recycle.Bin).

        Write RecycleBinRecords with fields:
          hostname (string): The target hostname
          domain (string): The target domain
          ts (datetime): The time of deletion
          path (uri): The file original location before deletion
          filesize (filesize): Filesize of the deleted file
          sid (string): SID of the user deleted the file, parsed from $I filepath
          user (string): Username matching SID, lookup using Dissect user plugin
          deleted_path (uri): Location of the deleted file after deletion $R file
          source (uri): Location of $I meta file on disk
        """
        try:
            recyclebin = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.recyclebin())
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
        except Exception as e:
            self.log_error(e)
            return

        self.records.append(recyclebin)

    def recyclebin(self) -> Generator[dict, None, None]:
        for entry in self.check_empty_entry(self.iter_entry(recurse=True)):
            try:
                recyclebin = RecycleBinParser(path=entry)
                ts = self.ts.wintimestamp(recyclebin.timestamp)
                path = uri.from_windows(recyclebin.filename.rstrip("\x00"))
                filename = os.path.split(path)[1]

                parsed_data = {
                    "ts": ts,
                    "path": path,
                    "filename": filename,
                    "filesize": recyclebin.file_size,
                    "deleted_path": uri.from_windows(recyclebin.deleted_path),
                    "source": uri.from_windows(recyclebin.source_path),
                    "evidence_id": self.evidence_id,
                }

                try:
                    yield RecyclebinRecord(**parsed_data)
                except ValidationError as e:
                    self.log_error(e)
                    continue
            except Exception as e:
                self.log_error(e)
                continue
