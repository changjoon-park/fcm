import os
import json
from pathlib import Path
from dataclasses import dataclass
from typing import Generator

from dissect import cstruct
from flow.record.fieldtypes import uri
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers.fsutil import TargetPath

from forensic_artifact import Source, ForensicArtifact

RecycleBinRecord = TargetRecordDescriptor(
    "windows/recyclebin",
    [
        ("datetime", "ts"),
        ("uri", "path"),
        ("string", "filename"),
        ("filesize", "filesize"),
        ("uri", "deleted_path"),
        ("string", "source"),
    ],
)

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

@dataclass(kw_only=True)
class RecycleBinParser:
    path: Path

    def __post_init__(self):
        self.sid = self.find_sid(self.path)
        self.source_path = str(self.path).lstrip("/")
        self.deleted_path = str(self.path.parent / self.path.name.replace("/$i", "/$r")).lstrip("/")
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

    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(
            src=src,
            artifact=artifact,
            category=category
        )
        
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
        recyclebin = sorted([
            json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
            for record in self.recyclebin()], reverse=descending)
     
        self.result = {
            "recyclebin": recyclebin
        }

    def recyclebin(self) -> Generator[RecycleBinRecord, None, None]:
        for entry in self._iter_entry(recurse=True):
            try:
                recyclebin = RecycleBinParser(path=entry)
                path = uri.from_windows(recyclebin.filename.rstrip("\x00"))
                filename = os.path.split(path)[1]
                
                yield RecycleBinRecord(
                    ts=self.ts.wintimestamp(recyclebin.timestamp),
                    path=path,
                    filename=filename,
                    source=uri.from_windows(recyclebin.source_path),
                    filesize=recyclebin.file_size,
                    deleted_path=uri.from_windows(recyclebin.deleted_path),
                    _target=self._target
                )
            except:
                pass