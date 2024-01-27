import logging
from typing import Optional, Generator
from datetime import datetime
from pathlib import Path

from pydantic import ValidationError
from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.ntfs.c_ntfs import segment_reference
from flow.record.fieldtypes import uri
from dissect.target.plugins.filesystem.ntfs.utils import get_drive_letter

from core.forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings.tables import Tables
from settings.artifact_schema import ArtifactSchema

logger = logging.getLogger(__name__)


class UsnJrnlRecord(ArtifactRecord):
    """UsnJrnl record."""

    ts: Optional[datetime]
    segment: Optional[str]
    path: Optional[str]
    usn: Optional[int]
    reason: Optional[str]
    attr: Optional[str]
    source: Optional[str]
    security_id: Optional[int]
    major: Optional[int]
    minor: Optional[int]

    class Config:
        table_name: str = Tables.FS_USNJRNL.value


class UsnJrnl(ForensicArtifact):
    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    def parse(self, descending: bool = False) -> Path:
        """Return the UsnJrnl entries of all NTFS filesystems.

        The Update Sequence Number Journal (UsnJrnl) is a feature of an NTFS file system and contains information about
        filesystem activities. Each volume has its own UsnJrnl.

        Sources:
            - https://en.wikipedia.org/wiki/USN_Journal
            - https://velociraptor.velocidex.com/the-windows-usn-journal-f0c55c9010e
        """

        try:
            usnjrnl = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for fs in self.check_empty_entry(self.iter_filesystem())
                    if (entry := fs.ntfs.usnjrnl)
                    for index, record in enumerate(
                        self.read_records(entry=entry, fs=fs)
                    )
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
        except Exception as e:
            self.log_error(e)
            usnjrnl = []
        finally:
            self.records.append(usnjrnl)

    def read_records(
        self, entry: Path, fs: Optional[NtfsFilesystem] = None
    ) -> Generator[dict, None, None]:
        drive_letter = get_drive_letter(self.src.source, fs)

        for record in entry.records():
            try:
                ts = None
                try:
                    ts = record.timestamp
                except:
                    logger.error(
                        "Error occured during parsing of timestamp in usnjrnl: %x",
                        record,
                        record.Timestamp,
                    )

                path = f"{drive_letter}{record.full_path}"
                segment = segment_reference(record.record.FileReferenceNumber)

                parsed_data = {
                    "ts": ts,
                    "segment": f"{segment}#{record.record.FileReferenceNumber.SequenceNumber}",
                    "path": uri.from_windows(path),
                    "usn": record.record.Usn,
                    "reason": str(record.record.Reason).replace("USN_REASON.", ""),
                    "attr": str(record.record.FileAttributes).replace(
                        "FILE_ATTRIBUTE.", ""
                    ),
                    "source": str(record.record.SourceInfo).replace("USN_SOURCE.", ""),
                    "security_id": record.record.SecurityId,
                    "major": record.record.MajorVersion,
                    "minor": record.record.MinorVersion,
                    "evidence_id": self.evidence_id,
                }

                try:
                    yield UsnJrnlRecord(**parsed_data)
                except ValidationError as e:
                    self.log_error(e)
                    continue
            except Exception as e:
                self.log_error(e)
                continue
