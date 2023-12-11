import logging
from typing import Optional, Generator
from pathlib import Path

from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.ntfs.c_ntfs import segment_reference
from flow.record.fieldtypes import uri
from dissect.target.plugins.filesystem.ntfs.utils import get_drive_letter

from forensic_artifact import Source, ForensicArtifact
from settings import ART_USNJRNL, RSLT_USNJRNL

logger = logging.getLogger(__name__)


class UsnJrnl(ForensicArtifact):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self, descending: bool = False) -> Path:
        """Return the UsnJrnl entries of all NTFS filesystems.

        The Update Sequence Number Journal (UsnJrnl) is a feature of an NTFS file system and contains information about
        filesystem activities. Each volume has its own UsnJrnl.

        Sources:
            - https://en.wikipedia.org/wiki/USN_Journal
            - https://velociraptor.velocidex.com/the-windows-usn-journal-f0c55c9010e
        """
        usnjrnl = []
        for fs in self.check_empty_entry(self._iter_filesystem()):
            if entry := fs.ntfs.usnjrnl:
                for index, record in enumerate(self.read_records(entry=entry, fs=fs)):
                    if type(record) == dict:
                        print(f"{self.artifact}-{index}: parsed successfully")
                    else:
                        print(
                            f"{self.artifact}-{index}: error during parsing, type: {type(record)}"
                        )
                        logging.error(
                            f"{self.artifact}-{index}: error during parsing, type: {type(record)}"
                        )
                    usnjrnl.append(record)

        self.result = {
            RSLT_USNJRNL: usnjrnl,
        }

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
                yield {
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
                }
            except Exception as e:
                logger.error(
                    "Error during processing of usnjrnl record: %s",
                    record.record,
                    exc_info=e,
                )
