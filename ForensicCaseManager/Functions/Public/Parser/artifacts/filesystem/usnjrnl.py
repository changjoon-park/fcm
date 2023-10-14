from dataclasses import dataclass
from typing import Iterator, Optional, Union, Iterator, Generator, Tuple
import json
from datetime import datetime

from dissect.target.filesystems.ntfs import NtfsFilesystem
from dissect.ntfs.c_ntfs import segment_reference
from flow.record.fieldtypes import uri
from pathlib import Path
from dissect.ntfs.usnjrnl import UsnJrnl
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugins.filesystem.ntfs.utils import get_drive_letter

from forensic_artifact import Source, ForensicArtifact


UsnjrnlRecord = TargetRecordDescriptor(
    "filesystem/ntfs/usnjrnl",
    [
        ("datetime", "ts"),
        ("varint", "usn"),
        ("string", "segment"),
        ("uri", "path"),
        ("string", "reason"),
        ("uint32", "security_id"),
        ("string", "source"),
        ("string", "attr"),
        ("uint16", "major"),
        ("uint16", "minor"),
    ],
)


class UsnJrnl(ForensicArtifact):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self) -> Path:
        """Return the UsnJrnl entries of all NTFS filesystems.

        The Update Sequence Number Journal (UsnJrnl) is a feature of an NTFS file system and contains information about
        filesystem activities. Each volume has its own UsnJrnl.

        Sources:
            - https://en.wikipedia.org/wiki/USN_Journal
            - https://velociraptor.velocidex.com/the-windows-usn-journal-f0c55c9010e
        """
        usnjrnl = []
        for fs in self._iter_filesystem():
            if entry := fs.ntfs.usnjrnl:
                for record in self.read_records(entry=entry, fs=fs):
                    usnjrnl.append(
                        json.dumps(
                            record._packdict(),
                            indent=2,
                            default=str,
                            ensure_ascii=False,
                        )
                    )

        self.result = {
            "usnjrnl": usnjrnl,
        }

    def read_records(
        self, entry: Path, fs: Optional[NtfsFilesystem] = None
    ) -> Iterator[Iterator]:
        drive_letter = get_drive_letter(self.src.source, fs)

        for record in entry.records():
            try:
                ts = None
                try:
                    ts = record.timestamp
                except:
                    pass

                path = f"{drive_letter}{record.full_path}"
                segment = segment_reference(record.record.FileReferenceNumber)
                yield UsnjrnlRecord(
                    ts=ts,
                    segment=f"{segment}#{record.FileReferenceNumber.SequenceNumber}",
                    path=uri.from_windows(path),
                    usn=record.Usn,
                    reason=str(record.Reason).replace("USN_REASON.", ""),
                    attr=str(record.FileAttributes).replace("FILE_ATTRIBUTE.", ""),
                    source=str(record.SourceInfo).replace("USN_SOURCE.", ""),
                    security_id=record.SecurityId,
                    major=record.MajorVersion,
                    minor=record.MinorVersion,
                )
            except:
                pass
