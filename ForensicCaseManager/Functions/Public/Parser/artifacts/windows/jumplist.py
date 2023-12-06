import os
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Generator, BinaryIO

from dissect.util.ts import wintimestamp
from dissect.target.helpers.descriptor_extensions import UserRecordDescriptorExtension
from dissect.target.helpers.record import create_extended_descriptor


from lib.jumplist.app_id_list import app_id_list
from lib.jumplist.jumplist import TJumpListParser

from forensic_artifact import Source, ForensicArtifact

JumpListRecord = create_extended_descriptor([UserRecordDescriptorExtension])(
    "windows/jumplist",
    [
        ("datetime", "last_opened"),
        ("string", "file_name"),
        ("string", "file_ext"),
        ("string", "path"),
        ("string", "size"),
        # ("string", "target_created"),
        # ("string", "target_modified"),
        # ("string", "target_accessed"),
        ("string", "volume_label"),
        ("string", "volume_serial_number"),
        ("string", "drive_type"),
        ("string", "app_id"),
        ("string", "app_name"),
        ("string", "access_count"),
        ("string", "entry_id"),
        ("string", "machine_id"),
        ("string", "mac_address"),
    ],
)


class JumpList(ForensicArtifact):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

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

        jumplist = sorted(
            [
                json.dumps(
                    record._packdict(), indent=2, default=str, ensure_ascii=False
                )
                for record in self.jumplist()
            ],
            reverse=descending,
        )

        self.result = {"jumplist": jumplist}

    def jumplist(self) -> Generator[JumpListRecord, None, None]:
        for entry in self._iter_entry():
            try:
                entry_filename = os.path.split(entry)[1]
                app_id = entry_filename[: entry_filename.rfind(".")]
                jumplist = TJumpListParser(fh=entry.open("rb"))
                parse_results = jumplist.dest_list
                # print(parse_results)

                if app_id in app_id_list:
                    application_name = app_id_list[app_id]
                else:
                    application_name = None

                for result in parse_results:
                    if result[1] is None:
                        record_time = ""
                    else:
                        record_time = wintimestamp(result[1])

                    # target_created = result[8]
                    # target_modified = result[9]
                    # target_accessed = result[10]
                    path = result[6] + result[5]
                    basename = os.path.basename(path)
                    file_name = os.path.splitext(basename)[0]
                    file_ext = os.path.splitext(basename)[1].strip(".")

                    yield JumpListRecord(
                        last_opened=self.ts.to_localtime(record_time),
                        file_name=str(file_name),
                        file_ext=file_ext,
                        path=str(path),
                        size=str(result[12]),
                        # target_created=target_created,
                        # target_modified=target_modified,
                        # target_accessed=target_accessed,
                        volume_label=str(result[14]),
                        volume_serial_number=str(result[15]),
                        drive_type=str(result[13]),
                        app_id=str(app_id),
                        app_name=str(application_name),
                        access_count=str(result[2]),
                        entry_id=str(result[3]),
                        machine_id=str(result[16]),
                        mac_address=str(result[17]),
                        _target=self._target,
                    )
            except:
                pass
