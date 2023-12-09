import os
import logging
from pathlib import Path
from typing import Generator, BinaryIO

from lib.jumplist.app_id_list import app_id_list
from lib.jumplist.jumplist import TJumpListParser

from forensic_artifact import Source, ForensicArtifact


class JumpList(ForensicArtifact):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self, descending: bool = False) -> None:
        jumplist = sorted(
            [record for record in self.jumplist()],
            key=lambda record: record[
                "last_opened"
            ],  # Sorting based on the 'last_opened' field
            reverse=descending,
        )

        self.result = {"jumplist": jumplist}

    def jumplist(self) -> Generator[dict, None, None]:
        for entry in self.check_empty_entry(self._iter_entry()):
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
                        record_time = self.ts.wintimestamp(result[1])

                    # target_created = result[8]
                    # target_modified = result[9]
                    # target_accessed = result[10]
                    path = result[6] + result[5]

                    yield {
                        "last_opened": self.ts.to_localtime(record_time),
                        "file_name": str(self.fe.extract_filename(path=path)),
                        "file_ext": str(self.fe.extract_file_extention(path=path)),
                        "path": str(path),
                        "size": str(result[12]),
                        # "target_created": target_created,
                        # "target_modified": target_modified,
                        # "target_accessed": target_accessed,
                        "volume_label": str(result[14]),
                        "volume_serial_number": str(result[15]),
                        "drive_type": str(result[13]),
                        "app_id": str(app_id),
                        "app_name": str(application_name),
                        "access_count": str(result[2]),
                        "entry_id": str(result[3]),
                        "machine_id": str(result[16]),
                        "mac_address": str(result[17]),
                    }
            except:
                logging.exception("Error parsing JumpList entry: %s", entry)
                continue
