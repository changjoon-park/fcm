import logging
import urllib
from typing import BinaryIO, Generator
from dataclasses import dataclass

from dissect.sql.sqlite3 import SQLite3
from dissect.sql.exceptions import Error as SQLError
from dissect.esedb import esedb, record, table

from forensic_artifact import Source, ForensicArtifact
from settings import ART_FILE_HISTORY, RSLT_FILE_HISTORY

logger = logging.getLogger(__name__)


@dataclass(kw_only=True)
class WebCache:
    fh: BinaryIO

    def __post_init__(self):
        self.db = esedb.EseDB(self.fh)

    def find_containers(self, name: str) -> table.Table:
        try:
            for container_record in self.db.table("Containers").records():
                if record_name := container_record.get("Name"):
                    record_name = record_name.rstrip("\00").lower()
                    if record_name == name.lower():
                        container_id = container_record.get("ContainerId")
                        yield self.db.table(f"Container_{container_id}")
        except KeyError:
            pass

    def _iter_records(self, name: str) -> Generator[record.Record, None, None]:
        for container in self.find_containers(name):
            try:
                yield from container.records()
            except:
                logger.exception(f"Error: Unable to parse records from {container}")

    def history(self) -> Generator[record.Record, None, None]:
        """Yield records from the history webcache container."""
        yield from self._iter_records("history")

    def downloads(self) -> Generator[record.Record, None, None]:
        """Yield records from the iedownload webcache container."""
        yield from self._iter_records("iedownload")


class FileHistory(ForensicArtifact):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self, descending: bool = False):
        file_history = sorted(
            [record for record in self.file_history()],
            key=lambda record: record["ts"],  # Sorting based on the 'ts' field
            reverse=descending,
        )

        self.result = {
            RSLT_FILE_HISTORY: file_history,
        }

    def file_history(self) -> Generator[dict, None, None]:
        # Edge History
        for db_file in self.check_empty_entry(self._iter_entry(name="History*")):
            try:
                db = SQLite3(db_file.open("rb"))
                try:
                    urls = {row.id: row for row in db.table("urls").rows()}

                    for row in db.table("visits").rows():
                        url_record = urls[row.url]
                        url = url_record.url
                        visit_count = url_record.visit_count

                        if (path := urllib.parse.unquote(url)).startswith("file://"):
                            path = path.strip("file://").replace("/", "\\")

                            yield {
                                "ts": self.ts.webkittimestamp(row.visit_time),
                                "file_name": self.fe.extract_filename(path=path),
                                "file_ext": self.fe.extract_file_extention(path=path),
                                "path": path,
                                "entry_id": row.id,
                                "visit_count": visit_count,
                                "browser": "edge",
                                "source": str(db_file),
                            }
                except SQLError as e:
                    logger.exception(
                        f"Error processing Edge history file: {db_file} / exc_info={e}"
                    )
            except Exception as e:
                logger.exception(
                    f"Error opening Edge history file: {db_file} / exc_info={e}"
                )

        # IE History
        for db_file in self.check_empty_entry(self._iter_entry(name="WebCacheV01.dat")):
            try:
                db = WebCache(fh=db_file.open("rb"))
                try:
                    for container_record in db.history():
                        if not container_record.get("Url"):
                            continue

                        _, _, url = (
                            container_record.get("Url", "")
                            .rstrip("\x00")
                            .partition("@")
                        )

                        if accessed_time := container_record.get("AccessedTime"):
                            ts = self.ts.wintimestamp(accessed_time)
                        else:
                            ts = None

                        if (path := urllib.parse.unquote(url)).startswith("file://"):
                            path = path.strip("file://").replace("/", "\\")

                            yield {
                                "ts": ts,
                                "file_name": self.fe.extract_filename(path=path),
                                "file_ext": self.fe.extract_file_extention(path=path),
                                "path": path,
                                "entry_id": container_record.get("EntryId"),
                                "visit_count": container_record.get("AccessCount"),
                                "browser": "iexplore",
                                "source": str(db_file),
                            }
                except Exception as e:
                    logger.exception(
                        f"Error processing IE history file: {db_file} / exc_info={e}"
                    )
            except Exception as e:
                logger.exception(
                    f"Error opening IE history file: {db_file} / exc_info={e}"
                )
