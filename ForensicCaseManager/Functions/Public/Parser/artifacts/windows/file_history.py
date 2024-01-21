import logging
import urllib
from datetime import datetime
from typing import BinaryIO, Generator, Optional
from dataclasses import dataclass

from pydantic import ValidationError
from dissect.sql.sqlite3 import SQLite3
from dissect.sql.exceptions import Error as SQLError
from dissect.esedb import esedb, record, table

from forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings.artifacts import Tables, ArtifactSchema

logger = logging.getLogger(__name__)


class FileHistoryRecord(ArtifactRecord):
    """File history record."""

    ts: datetime
    file_name: str
    file_ext: str
    path: str
    entry_id: int
    visit_count: int
    browser: str
    source: str

    class Config:
        table_name: str = Tables.WIN_FILE_HISTORY.value


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
    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    def parse(self, descending: bool = False):
        try:
            file_history = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.file_history())
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
        except Exception as e:
            self.log_error(e)
            file_history = []
        finally:
            self.records.append(file_history)

    def file_history(self) -> Generator[dict, None, None]:
        for data in self._combined_file_history():
            try:
                yield FileHistoryRecord(**data)
            except ValidationError as e:
                self.log_error(e)
                continue

    def _combined_file_history(self) -> Generator[dict, None, None]:
        """
        Combine Edge and IE history.
        """
        yield from self._edge_history()
        yield from self._ie_history()

    def _edge_history(self) -> Generator[dict, None, None]:
        for db_file in self.check_empty_entry(self.iter_entry(entry_name="Edge")):
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
                                "evidence_id": self.evidence_id,
                            }
                except SQLError as e:
                    logger.exception(
                        f"Error processing Edge history file: {db_file} / exc_info={e}"
                    )
            except Exception as e:
                logger.exception(
                    f"Error opening Edge history file: {db_file} / exc_info={e}"
                )

    def _ie_history(self) -> Generator[dict, None, None]:
        for db_file in self.check_empty_entry(self.iter_entry(entry_name="iExplorer")):
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
                                "evidence_id": self.evidence_id,
                            }
                except Exception as e:
                    logger.exception(
                        f"Error processing IE history file: {db_file} / exc_info={e}"
                    )
            except Exception as e:
                logger.exception(
                    f"Error opening IE history file: {db_file} / exc_info={e}"
                )
