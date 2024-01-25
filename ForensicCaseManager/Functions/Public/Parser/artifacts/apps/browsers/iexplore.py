import logging
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import BinaryIO, Generator, Optional

from pydantic import ValidationError
from dissect.esedb import esedb, record, table

from core.forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings.artifacts import Tables, ArtifactSchema

logger = logging.getLogger(__name__)


class IExplorerHistoryRecord(ArtifactRecord):
    """InterHistory record."""

    ts: datetime
    entry_id: int
    url: str
    title: Optional[str]
    visit_type: Optional[str]
    visit_count: int
    hidden: Optional[int]
    from_visit: Optional[int]
    from_url: Optional[str]
    browser_type: str
    source: str

    class Config:
        table_name: str = Tables.APP_IEXPLORE_HISTORY.value


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
            except GeneratorExit:
                return
            except:
                logging.exception(f"Error: Unable to parse records from {container}")

    def history(self) -> Generator[record.Record, None, None]:
        """Yield records from the history webcache container."""
        yield from self._iter_records("history")

    def downloads(self) -> Generator[record.Record, None, None]:
        """Yield records from the iedownload webcache container."""
        yield from self._iter_records("iedownload")


class InternetExplorer(ForensicArtifact):
    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    @property
    def browser_type(self) -> str:
        return "iExplorer"

    # set default datetime to sort by timestamp
    @property
    def default_datetime(self) -> datetime:
        return datetime(1970, 1, 1, 0, 0, 0, 0, tzinfo=timezone.utc)

    def parse(self, descending: bool = False) -> None:
        try:
            history = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.history())
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
        except Exception as e:
            self.log_error(e)
            history = []
        finally:
            self.records.append(history)

        # sorted_downloads = sorted(
        #     [record._packdict() for record in self.downloads()],
        #     key=lambda x: x["ts_start"], reverse=descending
        # )
        # downloads = [
        #     json.dumps(record, indent=2, default=str, ensure_ascii=False)
        #     for record in sorted_downloads
        # ]

    def history(self) -> Generator[dict, None, None]:
        for db_file in self.check_empty_entry(
            self.iter_entry(node_name="WebCacheV01.dat")
        ):
            try:
                db = WebCache(fh=db_file.open("rb"))
                for container_record in db.history():
                    if not container_record.get("Url"):
                        continue

                    _, _, url = (
                        container_record.get("Url", "").rstrip("\x00").partition("@")
                    )

                    ts = None
                    if accessed_time := container_record.get("AccessedTime"):
                        ts = self.ts.wintimestamp(accessed_time)

                    if not ts:
                        ts = self.default_datetime

                    if url.startswith("http"):
                        parsed_data = {
                            "ts": ts,
                            "entry_id": container_record.get("EntryId"),
                            "url": url,
                            "title": None,
                            "visit_type": None,
                            "visit_count": container_record.get("AccessCount"),
                            "hidden": None,
                            "from_visit": None,
                            "from_url": None,
                            "browser_type": self.browser_type,
                            "source": str(db_file),
                            "evidence_id": self.evidence_id,
                        }

                    try:
                        yield IExplorerHistoryRecord(**parsed_data)
                    except ValidationError as e:
                        logger.error(e)
                        return
            except:
                logger.exception(f"Error: Unable to parse history from {db_file}")

    # TODO: bug fix
    def downloads(self) -> Generator[dict, None, None]:
        for db_file in self.iter_entry(name=self.entry):
            try:
                db = WebCache(fh=db_file.open("rb"))
                for container_record in db.downloads():
                    response_headers = container_record.ResponseHeaders.decode(
                        "utf-16-le", errors="ignore"
                    )
                    (
                        ref_url,
                        mime_type,
                        temp_download_path,
                        down_url,
                        down_path,
                    ) = response_headers.split("\x00")[-6:-1]

                    yield {
                        "ts": self.ts.wintimestamp(container_record.AccessedTime),
                        "entry_id": container_record.EntryId,
                        "path": down_path,
                        "url": down_url,
                        "size": container_record.FileSize,
                        "state": container_record.FileExtension,
                        "browser_type": self.browser_type,
                        "source": str(db_file),
                        "evidence_id": self.evidence_id,
                    }
            except:
                pass
