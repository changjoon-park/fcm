import os
import json
import urllib
from typing import Generator

from dissect.sql.sqlite3 import SQLite3
from dissect.sql.exceptions import Error as SQLError
from dissect.target.helpers.record import TargetRecordDescriptor

from util.extractor import extract_basename, extract_fileext
from artifacts.application.browsers.iexplore import WebCache
from forensic_artifact import Source, ForensicArtifact

FileHistoryRecord = TargetRecordDescriptor(
    "windows/filehistory",
    [
        ("datetime", "ts"),
        ("string", "file_name"),
        ("string", "file_ext"),
        ("string", "path"),
        ("varint", "visit_count"),
        ("string", "id"),
        ("string", "browser"),
        ("path", "source"),
    ]    
)

class FileHistory(ForensicArtifact):

    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(
            src=src,
            artifact=artifact,
            category=category
        )
        
    def parse(self, descending: bool = False):
        file_history = sorted([
            json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
            for record in self.file_history()], reverse=descending)
        
        self.result = {
            "file_history": file_history,
        }

    def file_history(self) -> Generator[FileHistoryRecord, None, None] :
        # Edge History
        for db_file in self._iter_entry(name="History*"):
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

                            yield FileHistoryRecord(
                                ts=self.ts.webkittimestamp(row.visit_time),
                                file_name=extract_basename(path=path),
                                file_ext=extract_fileext(path=path),
                                path=path,
                                id=row.id,
                                visit_count=visit_count,
                                browser="edge",
                                source=str(db_file),
                            )

                except SQLError as e:
                    print(f"Error processing history file: {db_file} / exc_info={e}")
            except:
                pass
            
        # IE History
        for db_file in self._iter_entry(name="WebCacheV01.dat"):
            db = WebCache(fh=db_file.open("rb"))
            for container_record in db.history():
                if not container_record.get("Url"):
                    continue

                _, _, url = container_record.get("Url", "").rstrip("\x00").partition("@")

                if accessed_time := container_record.get("AccessedTime"):
                    ts = self.ts.wintimestamp(accessed_time)
                else:
                    ts = None

                if (path := urllib.parse.unquote(url)).startswith("file://"):
                    path = path.strip("file://").replace("/", "\\")

                    yield FileHistoryRecord(
                        ts=ts,
                        file_name=extract_basename(path=path),
                        file_ext=extract_fileext(path=path),
                        path=path,
                        id=container_record.get("EntryId"),
                        visit_count=container_record.get("AccessCount"),
                        browser="iexplore",
                        source=str(db_file),
                    )
                    