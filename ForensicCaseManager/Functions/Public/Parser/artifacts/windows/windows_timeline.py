import logging
from pathlib import Path
from typing import Generator, Optional
from datetime import datetime

from pydantic import ValidationError
from dissect.sql import sqlite3
from dissect.util.ts import from_unix

from core.forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings.artifacts import Tables, ArtifactSchema

logger = logging.getLogger(__name__)


class WindowsTimelineRecord(ArtifactRecord):
    """WindowsTimeline record."""

    start_time: datetime
    end_time: Optional[datetime]
    last_modified_time: Optional[datetime]
    last_modified_on_client: Optional[datetime]
    original_last_modified_on_client: Optional[datetime]
    expiration_time: Optional[datetime]
    app_id: Optional[str]
    enterprise_id: Optional[str]
    app_activity_id: Optional[str]
    group_app_activity_id: Optional[str]
    # group: Optional[str]  # TODO: Error with this field
    activity_type: Optional[int]
    activity_status: Optional[int]
    priority: Optional[int]
    match_id: Optional[int]
    etag: Optional[int]
    tag: Optional[str]
    is_local_only: Optional[bool]
    created_in_cloud: Optional[datetime]
    platform_device_id: Optional[str]
    package_id_hash: Optional[str]
    id: Optional[bytes]
    payload: Optional[str]
    original_payload: Optional[str]
    clipboard_payload: Optional[str]

    class Config:
        table_name: str = Tables.WIN_WINDOWSTIMELINE.value


class WindowsTimeline(ForensicArtifact):
    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    def parse(self, descending: bool = False) -> Path:
        """Return ActivitiesCache.db database content.

        The Windows Activities Cache database keeps track of activity on a device, such as application and services
        usage, files opened, and websites browsed. This database file can therefore be used to create a system timeline.
        It has first been used on Windows 10 1803.

        Currently only puts the database records straight into Flow Records. Ideally
        we do some additional parsing on this later.

        Sources:
            - https://artifacts-kb.readthedocs.io/en/latest/sources/windows/ActivitiesCacheDatabase.html
            - https://salt4n6.com/2018/05/03/windows-10-timeline-forensic-artefacts/

        Yields WindowsTimelineRecords with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            start_time (datetime): StartTime field.
            end_time (datetime): EndTime field.
            last_modified_time (datetime): LastModifiedTime field.
            last_modified_on_client (datetime): LastModifiedOnClient field.
            original_last_modified_on_client (datetime): OriginalLastModifiedOnClient field.
            expiration_time (datetime): ExpirationTime field.
            app_id (string): AppId field, JSON string containing multiple types of app name definitions.
            enterprise_id (string): EnterpriseId field.
            app_activity_id (string): AppActivityId field.
            group_app_activity_id (string): GroupAppActivityId field.
            group (string): Group field.
            activity_type (int): ActivityType field.
            activity_status (int): ActivityStatus field.
            priority (int): Priority field.
            match_id (int): MatchId field.
            etag (int): ETag field.
            tag (string): Tag field.
            is_local_only (boolean): IsLocalOnly field.
            created_in_cloud (datetime): CreatedInCloud field.
            platform_device_id (string): PlatformDeviceId field.
            package_id_hash (string): PackageIdHash field.
            id (bytes): Id field.
            payload (string): Payload field. JSON string containing payload data, varies per type.
            original_payload (string): OriginalPayload field.
            clipboard_payload (string): ClipboardPayload field.
        """

        try:
            windows_timeline = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.windows_timeline())
                ),
                key=lambda record: record.start_time,
            )
        except Exception as e:
            self.log_error(e)
            windows_timeline = []
        finally:
            self.records.append(windows_timeline)

    def windows_timeline(self) -> Generator[dict, None, None]:
        for entry in self.check_empty_entry(self.iter_entry(recurse=True)):
            try:
                fh = entry.open("rb")
                db = sqlite3.SQLite3(fh)
                for r in db.table("Activity").rows():
                    processed_data = {
                        "start_time": mkts(r["[StartTime]"]),
                        "end_time": mkts(r["[EndTime]"]),
                        "last_modified_time": mkts(r["[LastModifiedTime]"]),
                        "last_modified_on_client": mkts(r["[LastModifiedOnClient]"]),
                        "original_last_modified_on_client": mkts(
                            r["[OriginalLastModifiedOnClient]"]
                        ),
                        "expiration_time": mkts(r["[ExpirationTime]"]),
                        "app_id": r["[AppId]"],
                        "enterprise_id": r["[EnterpriseId]"],
                        "app_activity_id": r["[AppActivityId]"],
                        "group_app_activity_id": r["[GroupAppActivityId]"],
                        # "group": r["[Group]"],  # TODO: Error with this field
                        "activity_type": r["[ActivityType]"],
                        "activity_status": r["[ActivityStatus]"],
                        "priority": r["[Priority]"],
                        "match_id": r["[MatchId]"],
                        "etag": r["[ETag]"],
                        "tag": r["[Tag]"],
                        "is_local_only": r["[IsLocalOnly]"],
                        "created_in_cloud": r["[CreatedInCloud]"],
                        "platform_device_id": r["[PlatformDeviceId]"],
                        "package_id_hash": r["[PackageIdHash]"],
                        "id": r["[Id]"],
                        "payload": r["[Payload]"],
                        "original_payload": r["[OriginalPayload]"],
                        "clipboard_payload": r["[ClipboardPayload]"],
                        "evidence_id": self.evidence_id,
                    }

                    try:
                        yield WindowsTimelineRecord(**processed_data)
                    except ValidationError as e:
                        self.log_error(e)
                        continue
            except:
                self.log_error(e)
                continue


def mkts(ts):
    """Timestamps inside ActivitiesCache.db are stored in a Unix-like format.

    Source: https://salt4n6.com/2018/05/03/windows-10-timeline-forensic-artefacts/
    """
    return from_unix(ts) if ts else None
