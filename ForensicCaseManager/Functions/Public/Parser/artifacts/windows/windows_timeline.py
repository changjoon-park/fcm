import json
import datetime
from pathlib import Path
from typing import Optional, Generator, Union, Tuple

from dissect.sql import sqlite3
from dissect.util.ts import from_unix

from forensic_artifact import Source, ForensicArtifact


class WindowsTimeline(ForensicArtifact):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

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

        print(f"Parsing {self.artifact} from {self.src.source_path}")
        windows_timeline = sorted(
            [record for record in self.windows_timeline()],
            key=lambda record: record["start_time"],  # Sorting based on the 'ts' field
            reverse=descending,
        )
        self.result = {"windows_timeline": windows_timeline}

    def windows_timeline(self) -> Generator[dict, None, None]:
        for entry in self._iter_entry():
            if entry:
                print(f"parsing {entry}")
                try:
                    fh = entry.open("rb")
                    db = sqlite3.SQLite3(fh)
                    for r in db.table("Activity").rows():
                        yield {
                            "start_time": mkts(r["[StartTime]"]),
                            "end_time": mkts(r["[EndTime]"]),
                            # "last_modified_time": mkts(r["[LastModifiedTime]"]),
                            # "last_modified_on_client": mkts(r["[LastModifiedOnClient]"]),
                            # "original_last_modified_on_client": mkts(
                            #     r["[OriginalLastModifiedOnClient]"]
                            # ),
                            # "expiration_time": mkts(r["[ExpirationTime]"]),
                            # "app_id": r["[AppId]"],
                            # "enterprise_id": r["[EnterpriseId]"],
                            # "app_activity_id": r["[AppActivityId]"],
                            # "group_app_activity_id": r["[GroupAppActivityId]"],
                            # "group": r["[Group]"],
                            # "activity_type": r["[ActivityType]"],
                            # "activity_status": r["[ActivityStatus]"],
                            # "priority": r["[Priority]"],
                            # "match_id": r["[MatchId]"],
                            # "etag": r["[ETag]"],
                            # "tag": r["[Tag]"],
                            # "is_local_only": r["[IsLocalOnly]"],
                            # "created_in_cloud": r["[CreatedInCloud]"],
                            # "platform_device_id": r["[PlatformDeviceId]"],
                            # "package_id_hash": r["[PackageIdHash]"],
                            # "id": r["[Id]"],
                            # "payload": r["[Payload]"],
                            # "original_payload": r["[OriginalPayload]"],
                            # "clipboard_payload": r["[ClipboardPayload]"],
                        }
                except:
                    print("Error parsing Windows Timeline database")
            else:
                print(f"Error: no {entry} found")


def mkts(ts):
    """Timestamps inside ActivitiesCache.db are stored in a Unix-like format.

    Source: https://salt4n6.com/2018/05/03/windows-10-timeline-forensic-artefacts/
    """
    return from_unix(ts) if ts else None
