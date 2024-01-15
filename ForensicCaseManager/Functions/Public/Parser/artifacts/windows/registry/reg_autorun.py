import logging
from typing import Optional
from datetime import datetime

from flow.record.fieldtypes import uri

from forensic_artifact import Source, ArtifactRecord, ForensicArtifact, Record

logger = logging.getLogger(__name__)


class AutoRunRecord(ArtifactRecord):
    """Run key record."""

    ts: datetime
    name: str
    path: str
    key: str
    evidence_id: str

    class Config:
        record_name: str = "reg_autorun"


class AutoRun(ForensicArtifact):
    """Plugin that iterates various Runkey locations."""

    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self, descending: bool = False):
        try:
            runkeys = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.runkeys())
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
        except Exception as e:
            logger.error(f"Error while parsing {self.artifact} from {self.evidence_id}")
            logger.error(e)
            return

        self.records.append(
            Record(
                schema=AutoRunRecord,
                record=runkeys,  # record is a generator
            )
        )

    def runkeys(self):
        """Iterate various run key locations. See source for all locations.

        Run keys (Run and RunOnce) are registry keys that make a program run when a user logs on. a Run key runs every
        time the user logs on and the RunOnce key makes the program run once and deletes the key after. Often leveraged
        as a persistence mechanism.

        Sources:
            - https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys

        Yields RunKeyRecords with fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The registry key last modified timestamp.
            name (string): The run key name.
            path (string): The run key path.
            key (string): The source key for this run key.
        """
        for reg_path in self.iter_key():
            for r in self.src.source.registry.keys(reg_path):
                user = self.src.source.registry.get_user(r)
                for entry in r.values():
                    if not (ts := self.ts.to_localtime(r.ts)):
                        ts = self.ts.base_datetime_windows
                    path = uri.from_windows(entry.value)

                    yield AutoRunRecord(
                        ts=ts,
                        name=entry.name,
                        path=path,
                        key=str(reg_path),
                        evidence_id=self.evidence_id,
                    )
