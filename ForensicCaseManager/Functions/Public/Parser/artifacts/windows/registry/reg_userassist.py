import logging
import codecs
from typing import Optional
from datetime import datetime
from pydantic import ValidationError

from flow.record.fieldtypes import uri
from dissect import cstruct
from dissect.target.exceptions import RegistryValueNotFoundError
from dissect.target.helpers.shell_folder_ids import DESCRIPTIONS

from forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings.artifact_paths import ArtifactSchema
from settings.artifacts import Tables

logger = logging.getLogger(__name__)


userassist_def = """
struct VERSION5_ENTRY {
    char padding[4];
    uint32 number_of_executions;
    uint32 application_focus_count;
    uint32 application_focus_duration;
    char padding[44];
    uint64 timestamp;
    char padding[4];
};

struct VERSION3_ENTRY {
    uint32  session_id;
    uint32  number_of_executions;
    uint64  timestamp;
};
"""
c_userassist = cstruct.cstruct()
c_userassist.load(userassist_def)


class UserAssistRecord(ArtifactRecord):
    """UserAssist registry record."""

    ts: datetime
    path: str
    number_of_executions: Optional[int]
    application_focus_count: Optional[int]
    application_focus_duration: Optional[int]

    class Config:
        table_name: str = Tables.REG_USERASSIST.value


class UserAssist(ForensicArtifact):
    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    def parse(self, descending: bool = False):
        try:
            userassist = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.userassist())
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
        except Exception as e:
            self.log_error(e)
            return

        self.records.append(userassist)

    def userassist(self):
        """Return the UserAssist information for each user.

        The UserAssist registry keys contain information about programs that were recently executed on the system.
        Programs launch via the commandline are not registered within these registry keys.

        Sources:
            - https://www.magnetforensics.com/blog/artifact-profile-userassist/
            - https://www.aldeid.com/wiki/Windows-userassist-keys

        Yields UserAssistRecords with fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The entry timestamp.
            path (uri): The entry path.
            number_of_executions (int): The number of executions for this entry.
            application_focus_count (int): The number of focus acount for this entry.
            application_focus_duration (int): The duration of focus for this entry.
        """
        for reg_path in self.iter_entry():
            for reg in self.src.source.registry.keys(reg_path):
                user = self.src.source.registry.get_user(reg)
                for subkey in reg.subkeys():
                    try:
                        version = subkey.value("Version").value
                    except RegistryValueNotFoundError:
                        version = None

                    for count in subkey.subkeys():
                        for entry in count.values():
                            timestamp = 0
                            number_of_executions = None
                            application_focus_count = None
                            application_focus_duration = None

                            if version == 5 and len(entry.value) == 72:
                                data = c_userassist.VERSION5_ENTRY(entry.value)
                                timestamp = data.timestamp
                                number_of_executions = data.number_of_executions
                                application_focus_count = data.application_focus_count
                                application_focus_duration = (
                                    data.application_focus_duration
                                )
                            elif version == 3 and len(entry.value) == 16:
                                data = c_userassist.VERSION3_ENTRY(entry.value)
                                timestamp = data.timestamp
                                number_of_executions = data.number_of_executions
                            elif version == 3 and len(entry.value) == 8:
                                # Unknown format?
                                pass
                            elif version is None and len(entry.value) == 16:
                                # Unknown format?
                                pass
                            else:
                                logger.debug(
                                    "Invalid userassist value of length %d: %r",
                                    len(entry.value),
                                    entry.value,
                                )
                                continue

                            value = uri.from_windows(
                                codecs.decode(entry.name, "rot-13")
                            )
                            parts = value.split("/")

                            try:
                                value = value.replace(
                                    parts[0], DESCRIPTIONS[parts[0][1:-1].lower()]
                                )
                            except KeyError:
                                pass

                            if not (ts := self.ts.wintimestamp(timestamp)):
                                ts = self.ts.base_datetime_windows

                            parsed_data = {
                                "ts": ts,
                                "path": value,
                                "number_of_executions": number_of_executions,
                                "application_focus_count": application_focus_count,
                                "application_focus_duration": application_focus_duration,
                                "evidence_id": self.evidence_id,
                            }

                            try:
                                yield UserAssistRecord(**parsed_data)
                            except ValidationError as e:
                                self.log_error(e)
                                continue
