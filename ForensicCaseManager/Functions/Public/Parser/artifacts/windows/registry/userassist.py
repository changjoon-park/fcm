import codecs
import json

from flow.record.fieldtypes import uri

from dissect.target.exceptions import RegistryValueNotFoundError
from dissect.target.helpers.shell_folder_ids import DESCRIPTIONS
from dissect.target.plugins.os.windows.regf.userassist import (
    c_userassist,
    UserAssistRecord,
)

from forensic_artifact import Source, ForensicArtifact


class UserAssist(ForensicArtifact):
    """UserAssist plugin."""

    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self, descending: bool = False):
        userassist = sorted(
            [
                json.dumps(
                    record._packdict(), indent=2, default=str, ensure_ascii=False
                )
                for record in self.userassist()
            ],
            reverse=descending,
        )

        self.result = {
            "userassist": userassist,
        }

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
        for reg_path in self._iter_key():
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

                            yield UserAssistRecord(
                                ts=self.ts.wintimestamp(timestamp),
                                path=value,
                                number_of_executions=number_of_executions,
                                application_focus_count=application_focus_count,
                                application_focus_duration=application_focus_duration,
                                _target=self._target,
                                _user=user,
                                _key=count,
                            )
