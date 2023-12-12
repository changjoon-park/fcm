import json
from flow.record.fieldtypes import uri
from dissect.target.plugins.os.windows.regf.runkeys import RunKeyRecord
from forensic_artifact import Source, ForensicArtifact


class AutoRun(ForensicArtifact):
    """Plugin that iterates various Runkey locations."""

    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self, descending: bool = False):
        runkeys = sorted(
            [
                json.dumps(
                    record._packdict(), indent=2, default=str, ensure_ascii=False
                )
                for record in self.runkeys()
            ],
            reverse=descending,
        )

        self.result = {
            "runkeys": runkeys,
        }

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
                    ts = self.ts.to_localtime(r.ts)
                    path = uri.from_windows(entry.value)
                    yield RunKeyRecord(
                        ts=ts,
                        name=entry.name,
                        path=path,
                        key=reg_path,
                        _target=self._target,
                        _key=r,
                        _user=user,
                    )
