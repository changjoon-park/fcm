import json

from flow.record.fieldtypes import uri
from dissect.cstruct import cstruct

from forensic_artifact import Source, ForensicArtifact

c_bamdef = """
    struct entry {
        uint64 ts;
    };
    """
c_bam = cstruct()
c_bam.load(c_bamdef)


class BAM(ForensicArtifact):
    """Plugin for bam/dam registry keys."""

    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self, descending: bool = False):
        bam = sorted(
            [
                self.validate_record(index=index, record=record)
                for index, record in enumerate(self.bam())
            ],
            key=lambda record: record["ts"],
            reverse=descending,
        )

    def bam(self):
        """Parse bam and dam registry keys.

        Yields BamDamRecords with fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The parsed timestamp.
            path (uri): The parsed path.
        """
        for reg_path in self.iter_key():
            for r in self.src.source.registry.keys(reg_path):
                for sub in r.subkeys():
                    for entry in sub.values():
                        if isinstance(entry.value, int):
                            continue

                        data = c_bam.entry(entry.value)

                        if not (ts := self.ts.wintimestamp(data.ts)):
                            ts = self.ts.base_datetime_windows

                        yield {
                            "ts": ts,
                            "path": uri.from_windows(entry.name),
                            "evidence_id": self.evidence_id,
                        }
