from datetime import datetime
from pydantic import ValidationError

from flow.record.fieldtypes import uri
from dissect.cstruct import cstruct

from forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings.artifact_paths import ArtifactSchema
from settings.artifacts import Tables

c_bamdef = """
    struct entry {
        uint64 ts;
    };
    """
c_bam = cstruct()
c_bam.load(c_bamdef)


class BamRecord(ArtifactRecord):
    """Bam registry record."""

    ts: datetime
    path: str

    class Config:
        table_name: str = Tables.REG_BAM.value


class BAM(ForensicArtifact):
    """Plugin for bam/dam registry keys."""

    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    def parse(self, descending: bool = False):
        try:
            bam = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.bam())
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
        except Exception as e:
            self.log_error(e)
            return

        self.records.append(bam)

    def bam(self):
        """Parse bam and dam registry keys.

        Yields BamDamRecords with fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The parsed timestamp.
            path (uri): The parsed path.
        """
        for reg_path in self.iter_entry():
            for r in self.src.source.registry.keys(reg_path):
                for sub in r.subkeys():
                    for entry in sub.values():
                        if isinstance(entry.value, int):
                            continue

                        data = c_bam.entry(entry.value)

                        if not (ts := self.ts.wintimestamp(data.ts)):
                            ts = self.ts.base_datetime_windows

                        parsed_data = {
                            "ts": ts,
                            "path": str(uri.from_windows(entry.name)),
                            "evidence_id": self.evidence_id,
                        }

                        try:
                            yield BamRecord(**parsed_data)
                        except ValidationError as e:
                            self.log_error(e)
                            continue
