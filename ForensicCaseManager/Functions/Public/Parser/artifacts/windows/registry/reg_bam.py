import logging
from datetime import datetime

from flow.record.fieldtypes import uri
from dissect.cstruct import cstruct

from forensic_artifact import Source, ArtifactRecord, ForensicArtifact, Record
from settings.artifact_paths import ArtifactSchema

logger = logging.getLogger(__name__)

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
    evidence_id: str

    class Config:
        record_name: str = "reg_bam"


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
            )
        except Exception as e:
            logger.error(f"Error while parsing {self.name} from {self.evidence_id}")
            logger.error(e)
            return

        self.records.append(
            Record(
                schema=BamRecord,
                record=bam,  # record is a generator
            )
        )

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

                        yield BamRecord(
                            ts=ts,
                            path=str(uri.from_windows(entry.name)),
                            evidence_id=self.evidence_id,
                        )
