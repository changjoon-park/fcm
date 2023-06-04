import json
from flow.record.fieldtypes import uri

from dissect.target.plugins.os.windows.regf.bam import (
    c_bam,
    BamDamRecord,
)

from forensic_artifact import Source, ForensicArtifact

class BAM(ForensicArtifact):
    """Plugin for bam/dam registry keys."""

    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(
            src=src,
            artifact=artifact,
            category=category
        )

    def parse(self, descending: bool = False):
        bam = sorted([
            json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
            for record in self.bam()], reverse=descending)
                    
        self.result = {
            "bam": bam,
        }
        
    def bam(self):
        """Parse bam and dam registry keys.

        Yields BamDamRecords with fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): The parsed timestamp.
            path (uri): The parsed path.
        """
        for reg_path in self._iter_key():
            for r in self.src.source.registry.keys(reg_path):
                for sub in r.subkeys():
                    for entry in sub.values():
                        if isinstance(entry.value, int):
                            continue

                        data = c_bam.entry(entry.value)
                        yield BamDamRecord(
                            ts=self.ts.wintimestamp(data.ts),
                            path=uri.from_windows(entry.name),
                            _target=self._target,
                        )
