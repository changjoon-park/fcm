import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field
from icecream import ic

from util.converter import convertfrom_extended_ascii
from pathlib import Path
from forensic_artifact import Source, ForensicArtifact
from case_config import CaseConfig
from settings.plugins import WINDOWS_PLUGINS
from settings.artifact_paths import ArtifactSchema

logger = logging.getLogger(__name__)


@dataclass(kw_only=True)
class ForensicEvidence(CaseConfig):
    _evidence_number: int
    _evidence: Optional[str] = None
    _artifacts: Optional[list] = None
    _categories: Optional[list] = None
    src: Source = field(init=False)
    evidence_id: str = field(init=False)
    forensic_artifacts: list[ForensicArtifact] = field(default_factory=list)

    def __post_init__(self):
        super().__post_init__()

        # set src
        self.src = Source(_evidence=self._evidence)

        # set evidence_id
        self.evidence_id = "-".join([str(self.session_id), str(self._evidence_number)])

        # set forensic_artifacts
        for plugin_name, plugin in WINDOWS_PLUGINS.items():
            ForensicArtifact, category = plugin
            if self._artifacts:
                for artifact_name in self._artifacts:
                    if plugin_name == artifact_name:
                        self.forensic_artifacts.append(
                            ForensicArtifact(
                                src=self.src,
                                schema=ArtifactSchema(
                                    name=artifact_name,
                                    category=category,
                                ),
                            )
                        )
            if self._categories:
                for category_entry in self._categories:
                    if category == category_entry:
                        self.forensic_artifacts.append(
                            ForensicArtifact(
                                src=self.src,
                                schema=ArtifactSchema(
                                    name=plugin_name,
                                    category=category,
                                ),
                            )
                        )

        # set forensic_artifacts properties
        for forensic_artifact in self.forensic_artifacts:
            forensic_artifact.evidence_id = self.evidence_id

    @property
    def evidence_label(self):
        return Path(self.src.source_path).stem

    @property
    def computer_name(self):
        computer_name = self.src.source.name
        try:
            # 'ComputerName' Registry value is stored by "UTF-16" encoding
            # However, dissect module reads the data by "Extended ASCII" encoding. That occurs error
            # Moreover, dissect module removes 'null value' from original bytes when decoding
            # This makes it difficult to deal with combined-characters (ex. 한s -> unicode, ascii)
            _ = computer_name.encode(
                "ASCII"
            )  # ! test if the name's each character is ascii (not extended)
            return computer_name
        except:
            return convertfrom_extended_ascii(
                string=computer_name,
                encoding="UTF-16-LE",
            )

    @property
    def registered_owner(self):
        reg_path = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        registered_owner = (
            self.src.source.registry.key(reg_path).value("RegisteredOwner").value
        )
        try:
            _ = registered_owner.encode("ASCII")
            return registered_owner
        except:
            return convertfrom_extended_ascii(
                string=registered_owner,
                encoding="UTF-16-LE",
            )

    def parse_evidence(self, descending: bool = False) -> None:
        """Return the content of all forensic artifacts."""
        for forensic_artifact in self.forensic_artifacts:
            forensic_artifact.parse(descending=descending)

    def export_evidence(self) -> None:
        for forensic_artifact in self.forensic_artifacts:
            for record in forensic_artifact.records:
                # create artifact table
                self.db_manager.create_artifact_table(record)

                # insert artifact data
                self.db_manager.insert_artifact_data(
                    record=record
                )  # ! record is a generator[Pydantic Model]
