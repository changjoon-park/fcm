import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

from util.converter import convertfrom_extended_ascii
from pathlib import Path
from forensic_artifact import (
    Source,
    ForensicArtifact,
)
from case_config import CaseConfig

logger = logging.getLogger(__name__)


@dataclass(kw_only=True)
class ForensicEvidence(CaseConfig):
    evidence_number: int
    _local: Optional[bool] = False
    _container: Optional[str] = None
    _artifacts: Optional[list] = None
    _categories: Optional[list] = None
    src: Source = field(init=False)
    forensic_artifacts: list[ForensicArtifact] = field(default_factory=list)

    def __post_init__(self):
        super().__post_init__()

        # set src
        self.src = Source(
            _local=self._local,
            _container=self._container,
        )
        # set forensic_artifacts
        for artifact, plugin in self.PLUGINS.items():
            ForensicArtifact, category = plugin
            if self._artifacts:
                for artifact_entry in self._artifacts:
                    if artifact == artifact_entry:
                        self.forensic_artifacts.append(
                            ForensicArtifact(
                                src=self.src,
                                artifact=artifact,
                                category=category,
                            )
                        )
            if self._categories:
                for category_entry in self._categories:
                    if category == category_entry:
                        self.forensic_artifacts.append(
                            ForensicArtifact(
                                src=self.src,
                                artifact=artifact,
                                category=category,
                            )
                        )
            # # set evidence_id to forensic_artifacts
            # for artifact in self.forensic_artifacts:
            #     artifact.evidence_id = self.evidence_id

    @property
    def case_id(self):
        return self._case_id

    @case_id.setter
    def case_id(self, value):
        self._case_id = value

    @property
    def evidence_id(self):
        evidence_id = [
            str(self.case_id),
            str(self.evidence_number),
        ]
        return "-".join(evidence_id)

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

    def parse_evidence(self, descending: bool = False) -> Path:
        """Return the content of all forensic artifacts."""
        for forensic_artifact in self.forensic_artifacts:
            forensic_artifact.parse(descending=descending)

    def export_evidence(self, evidence_id: str = None) -> None:
        self.db_manager.connect()
        for forensic_artifact in self.forensic_artifacts:
            # create artifact table
            if schema_files := self.ARTIFACT_SCHEMA.get(
                forensic_artifact.artifact,  # ? parameter: ART_ARTIFACT, e.g., 'prefetch', 'sru_network', 'chrome'
            ):
                for schema_file in schema_files:
                    self.db_manager.create_artifact_table_from_yaml(
                        schema_file=schema_file,
                    )
            else:
                logger.error(
                    f"Invalid artifact: Unable to find schema file - {forensic_artifact.artifact} in {evidence_id}"
                )
                continue

            # insert artifact data / result: {name: [data, ...]}
            for artifact, entry_data in forensic_artifact.result.items():
                logger.info(
                    f"{len(entry_data)} {artifact} entries has been parsed from {evidence_id}"
                )
                for index, data in enumerate(entry_data):
                    if type(data) == dict:
                        print(f"{artifact}-{index}: {type(data)} - status OK")
                    else:
                        print(f"{artifact}-{index}: {type(data)} - status: ERROR")
                        logging.error(
                            f"{artifact}-{index}: {type(data)} - status: ERROR"
                        )
                    self.db_manager.insert_artifact_data(
                        artifact=artifact,  # ? parameter: RSLT_ARTIFACT, e.g., 'prefetch', 'sru_network_DATA', 'chrome_history'
                        data=data,
                        evidence_id=evidence_id,
                    )
        self.db_manager.close()
