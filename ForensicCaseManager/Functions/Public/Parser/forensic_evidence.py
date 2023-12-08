import logging
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field

from util.converter import convertfrom_extended_ascii
from util.extractor import extract_basename
from pathlib import Path
from plugins import PLUGINS
from forensic_artifact import (
    Source,
    ForensicArtifact,
)
from database_manager import DatabaseManager


@dataclass(kw_only=True)
class ForensicEvidence:
    evidence_number: int
    _local: Optional[bool] = False
    _container: Optional[str] = None
    _artifacts: Optional[list] = None
    _categories: Optional[list] = None
    src: Source = field(init=False)
    forensic_artifacts: list[ForensicArtifact] = field(default_factory=list)

    def __post_init__(self):
        self.src = Source(
            _local=self._local,
            _container=self._container,
        )
        # set forensic_artifacts
        for artifact, plugin in PLUGINS.items():
            ForensicArtifact, category = plugin
            if self._artifacts:
                for artifact_entry in self._artifacts:
                    if artifact == artifact_entry:
                        self.forensic_artifacts.append(
                            ForensicArtifact(
                                src=self.src, artifact=artifact, category=category
                            )
                        )
            if self._categories:
                for category_entry in self._categories:
                    if category == category_entry:
                        self.forensic_artifacts.append(
                            ForensicArtifact(
                                src=self.src, artifact=artifact, category=category
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
        return extract_basename(path=self.src.source_path)

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
                string=computer_name, encoding="UTF-16-LE"
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
                string=registered_owner, encoding="UTF-16-LE"
            )

    @property
    def evidence_information(self):
        return {
            "evidence_label": self._evidence_label,
            "computer_name": self._computer_name,
            "registered_owner": self._registered_owner,
            "forensic_artifacts": self.forensic_artifacts,
        }
