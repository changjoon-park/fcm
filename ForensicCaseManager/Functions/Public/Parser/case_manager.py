import logging
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from forensic_base import ForensicBase


@dataclass(kw_only=True)
class CaseManager(ForensicBase):
    case_name: str
    forensic_evidences: list

    def __post_init__(self):
        super().__post_init__()

        # set case_directory
        self.case_directory = self.root_directory / self.case_name

        # set case_id to forensic_evidences
        for evidence in self.forensic_evidences:
            evidence.case_id = self.case_id

    def investigate_case(self):
        # create case directory
        self._create_case_directory()

        # initialize database
        self._init_database()

        # parse artifacts in all forensic evidences
        self._parse_case_artifacts()

        # export artifacts in all forensic evidences
        self._export_case_artifacts()

    def _create_case_directory(self):
        try:
            self.case_directory.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logging.exception(f"Error: {e}")

    def _init_database(self):
        # set forensic case table
        self._init_table_forensic_case()

        # set evidences table
        self._init_table_evidences()

        # set artifact category table
        self._init_table_artifact_category()

    def _init_table_forensic_case(self):
        self.db_manager.connect()

        # create forensic_case table
        if not self.db_manager.is_table_exist("forensic_case"):
            self.db_manager.create_forensic_case_table()

        # insert forensic_case data
        self.db_manager.insert_forensic_case(
            id=self.case_id,
            case_name=self.case_name,
            case_directory=str(self.case_directory),
        )
        self.db_manager.close()

    def _init_table_evidences(self):
        for evidence in self.forensic_evidences:
            self.db_manager.connect()
            # create "evidences" table
            if not self.db_manager.is_table_exist("evidences"):
                self.db_manager.create_evidences_table()

            # insert "evidences" table
            self.db_manager.insert_evidences(
                id=evidence.evidence_id,
                evidence_label=evidence.evidence_label,
                computer_name=evidence.computer_name,
                registered_owner=evidence.registered_owner,
                source=evidence.src.source_path,
                case_id=self.case_id,
                evidence_number=evidence.evidence_number,
            )
            self.db_manager.close()

    def _init_table_artifact_category(self):
        self.db_manager.connect()
        if not self.db_manager.is_table_exist("artifact_category"):
            self.db_manager.create_artifact_category_table()
            for id, category in self.ARTIFACT_CATEGORIES:
                self.db_manager.insert_artifact_category(
                    id=id,
                    category=category,
                )
        self.db_manager.close()

    def _parse_case_artifacts(self):
        for forensic_evidence in self.forensic_evidences:
            forensic_evidence.parse_evidence(descending=False)

    def _export_case_artifacts(self):
        for forensic_evidence in self.forensic_evidences:
            forensic_evidence.export_evidence(
                evidence_id=forensic_evidence.evidence_id,
            )
