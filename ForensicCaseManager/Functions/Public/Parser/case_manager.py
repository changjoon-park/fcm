import json
import uuid
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field

from util.converter import convertfrom_extended_ascii
from util.extractor import extract_basename
from pathlib import Path
from database_manager import DatabaseManager
from forensic_evidence import ForensicEvidence
from config import DATABASE_NAME, ARTIFACT_CATEGORIES


@dataclass(kw_only=True)
class CaseManager:
    case_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_name: str
    root_directory: Path
    forensic_evidences: list[ForensicEvidence]
    db_manager: DatabaseManager = field(init=False)

    def __post_init__(self):
        self.db_manager = DatabaseManager(database=self.database)

    @property
    def case_directory(self):
        return self.root_directory / self.case_name

    @property
    def database(self):
        return self.root_directory / self.case_name / DATABASE_NAME

    @property
    def case_information(self):
        return {
            "case_name": self.case_name,
            "case_directory": self.root_directory / self.case_name,
            "forensic_evidences": self.forensic_evidences,
            "case_id": self.case_id,
        }

    def investigate_case(self):
        # create case directory
        self._create_case_directory()

        # initialize database
        self._init_database()

        # parse artifacts in all forensic evidences
        self._parse_artifacts_all()

        # export artifacts in all forensic evidences
        self._export_artifacts_all()

    def _create_case_directory(self):
        self.case_directory.mkdir(parents=True, exist_ok=True)

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
                evidence_number=evidence.evidence_number,
                evidence_label=evidence.evidence_label,
                computer_name=evidence.computer_name,
                registered_owner=evidence.registered_owner,
                source=evidence.src.source_path,
                case_id=self.case_id,
            )
            self.db_manager.close()

    def _init_table_artifact_category(self):
        self.db_manager.connect()
        if not self.db_manager.is_table_exist("artifact_category"):
            self.db_manager.create_artifact_category_table()
            for id, category in ARTIFACT_CATEGORIES:
                self.db_manager.insert_artifact_category(
                    id=id,
                    category=category,
                )
        self.db_manager.close()

    def _parse_artifacts_all(self):
        for forensic_evidence in self.forensic_evidences:
            forensic_evidence.parse_artifacts()

    def _export_artifacts_all(self):
        for forensic_evidence in self.forensic_evidences:
            forensic_evidence.export_artifacts(db_manager=self.db_manager)
