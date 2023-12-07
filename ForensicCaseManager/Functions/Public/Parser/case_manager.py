import json
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field

from util.converter import convertfrom_extended_ascii
from util.extractor import extract_basename
from pathlib import Path
from forensic_artifact import (
    SOURCE_TYPE_CONTAINER,
    SOURCE_TYPE_LOCAL,
)
from database_manager import DatabaseManager
from forensic_evidence import ForensicEvidence
from config import DATABASE_NAME, ARTIFACT_CATEGORIES


@dataclass(kw_only=True)
class CaseManager:
    case_name: str
    root_directory: Path
    forensic_evidences: list[ForensicEvidence] = field(default_factory=list)
    db_manager: DatabaseManager = field(init=False)

    def __post_init__(self):
        self.db_manager = DatabaseManager(database=self.database)
        self.investigate_case()

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
        }

    def _create_case_directory(self):
        self.case_directory.mkdir(parents=True, exist_ok=True)

    def _database_init(self):
        # connect to database
        self.db_manager.connect()

        # create/insert "category" table
        if not self.db_manager.is_table_exist("category"):
            self.db_manager.create_category_table()
            for id, category in ARTIFACT_CATEGORIES:
                self.db_manager.insert_category(
                    id=id,
                    category=category,
                )

        # create "session_data" table
        if not self.db_manager.is_table_exist("session_data"):
            self.db_manager.create_session_data_table()

        # close database
        self.db_manager.close()

    def _export_evidence_information(self):
        self.db_manager.connect()
        for forensic_evidence in self.forensic_evidences:
            # create "case_information" table
            if not self.db_manager.is_table_exist("case_information"):
                self.db_manager.create_evidence_information_table()

            self.db_manager.insert_evidence_information(
                evidence_label=forensic_evidence._evidence_label,
                computer_name=forensic_evidence._computer_name,
                registered_owner=forensic_evidence._registered_owner,
                source=forensic_evidence.src.source_path,
            )
            self.db_manager.close()

    def _parse_evidence_artifacts(self):
        for forensic_evidence in self.forensic_evidences:
            forensic_evidence.parse_all()

    def _export_evidence_artifacts(self):
        for forensic_evidence in self.forensic_evidences:
            forensic_evidence.export_all(db_manager=self.db_manager)

    def investigate_case(self):
        self._create_case_directory()
        self._database_init()
        self._export_evidence_information()
        self._parse_evidence_artifacts()
        self._export_evidence_artifacts()
