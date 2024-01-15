import logging
from pathlib import Path
from dataclasses import dataclass

from settings.plugins import ARTIFACT_CATEGORIES

from case_config import CaseConfig
from forensic_evidence import ForensicEvidence

logger = logging.getLogger(__name__)


@dataclass(kw_only=True)
class ForensicCase(CaseConfig):
    case_directory: Path
    forensic_evidences: list[ForensicEvidence]

    def __post_init__(self):
        super().__post_init__()

    def investigate_case(self):
        # # create case directory
        # self._create_case_directory()

        # initialize database
        self._init_database()

        # parse artifacts in all forensic evidences
        self._parse_evidences_all()

        # export artifacts in all forensic evidences
        self._export_evidences_all()

    # def _create_case_directory(self):
    #     try:
    #         self.case_directory.mkdir(parents=True, exist_ok=True)
    #     except Exception as e:
    #         logger.exception(f"Unable to create case directory: {e}")

    def _init_database(self):
        # set forensic case table
        self._init_table_forensic_case()

        # set evidences table
        self._init_table_evidences()

        # TODO: Make a connection to the Artifacts
        # set artifact category table
        # self._init_table_artifact_category()

    def _init_table_forensic_case(self):
        # create forensic_case table
        self.db_manager.create_forensic_case_table()

        # insert forensic_case data
        self.db_manager.insert_forensic_case(
            id=self.session_id,
            case_name=self.case_name,
            case_directory=str(self.case_directory),
        )

    def _init_table_evidences(self):
        for forensic_evidence in self.forensic_evidences:
            # create "evidences" table
            if not self.db_manager.is_table_exist("evidences"):
                self.db_manager.create_evidences_table()

            # insert "evidences" table
            if self.db_manager.insert_evidences(
                id=forensic_evidence.evidence_id,
                evidence_label=forensic_evidence.evidence_label,
                computer_name=forensic_evidence.computer_name,
                registered_owner=forensic_evidence.registered_owner,
                source=forensic_evidence.src.source_path,
                session_id=self.session_id,
                evidence_number=forensic_evidence._evidence_number,
            ):
                logger.info(
                    f"Inserted {forensic_evidence.evidence_id} into evidences table in {self.case_name} case"
                )

    def _init_table_artifact_category(self):
        self.db_manager.create_artifact_category_table()

    def _parse_evidences_all(self):
        for forensic_evidence in self.forensic_evidences:
            forensic_evidence.parse_evidence(descending=False)

    def _export_evidences_all(self):
        for forensic_evidence in self.forensic_evidences:
            forensic_evidence.export_evidence()
