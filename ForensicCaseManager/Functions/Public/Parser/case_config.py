import uuid
from dataclasses import dataclass, field
from pathlib import Path

from database_manager import DatabaseManager
from schema.artifact_schema import ARTIFACT_SCHEMA


@dataclass(kw_only=True)
class CaseConfig:
    root_directory: Path
    case_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_name: str
    database: Path = field(init=False)
    db_manager: DatabaseManager = field(init=False)

    # Class-level constant for database name
    DATABASE_NAME = "forensic_data.sqlite"

    # Class-level constant for artifact schema
    ARTIFACT_SCHEMA = ARTIFACT_SCHEMA

    # Class-level constant for artifact categories
    ARTIFACT_CATEGORIES = [
        (1, "APPLICATION_EXECUTION"),
        (2, "FILE_FOLDER_OPENING"),
        (3, "DELETED_ITEMS_FILE_EXISTENCE"),
        (4, "BROWSER_ACTIVITY"),
        (5, "CLOUD_STORAGE"),
        (6, "ACCOUNT_USAGE"),
        (7, "NETWORK_ACTIVITY_PHYSICAL_LOCATION"),
        (8, "SYSTEM_INFORMATION"),
        (9, "EXTERNAL_DEVICE_USB_USAGE"),
    ]

    def __post_init__(self):
        self.database = self.root_directory / self.case_name / self.DATABASE_NAME
        self.db_manager = DatabaseManager(database=self.database)
