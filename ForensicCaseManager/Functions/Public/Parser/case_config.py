import uuid
from dataclasses import dataclass, field
from pathlib import Path

from database_manager import DatabaseManager
from lib.plugins import ARTIFACT_SCHEMA, WINDOWS_PLUGINS, ARTIFACT_CATEGORIES
from settings import DATABASE_NAME


@dataclass(kw_only=True)
class CaseConfig:
    root_directory: Path
    case_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_name: str
    database: Path = field(init=False)
    db_manager: DatabaseManager = field(init=False)

    # Class-level constant for database name
    DATABASE_NAME = DATABASE_NAME

    # Class-level constant for artifact categories
    ARTIFACT_CATEGORIES = ARTIFACT_CATEGORIES

    # Class-level constant for artifact schema
    ARTIFACT_SCHEMA = ARTIFACT_SCHEMA

    # Class-level constant for plugins
    PLUGINS = WINDOWS_PLUGINS

    def __post_init__(self):
        self.database = self.root_directory / self.case_name / self.DATABASE_NAME
        self.db_manager = DatabaseManager(database=self.database)
