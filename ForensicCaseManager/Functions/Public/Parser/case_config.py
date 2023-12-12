import uuid
from dataclasses import dataclass, field
from pathlib import Path

from database_manager import DatabaseManager
from settings import DATABASE_NAME


@dataclass(kw_only=True)
class CaseConfig:
    root_directory: Path
    case_name: str
    case_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    database: Path = field(init=False)
    db_manager: DatabaseManager = field(init=False)

    def __post_init__(self):
        self.database = self.root_directory / self.case_name / DATABASE_NAME
        self.db_manager = DatabaseManager(database=self.database)
