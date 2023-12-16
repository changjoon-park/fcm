import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from database_manager import DatabaseManager
from settings import DATABASE_NAME


def get_session_id(case_name: str) -> str:
    current_time = datetime.now().isoformat()
    return f"{case_name}_{current_time}"


@dataclass(kw_only=True)
class CaseConfig:
    case_directory: Path
    case_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_name: str = field(init=False)
    session_id: str = field(init=False)
    database: Path = field(init=False)
    db_manager: DatabaseManager = field(init=False)

    def __post_init__(self):
        self.case_name = self.case_directory.name
        self.case_id = get_session_id(self.case_name)
        self.database = self.case_directory / DATABASE_NAME
        self.db_manager = DatabaseManager(database=self.database)
