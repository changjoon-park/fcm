import logging
from dataclasses import dataclass, field
from pathlib import Path

from core.database_manager import DatabaseManager
from settings.config import DATABASE_NAME

logger = logging.getLogger(__name__)


@dataclass(kw_only=True)
class CaseConfig:
    session_id: str
    case_directory: Path
    case_name: str = field(init=False)
    database: Path = field(init=False)
    db_manager: DatabaseManager = field(init=False)

    def __post_init__(self):
        self.case_name = self.case_directory.name
        self.database = self.case_directory / DATABASE_NAME
        self.db_manager = DatabaseManager(database=self.database)
