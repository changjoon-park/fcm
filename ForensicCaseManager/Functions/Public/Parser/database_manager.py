import sqlite3
import yaml
import json
import logging
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(kw_only=True)
class DatabaseManager:
    database: Path

    def __post_init__(self):
        pass

    def connect(self):
        try:
            self.conn = sqlite3.connect(self.database)
            self.c = self.conn.cursor()
        except Exception as e:
            logger.error(f"Error: connect to database {self.database} / failed: {e}")

    def close(self):
        self.conn.close()

    def is_table_exist(self, table_name: str) -> bool:
        try:
            with self.conn:
                self.c.execute(
                    """
                SELECT name
                FROM sqlite_master
                WHERE type='table' AND name=?
                """,
                    (table_name,),
                )
                return self.c.fetchone() is not None
        except Exception as e:
            logger.error(f"Error: {e}")

    # create/insert forensic_case table
    def create_forensic_case_table(self):
        try:
            with self.conn:
                self.c.execute(
                    """
                CREATE TABLE IF NOT EXISTS forensic_case (
                    id TEXT PRIMARY KEY,
                    case_name TEXT NOT NULL,
                    case_directory TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
                """
                )
        except Exception as e:
            logger.error(f"Error: {e}")

    def insert_forensic_case(
        self,
        id: str,
        case_name: str,
        case_directory: str,
    ):
        try:
            with self.conn:
                self.c.execute(
                    """
                INSERT INTO forensic_case (id, case_name, case_directory)
                VALUES (?, ?, ?)
                """,
                    (
                        id,
                        case_name,
                        case_directory,
                    ),
                )
        except Exception as e:
            logger.error(f"Error: {e}")

    # create/insert evidences table
    def create_evidences_table(self):
        try:
            with self.conn:
                self.c.execute(
                    """
                CREATE TABLE IF NOT EXISTS evidences (
                    id TEXT NOT NULL PRIMARY KEY,
                    evidence_label TEXT NOT NULL,
                    computer_name TEXT,
                    registered_owner TEXT,
                    source TEXT NOT NULL,
                    case_id TEXT NOT NULL,
                    evidence_number INTEGER NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES forensic_case (id)
                )
                """
                )
        except Exception as e:
            logger.error(f"Error: {e}")

    def insert_evidences(
        self,
        id: str,
        evidence_label: str,
        computer_name: str,
        registered_owner: str,
        source: str,
        case_id: str,
        evidence_number: int,
    ):
        try:
            with self.conn:
                self.c.execute(
                    """
                INSERT INTO evidences (
                    id,
                    evidence_label, 
                    computer_name, 
                    registered_owner, 
                    source, 
                    case_id,
                    evidence_number)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        id,
                        evidence_label,
                        computer_name,
                        registered_owner,
                        source,
                        case_id,
                        evidence_number,
                    ),
                )
        except Exception as e:
            logger.exception(f"Error: Unable to insert evidences table: {e}")

    # create/insert artifact category table
    def create_artifact_category_table(self):
        try:
            with self.conn:
                self.c.execute(
                    """
                CREATE TABLE IF NOT EXISTS artifact_category (
                    id INTEGER PRIMARY KEY,
                    category TEXT NOT NULL
                )"""
                )
        except Exception as e:
            logger.exception(f"Error: Unable to create artifact_category table: {e}")

    def insert_artifact_category(self, id: int, category: str):
        try:
            with self.conn:
                self.c.execute(
                    """
                INSERT INTO artifact_category (id, category)
                VALUES (?, ?)
                """,
                    (
                        id,
                        category,
                    ),
                )
        except Exception as e:
            logger.exception(f"Error: Unable to insert artifact_category table: {e}")

    # create/insert artifact table
    def create_artifact_table_from_yaml(self, yaml_file: Path):
        try:
            with open(yaml_file, "r", encoding="utf-8") as f:
                schema = yaml.load(f, Loader=yaml.FullLoader)
                for table in schema.get("Table", []):
                    table_name = table.get("TableName")
                    columns = table.get("Columns", [])
                    types = table.get("Types", [])

                    column_defs = ",".join(
                        [f"{column} {type[0]}" for column, type in zip(columns, types)]
                    )
                    create_statement = (
                        f"CREATE TABLE IF NOT EXISTS {table_name} ({column_defs})"
                    )
                    with self.conn:
                        self.c.execute(create_statement)
        except Exception as e:
            logger.exception(f"Error: Unable to create artifact table: {e}")

    def insert_artifact_data(self, artifact: str, data: dict, evidence_id: str):
        try:
            # convert python data type to sqlite data type
            for attribute, value in data.items():
                if type(value) == list:
                    for i, v in enumerate(value):
                        if type(v) == datetime:
                            value[i] = v.isoformat()
                    data[attribute] = json.dumps(value)

            # add evidence_id
            data["evidence_id"] = evidence_id

            with self.conn:
                self.c.execute(
                    f"""
                INSERT INTO {artifact} ({','.join(data.keys())})
                VALUES ({','.join(['?'] * len(data.keys()))})
                """,
                    tuple(data.values()),
                )
        except Exception as e:
            logger.exception(f"Error: Unable to insert artifact data: {e}")
