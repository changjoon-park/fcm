import sqlite3
import json
import logging
from typing import Generator, get_type_hints
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass

from core.forensic_artifact import ArtifactRecord, ArtifactRecord
from settings.plugins import ARTIFACT_CATEGORIES
from settings.config import (
    TABLE_NAME_FORENSIC_CASE,
    TABLE_NAME_EVIDENCES,
    TABLE_NAME_ARTIFACT_CATEGORY,
)

logger = logging.getLogger(__name__)


@contextmanager
def open_db(db_path: Path):
    try:
        conn = sqlite3.connect(db_path)
        yield conn.cursor()
    except Exception as e:
        logger.error(f"Error: connect to database {db_path} / failed: {e}")
    finally:
        conn.commit()
        conn.close()


@dataclass(kw_only=True)
class DatabaseManager:
    database: Path

    def __post_init__(self):
        pass

    def is_table_exist(self, table_name: str) -> bool:
        with open_db(self.database) as cursor:
            cursor.execute(
                """
            SELECT name
            FROM sqlite_master
            WHERE type='table' AND name=?
            """,
                (table_name,),
            )
            return cursor.fetchone() is not None

    # create/insert forensic_case table
    def create_forensic_case_table(self):
        if not self.is_table_exist(TABLE_NAME_FORENSIC_CASE):
            with open_db(self.database) as cursor:
                cursor.execute(
                    f"""
                CREATE TABLE IF NOT EXISTS {TABLE_NAME_FORENSIC_CASE} (
                    id TEXT PRIMARY KEY,
                    case_name TEXT NOT NULL,
                    case_directory TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
                )
                """
                )

    def insert_forensic_case(
        self,
        id: str,
        case_name: str,
        case_directory: str,
    ) -> bool:
        with open_db(self.database) as cursor:
            cursor.execute(
                f"""
            INSERT INTO {TABLE_NAME_FORENSIC_CASE} (id, case_name, case_directory)
            VALUES (?, ?, ?)
            """,
                (
                    id,
                    case_name,
                    case_directory,
                ),
            )
            return True

    # create/insert evidences table
    def create_evidences_table(self):
        with open_db(self.database) as cursor:
            cursor.execute(
                f"""
            CREATE TABLE IF NOT EXISTS {TABLE_NAME_EVIDENCES} (
                id TEXT NOT NULL PRIMARY KEY,
                evidence_label TEXT NOT NULL,
                computer_name TEXT,
                registered_owner TEXT,
                source TEXT NOT NULL,
                session_id TEXT NOT NULL,
                evidence_number INTEGER NOT NULL,
                FOREIGN KEY (session_id) REFERENCES {TABLE_NAME_FORENSIC_CASE} (id)
            )
            """
            )

    def insert_evidences(
        self,
        id: str,
        evidence_label: str,
        computer_name: str,
        registered_owner: str,
        source: str,
        session_id: str,
        evidence_number: int,
    ) -> bool:
        with open_db(self.database) as cursor:
            cursor.execute(
                f"""
            INSERT INTO {TABLE_NAME_EVIDENCES} (
                id,
                evidence_label, 
                computer_name, 
                registered_owner, 
                source, 
                session_id,
                evidence_number)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    id,
                    evidence_label,
                    computer_name,
                    registered_owner,
                    source,
                    session_id,
                    evidence_number,
                ),
            )
            return True

    # create/insert artifact category table
    def create_artifact_category_table(self):
        with open_db(self.database) as cursor:
            cursor.execute(
                f"""
            CREATE TABLE IF NOT EXISTS {TABLE_NAME_ARTIFACT_CATEGORY} (
                id INTEGER PRIMARY KEY,
                category TEXT NOT NULL
            )"""
            )
            for id, category in ARTIFACT_CATEGORIES:
                cursor.execute(
                    f"""
                INSERT INTO {TABLE_NAME_ARTIFACT_CATEGORY} (id, category)
                VALUES (?, ?)
                """,
                    (
                        id,
                        category,
                    ),
                )

    def create_artifact_table(self, record: list[ArtifactRecord], evidence_id: str):
        if not isinstance(record, list):
            logger.error(f"Error: record must be a list, not {type(record)}")
            return

        model = record[0]
        full_annotations = self._get_full_annotations(model)
        table_name = model.Config.table_name
        try:
            # Extracting table name and column definitions from the Pydantic model
            columns = []
            for field_name, field_type in full_annotations.items():
                column_type = "TEXT"  # Default type, adjust as needed
                if field_type == int:
                    column_type = "INTEGER"
                elif field_type == float:
                    column_type = "REAL"
                elif field_type == bool:
                    column_type = "BOOLEAN"
                elif field_type == datetime:
                    column_type = "DATETIME"
                # Add more data types as necessary
                columns.append(f"{field_name} {column_type}")

            column_definitions = ", ".join(columns)

            # Constructing the CREATE TABLE SQL statement
            create_statement = (
                f"CREATE TABLE IF NOT EXISTS {table_name} ({column_definitions})"
            )

            # Creating the table
            with open_db(self.database) as cursor:
                cursor.execute(create_statement)

        except Exception as e:
            logger.exception(
                f"Failed to create table {table_name} to {evidence_id}: {e}"
            )

    def _get_full_annotations(self, model):
        annotations = {}
        for cls in reversed(model.__class__.mro()):
            if cls is object:
                continue
            annotations.update(get_type_hints(cls))
        return annotations

    def insert_artifact_data(
        self, record: Generator[ArtifactRecord, None, None], evidence_id: str
    ):
        try:
            all_records = []
            table_name = None
            keys = None

            # Accumulate all records
            for data in record:
                table_name, prepared_data, keys = self._prepare_record_data(data)
                all_records.append(prepared_data)

            # Perform batch insertion if there are records to insert
            if all_records:
                statement = self._prepare_insert_statement(table_name, keys)
                with open_db(self.database) as cursor:
                    cursor.executemany(statement, all_records)
                    logger.info(
                        f"Inserted {len(all_records)} entries into {table_name} table in {evidence_id}"
                    )

        except Exception as e:
            logger.exception(f"Error inserting data into table: {e}")

    def _prepare_record_data(self, data):
        table_name = data.Config.table_name
        processed_record = self._process_record_data(data.model_dump())
        keys = list(processed_record.keys())  # Ensure keys are extracted here
        return table_name, tuple(processed_record.values()), keys

    def _process_record_data(self, record_data):
        return {
            key: json.dumps(
                [v.isoformat() if isinstance(v, datetime) else v for v in value]
            )
            if isinstance(value, list)
            else value
            for key, value in record_data.items()
        }

    def _prepare_insert_statement(self, table_name, keys):
        placeholders = ", ".join(["?"] * len(keys))
        return f"INSERT INTO {table_name} ({', '.join(keys)}) VALUES ({placeholders})"
