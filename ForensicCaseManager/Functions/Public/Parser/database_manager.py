import sqlite3
import yaml
import json
import logging
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass

from forensic_artifact import ArtifactRecord
from lib.plugins import ARTIFACT_CATEGORIES
from settings import (
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

    def create_artifact_table_from_yaml(self, schema_file: Path):
        if not schema_file or not schema_file.exists():
            logger.error(f"Schema file {schema_file} does not exist")
            return

        try:
            with open(schema_file, "r", encoding="utf-8") as f:
                schema = yaml.load(f, Loader=yaml.FullLoader)

            table_info = schema.get("Table", {})
            table_name = table_info.get("TableName")
            if not table_name:
                logger.error("No table name specified in schema")
                return

            column_defs = ", ".join(
                f"{column_name} {column_type}"
                for column in table_info["Columns"]
                for column_name, column_type in column.items()
            )

            create_statement = (
                f"CREATE TABLE IF NOT EXISTS {table_name} ({column_defs})"
            )

            with open_db(self.database) as cursor:
                cursor.execute(create_statement)

        except Exception as e:
            logger.exception(f"Failed to create table {table_name} from YAML: {e}")

    def create_artifact_table_from_pydantic_model(self, model: ArtifactRecord):
        try:
            # Extracting table name and column definitions from the Pydantic model
            table_name = model.Config.record_name
            columns = []
            for field_name, field_type in model.__annotations__.items():
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
            logger.exception(f"Failed to create table {table_name} from Pydantic model")

    def insert_artifact_data(
        self,
        artifact: str,
        data: list[dict],
    ):
        if not data:
            logger.warning("No data provided to insert into artifact table")
            return

        try:
            # Prepare the list of tuples for batch insertion
            prepared_data = []
            for record in data:
                # Convert datetime objects in lists to strings and serialize lists to JSON
                processed_record = {
                    key: json.dumps(
                        [v.isoformat() if isinstance(v, datetime) else v for v in value]
                    )
                    if isinstance(value, list)
                    else value
                    for key, value in record.items()
                }

                # Convert the dictionary to a tuple
                record_tuple = tuple(processed_record.values())

                # Append the tuple to the list of tuples
                prepared_data.append(record_tuple)

            # Prepare SQL statement with placeholders
            keys = data[0].keys() if data else []
            placeholders = ", ".join(["?"] * len(keys))
            statement = (
                f"INSERT INTO {artifact} ({', '.join(keys)}) VALUES ({placeholders})"
            )
            with open_db(self.database) as cursor:
                cursor.executemany(statement, prepared_data)
                logger.info(
                    f"Inserted {len(data)} {artifact} entries into {artifact} table"
                )

        except Exception as e:
            logger.exception(f"Error inserting data into {artifact} table: {e}")
