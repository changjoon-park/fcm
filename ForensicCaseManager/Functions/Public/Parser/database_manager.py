import sqlite3
import yaml
import json
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass


@dataclass(kw_only=True)
class DatabaseManager:
    database: Path

    def __post_init__(self):
        pass

    def connect(self):
        self.conn = sqlite3.connect(self.database)
        self.c = self.conn.cursor()

    def close(self):
        self.conn.close()

    def is_table_exist(self, table_name: str) -> bool:
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

    # create/insert forensic_case table
    def create_forensic_case_table(self):
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

    def insert_forensic_case(
        self,
        id: str,
        case_name: str,
        case_directory: str,
    ):
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

    # create/insert evidences table
    def create_evidences_table(self):
        with self.conn:
            self.c.execute(
                """
            CREATE TABLE IF NOT EXISTS evidences (
                evidence_number INTEGER NOT NULL,
                evidence_label TEXT NOT NULL,
                computer_name TEXT,
                registered_owner TEXT,
                source TEXT NOT NULL,
                case_id TEXT NOT NULL,
                FOREIGN KEY (case_id) REFERENCES forensic_case (id)
            )
            """
            )

    def insert_evidences(
        self,
        evidence_number: int,
        evidence_label: str,
        computer_name: str,
        registered_owner: str,
        source: str,
        case_id: str,
    ):
        with self.conn:
            self.c.execute(
                """
            INSERT INTO evidences (
                evidence_number,
                evidence_label, 
                computer_name, 
                registered_owner, 
                source, 
                case_id)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    evidence_number,
                    evidence_label,
                    computer_name,
                    registered_owner,
                    source,
                    case_id,
                ),
            )

    # create/insert artifact category table
    def create_artifact_category_table(self):
        with self.conn:
            self.c.execute(
                """
            CREATE TABLE IF NOT EXISTS artifact_category (
                id INTEGER PRIMARY KEY,
                category TEXT NOT NULL
            )"""
            )

    def insert_artifact_category(self, id: int, category: str):
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

    # create/insert artifacts table
    def create_artifacts_table(self):
        with self.conn:
            self.c.execute(
                """
            CREATE TABLE IF NOT EXISTS artifacts (
                artifact TEXT NOT NULL,
                category TEXT NOT NULL,
                record TEXT NOT NULL,
            )"""
            )

    # create/insert session_data table
    def create_session_data_table(self):
        with self.conn:
            self.c.execute(
                """
            CREATE TABLE IF NOT EXISTS session_data (
                category TEXT NOT NULL,
                artifact TEXT NOT NULL,
                record TEXT NOT NULL,
                session_id TEXT NOT NULL
            )"""
            )

    def insert_session_data(
        self, category: str, artifact: str, record: str, session_id: str
    ):
        with self.conn:
            self.c.execute(
                """
            INSERT INTO session_data (category, artifact, record, session_id)
            VALUES (?, ?, ?)
            """,
                (category, artifact, record, session_id),
            )

    # create/insert artifact table
    def create_artifact_table_from_yaml(self, yaml_file: Path):
        with open(yaml_file, "r", encoding="utf-8") as f:
            schema = yaml.load(f, Loader=yaml.FullLoader)
            for table in schema.get("Table", []):
                table_name = table.get("TableName")
                columns = table.get("Columns", [])
                types = table.get("Types", [])

                column_defs = ",".join(
                    [f"{column} {type}" for column, type in zip(columns, types)]
                )
                create_statement = (
                    f"CREATE TABLE IF NOT EXISTS {table_name} ({column_defs})"
                )
                with self.conn:
                    self.c.execute(create_statement)

    def insert_artifact_data(self, artifact: str, data: dict):
        for attribute, value in data.items():
            if type(value) == list:
                for i, v in enumerate(value):
                    if type(v) == datetime:
                        value[i] = v.isoformat()
                data[attribute] = json.dumps(value)

        with self.conn:
            self.c.execute(
                f"""
            INSERT INTO {artifact} ({','.join(data.keys())})
            VALUES ({','.join(['?'] * len(data.keys()))})
            """,
                tuple(data.values()),
            )
