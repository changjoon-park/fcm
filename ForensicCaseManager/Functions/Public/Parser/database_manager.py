import sqlite3
import yaml
from pathlib import Path


class DatabaseManager:
    DATABASE = "test.sqlite"

    def __init__(self):
        self.conn = None

    def connect(self):
        self.conn = sqlite3.connect(self.DATABASE)
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

    # create/insert case_information table
    def create_case_information_table(self):
        with self.conn:
            self.c.execute(
                """
            CREATE TABLE IF NOT EXISTS case_information (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_label TEXT NOT NULL,
                computer_name TEXT NOT NULL,
                registered_owner TEXT NOT NULL,
                source TEXT NOT NULL,
                session_id TEXT NOT NULL
            )
            """
            )

    def insert_case_information(
        self,
        case_label: str,
        computer_name: str,
        registered_owner: str,
        source: str,
        session_id: str,
    ):
        with self.conn:
            self.c.execute(
                """
            INSERT INTO case_information (case_label, computer_name, registered_owner, source, session_id)
            VALUES (?, ?, ?, ?, ?)
            """,
                (
                    case_label,
                    computer_name,
                    registered_owner,
                    source,
                    session_id,
                ),
            )

    # create/insert category table
    def create_category_table(self):
        with self.conn:
            self.c.execute(
                """
            CREATE TABLE IF NOT EXISTS category (
                id INTEGER PRIMARY KEY,
                category TEXT NOT NULL
            )"""
            )

    def insert_category(self, id: int, category: str):
        with self.conn:
            self.c.execute(
                """
            INSERT INTO category (id, category)
            VALUES (?, ?)
            """,
                (
                    id,
                    category,
                ),
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
        with self.conn:
            self.c.execute(
                f"""
            INSERT INTO {artifact} ({','.join(data.keys())})
            VALUES ({','.join(['?'] * len(data.keys()))})
            """,
                tuple(data.values()),
            )
