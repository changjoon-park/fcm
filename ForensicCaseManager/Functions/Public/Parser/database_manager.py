import sqlite3


class DatabaseManager:
    DATABASE = "teset.sqlite"

    def __init__(self):
        self.conn = None

    def connect(self):
        self.conn = sqlite3.connect(self.DATABASE)
        self.c = self.conn.cursor()

    def close(self):
        self.conn.close()

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
                session TEXT NOT NULL
            )
            """
            )

    def create_category_table(self):
        with self.conn:
            self.c.execute(
                """
            CREATE TABLE IF NOT EXISTS category (
                id INTEGER PRIMARY KEY,
                category TEXT NOT NULL
            )"""
            )

    def insert_category(self, id, category):
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

    def insert_case_information(
        self, case_label, computer_name, registered_owner, source, session
    ):
        with self.conn:
            self.c.execute(
                """
            INSERT INTO case_information (case_label, computer_name, registered_owner, source, session)
            VALUES (?, ?, ?, ?, ?)
            """,
                (
                    case_label,
                    computer_name,
                    registered_owner,
                    source,
                    session,
                ),
            )
