import json
from datetime import datetime
from typing import Optional
from dataclasses import dataclass, field

from util.converter import convertfrom_extended_ascii
from util.extractor import extract_basename
from pathlib import Path
from plugins import PLUGINS
from forensic_artifact import (
    Source,
    ForensicArtifact,
    SOURCE_TYPE_CONTAINER,
    SOURCE_TYPE_LOCAL,
)
from database_manager import DatabaseManager

ROOT_DIRECTORY_NAME = "_fcm"


@dataclass(kw_only=True)
class CaseManager:
    _path: Optional[str] = None
    _local: Optional[bool] = False
    _container: Optional[str] = None
    _artifacts: Optional[list] = None
    _categories: Optional[list] = None
    root_directory: Path
    src: Source = field(init=False)
    forensic_artifact: ForensicArtifact = field(default_factory=list)
    db_manager: DatabaseManager = field(default_factory=DatabaseManager)

    def __post_init__(self):
        self.database_init()
        self.src = Source(
            _path=self._path,
            _local=self._local,
            _container=self._container,
        )
        for artifact, plugin in PLUGINS.items():
            ForensicArtifact, category = plugin
            if self._artifacts:
                for artifact_entry in self._artifacts:
                    if artifact == artifact_entry:
                        self.forensic_artifact.append(
                            ForensicArtifact(
                                src=self.src, artifact=artifact, category=category
                            )
                        )
            if self._categories:
                for category_entry in self._categories:
                    if category == category_entry:
                        self.forensic_artifact.append(
                            ForensicArtifact(
                                src=self.src, artifact=artifact, category=category
                            )
                        )

    @property
    def case_information(self):
        return {
            "case_label": self._case_label,
            "computer_name": self._computer_name,
            "registered_owner": self._registered_owner,
            "source": self.src.source_path,
        }

    @property
    def _case_label(self):
        return extract_basename(path=self.src.source_path)

    @property
    def _computer_name(self):
        computer_name = self.src.source.name
        try:
            # 'ComputerName' Registry value is stored by "UTF-16" encoding
            # However, dissect module reads the data by "Extended ASCII" encoding. That occurs error
            # Moreover, dissect module removes 'null value' from original bytes when decoding
            # This makes it difficult to deal with combined-characters (ex. 한s -> unicode, ascii)
            _ = computer_name.encode(
                "ASCII"
            )  # ! test if the name's each character is ascii (not extended)
            return computer_name
        except:
            return convertfrom_extended_ascii(
                string=computer_name, encoding="UTF-16-LE"
            )

    @property
    def _registered_owner(self):
        reg_path = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
        registered_owner = (
            self.src.source.registry.key(reg_path).value("RegisteredOwner").value
        )
        try:
            _ = registered_owner.encode("ASCII")
            return registered_owner
        except:
            return convertfrom_extended_ascii(
                string=registered_owner, encoding="UTF-16-LE"
            )

    @property
    def session_dir(self) -> Path:
        if self.src.type == SOURCE_TYPE_LOCAL or self.src.type == SOURCE_TYPE_CONTAINER:
            return self.root_directory / self._computer_name
        else:
            return self.root_directory / "tmp"

    @property
    def session_time(self) -> str:
        return datetime.now().strftime("%Y%m%dT%H%M%S")

    def database_init(self):
        categories = [
            (1, "APPLICATION_EXECUTION"),
            (2, "FILE_FOLDER_OPENING"),
            (3, "DELETED_ITEMS_FILE_EXISTENCE"),
            (4, "BROWSER_ACTIVITY"),
            (5, "CLOUD_STORAGE"),
            (6, "ACCOUNT_USAGE"),
            (7, "NETWORK_ACTIVITY_PHYSICAL_LOCATION"),
            (8, "SYSTEM_INFORMATION"),
            (9, "EXTERNAL_DEVICE_USB_USAGE"),
        ]
        self.db_manager.connect()
        if not self.db_manager.is_table_exist("case_information"):
            self.db_manager.create_case_information_table()
        if not self.db_manager.is_table_exist("category"):
            self.db_manager.create_category_table()
            for id, category in categories:
                self.db_manager.insert_category(
                    id=id,
                    category=category,
                )
        if not self.db_manager.is_table_exist("session_data"):
            self.db_manager.create_session_data_table()
        self.db_manager.close()

    def parse_all(self) -> None:
        for entry in self.forensic_artifact:
            entry.parse(descending=False)

    def export_all(self) -> list[dict]:
        for entry in self.forensic_artifact:
            entry.export_db(session_id=self.session_time)

        result_files = []
        for entry in self.forensic_artifact:
            output_dir = self.session_dir / f"{entry.category}" / f"{entry.artifact}"
            result_files.extend(
                entry.export(output_dir=output_dir, current_time=self.session_time)
            )
        return (
            self._export_session(result_files=result_files),
            self._export_case_information(),
        )

    def _export_session(self, result_files: list) -> list[dict]:
        session = "[" + ",\n".join(result_files) + "]"
        session_file = self.session_dir / f"session_{self.session_time}.json"
        with open(session_file, "a+", encoding="utf-8") as f:
            f.write(session)
        return session

    def _export_case_information(self):
        self.db_manager.connect()
        self.db_manager.insert_case_information(
            case_label=self._case_label,
            computer_name=self._computer_name,
            registered_owner=self._registered_owner,
            source=self.src.source_path,
            session_id=self.session_time,
        )
        self.db_manager.close()

        case_information = (
            "["
            + json.dumps(
                self.case_information, indent=2, default=str, ensure_ascii=False
            )
            + "]"
        )
        case_information_file = self.session_dir / "case_information.json"
        with open(case_information_file, "w", encoding="utf-8") as f:
            f.write(case_information)
        return case_information
