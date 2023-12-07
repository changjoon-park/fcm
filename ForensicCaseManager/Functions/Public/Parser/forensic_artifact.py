import os
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Generator, Union, Annotated
from dataclasses import dataclass, field

from dissect.target import Target
from dissect.target.filesystem import Filesystem

from path_finder import ARTIFACT_PATH
from util.ts import TimeStamp
from database_manager import DatabaseManager
from schema.artifact_schema import ARTIFACT_SCHEMA
from config import DATABASE_NAME

SOURCE_TYPE_LOCAL = "Local"
SOURCE_TYPE_CONTAINER = "Container"


@dataclass
class Source:
    _local: bool = False
    _container: str = None
    source: Target = field(init=False)
    source_path: str = field(init=False)
    type: str = field(init=False)

    def __post_init__(self):
        if self._local:
            self.source = Target.open("local")
            self.source_path = "Local"
            self.type = SOURCE_TYPE_LOCAL
            self._target = self.source  #
        elif self._container:
            self.source = Target.open(self._container)
            self.source_path = self._container
            self.type = SOURCE_TYPE_CONTAINER
            self._target = self.source  #
        else:
            raise ValueError(f"Error :(")


@dataclass(kw_only=True)
class ForensicArtifact:
    src: Source
    artifact: str
    category: str
    artifact_directory: list[str] = field(init=False)
    artifact_entry: str = field(init=False)
    result: dict = field(
        default_factory=dict
    )  # {name: [json.dumps(data, indent=2, default=str, ensure_ascii=False), ...]}

    def __post_init__(self):
        self.artifact_directory, self.artifact_entry = ARTIFACT_PATH.get(self.artifact)
        self._target = self.src._target  #

    @property
    def ts(self) -> TimeStamp:
        try:
            bias: timedelta = self.src.source.datetime.tzinfo.bias
        except:
            bias: timedelta = timedelta(hours=9)  # KST(+09:00)
        return TimeStamp(tzinfo=timezone(bias))

    def _iter_filesystem(self, type: str = "ntfs") -> Generator[Filesystem, None, None]:
        yield from (fs for fs in self.src.source.filesystems if fs.__fstype__ == type)

    def _iter_directory(self) -> Generator[Path, None, None]:
        for dir in self.artifact_directory:
            if dir.startswith("%ROOT%"):
                dir = Path(dir.replace("%ROOT%", ""))
                yield from (
                    root.joinpath(dir)
                    for root in self.src.source.fs.path("/").iterdir()
                    if root.joinpath(dir).parts[1] != "sysvol"
                    and root.joinpath(dir).exists()
                )
            elif dir.startswith("%USER%"):
                dir = Path(dir.replace("%USER%", ""))
                yield from (
                    user_details.home_path.joinpath(dir)
                    for user_details in self.src.source.user_details.all_with_home()
                    if user_details.home_path.joinpath(dir).exists()
                )

    def _iter_entry(
        self, name: str = None, recurse: bool = False
    ) -> Generator[Path, None, None]:
        if name == None:
            artifact_entry = self.artifact_entry
        else:
            artifact_entry = name

        for dir in self._iter_directory():
            if dir.is_dir():
                if recurse == True:
                    yield from dir.rglob(artifact_entry)
                else:
                    yield from dir.glob(artifact_entry)
            else:
                yield Path(self.src.source)

    def _iter_key(self, name: str = None) -> Generator:
        if self.artifact_directory == None:
            if name == None:
                yield from self.artifact_entry
            else:
                yield from self.artifact_entry.get(name)

    def parse(self, descending: bool = False) -> None:
        """parse artifact. parsed results update 'self.result' variable.

        Args:
            descending (bool, optional)
                - sort parsed results by descending/ascending order. Defaults to False.
        """
        raise NotImplementedError

    def export(self, db_manager: DatabaseManager = None):
        db_manager.connect()
        db_manager.create_artifact_table_from_yaml(ARTIFACT_SCHEMA.get(self.artifact))
        # for artifact_name, artifact_data in self.result.items():

        # self.db_manager.insert_artifact_data(

        # )
        self.db_manager.close()
