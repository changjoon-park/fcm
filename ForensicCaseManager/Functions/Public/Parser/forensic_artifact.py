import logging
from pathlib import Path
from datetime import timedelta, timezone
from typing import Generator
from dataclasses import dataclass, field
from pydantic import BaseModel
from collections import namedtuple
from icecream import ic

from dissect.target import Target
from dissect.target.filesystem import Filesystem

from settings.artifact_paths import ARTIFACT_PATH
from util.timestamp import Timestamp
from util.file_extractor import FileExtractor
from settings.config import ARTIFACT_OWNER_SYSTEM, ARTIFACT_OWNER_USER
from settings.artifact_paths import ArtifactSchema

logger = logging.getLogger(__name__)

Record = namedtuple("Record", ["schema", "record"])


class ArtifactRecord(BaseModel):
    evidence_id: str


@dataclass
class Source:
    _evidence: str = None
    source: Target = field(init=False)
    source_path: str = field(init=False)

    def __post_init__(self):
        self.source = Target.open(self._evidence)
        self.source_path = self._evidence


@dataclass(kw_only=True)
class ForensicArtifact:
    src: Source
    schema: ArtifactSchema
    records: list[Record] = field(default_factory=list)
    _evidence_id: str = field(init=False)

    def __post_init__(self):
        pass

    @property
    def evidence_id(self) -> str:
        return self._evidence_id

    @evidence_id.setter
    def evidence_id(self, value: str) -> None:
        self._evidence_id = value

    @property
    def ts(self) -> Timestamp:
        try:
            bias: timedelta = self.src.source.datetime.tzinfo.bias
        except:
            bias: timedelta = timedelta(hours=9)  # KST(+09:00)
        return Timestamp(tzinfo=timezone(bias))

    @property
    def fe(self) -> FileExtractor:
        return FileExtractor()

    def iter_filesystem(self, type: str = "ntfs") -> Generator[Filesystem, None, None]:
        yield from (fs for fs in self.src.source.filesystems if fs.__fstype__ == type)

    def iter_directory(self) -> Generator[Path, None, None]:
        root = self.schema.root  # str
        directories = self.schema.directories  # list[str]

        if root == "system":
            for root in self.src.source.fs.path("/").iterdir():
                if not str(root) == "/sysvol":
                    yield from (
                        root.joinpath(directory)
                        for directory in directories
                        if root.joinpath(directory).exists()
                    )
        elif root == "user":
            for user_details in self.src.source.user_details.all_with_home():
                yield from (
                    user_details.home_path.joinpath(directory)
                    for directory in directories
                    if user_details.home_path.joinpath(directory).exists()
                )

    def iter_entry(
        self, name: str = None, recurse: bool = False
    ) -> Generator[Path, None, None]:
        # for dir in self.iter_directory():
        #     if name == None:
        #         for entry in self.schema.entries:
        #             if recurse == True:
        #                 yield from dir.rglob(entry)
        #             else:
        #                 yield from dir.glob(entry)
        #     else:
        #         if recurse == True:
        #             yield from dir.rglob(name)
        #         else:
        #             yield from dir.glob(name)

        for dir in self.iter_directory():
            entries = [name] if name else self.schema.entries
            for entry in entries:
                yield from (dir.rglob(entry) if recurse else dir.glob(entry))

    def iter_key(self, name: str = None) -> Generator:
        if self.artifact_directory == "registry":
            if name == None:
                yield from self.artifact_entry
            else:
                yield from self.artifact_entry.get(name)

    def parse(self, descending: bool = False) -> Generator[ArtifactRecord, None, None]:
        """parse artifact.

        Args:
            descending (bool, optional)
                - sort parsed results by descending/ascending order. Defaults to False.
        """
        raise NotImplementedError

    def check_empty_entry(self, entry: Generator) -> Generator:
        try:
            first = next(entry)
        except StopIteration:
            logger.info(
                f"No entries found in the {self.schema.name} from {self.evidence_id}"
            )
        else:
            yield first
            yield from entry

    def validate_record(self, index: int, record: ArtifactRecord) -> dict:
        if isinstance(record, ArtifactRecord):
            print(f"{self.schema.name}-{index}: Parsed successfully")
        else:
            print(
                f"{self.schema.name}-{index}: error during parsing, type: {type(record)}"
            )
            logging.error(
                f"{self.schema.name}-{index}: error during parsing, type: {type(record)}"
            )
        return record
