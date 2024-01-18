import logging
from pathlib import Path
from datetime import timedelta, timezone
from typing import Generator
from dataclasses import dataclass, field
from pydantic import BaseModel
from icecream import ic

from dissect.target import Target
from dissect.target.filesystem import Filesystem

from util.timestamp import Timestamp
from util.file_extractor import FileExtractor
from settings.artifact_paths import ArtifactSchema

logger = logging.getLogger(__name__)


class ArtifactRecord(BaseModel):
    evidence_id: str
    record_name: str


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
    name: str = field(init=False)
    category: str = field(init=False)
    root: str = field(init=False)
    owner: str = field(init=False)
    entries: dict = field(init=False)
    records: list[ArtifactRecord] = field(default_factory=list)
    _evidence_id: str = field(init=False)

    def __post_init__(self):
        self.name = self.schema.name
        self.category = self.schema.category
        self.root = self.schema.root
        self.owner = self.schema.owner
        self.entries = self.schema.entries

    @property
    def evidence_id(self) -> str:
        return self._evidence_id

    @evidence_id.setter
    def evidence_id(self, value: str) -> None:
        self._evidence_id = value

    def get_record_name(self, entry_name: str = "") -> str:
        if not entry_name:
            entry_name = self.__class__.__name__
        record_name = self.entries.get(entry_name, {}).get("record_name")
        if not record_name:
            logger.error(f"Unable to find {entry_name} in {self.evidence_id}")
            return ""
        return record_name

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

    def iter_directory(
        self, directories: list[str] = []
    ) -> Generator[Path, None, None]:
        if self.root == "system":
            for root in self.src.source.fs.path("/").iterdir():
                if not str(root) == "/sysvol":
                    yield from (
                        root.joinpath(directory)
                        for directory in directories
                        if root.joinpath(directory).exists()
                    )
        elif self.root == "user":
            for user_details in self.src.source.user_details.all_with_home():
                yield from (
                    user_details.home_path.joinpath(directory)
                    for directory in directories
                    if user_details.home_path.joinpath(directory).exists()
                )

    def iter_entry(
        self, entry_name: str = None, node_name: str = None, recurse: bool = False
    ) -> Generator[Path, None, None]:
        for name, entry in self.entries.items():
            directories = entry.get("directories")
            nodes = entry.get("nodes")
            if entry_name and entry_name != name:
                continue
            if directories:
                for dir in self.iter_directory(directories=directories):
                    for node in nodes:
                        if node_name and node_name != node:
                            continue
                        yield from (dir.rglob(node) if recurse else dir.glob(node))
            else:
                for node in nodes:
                    if node_name and node_name != node:
                        continue
                    yield node

    def iter_key(self, name: str = None) -> Generator:
        if self.artifact_directory == "registry":
            if name == None:
                yield from self.artifact_entry
            else:
                yield from self.artifact_entry.get(name)
        else:
            logger.error(f"iter_key() is not supported for {self.schema.name} artifact")

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
            logger.info(f"No entries found in the {self.name} from {self.evidence_id}")
        else:
            yield first
            yield from entry

    def validate_record(self, index: int, record: ArtifactRecord) -> dict:
        if isinstance(record, ArtifactRecord):
            print(f"{self.name}-{index}: Succeed to parse")
        else:
            print(f"{self.name}-{index}: Failed to parse")
            logging.error(
                f"{self.name}-{index}: error during parsing, type: {type(record)}"
            )
        return record

    def log_error(self, error: Exception) -> None:
        logger.error(f"{self.evidence_id}:{self.name} - {error}")
