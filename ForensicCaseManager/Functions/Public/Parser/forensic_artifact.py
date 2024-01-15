import logging
from pathlib import Path
from datetime import timedelta, timezone
from typing import Generator
from dataclasses import dataclass, field
from pydantic import BaseModel
from collections import namedtuple

from dissect.target import Target
from dissect.target.filesystem import Filesystem

from settings.artifact_paths import ARTIFACT_PATH
from util.timestamp import Timestamp
from util.file_extractor import FileExtractor
from settings.config import ARTIFACT_OWNER_SYSTEM, ARTIFACT_OWNER_USER


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
    artifact: str
    category: str
    _evidence_id: str = field(init=False)
    artifact_directory: list[dict] = field(init=False)
    artifact_entry: str = field(init=False)
    records: list[Record] = field(default_factory=list)

    def __post_init__(self):
        self.artifact_directory, self.artifact_entry = ARTIFACT_PATH.get(self.artifact)

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
        for directory in self.artifact_directory:
            if isinstance(directory, dict):
                owner = directory.get("owner", "")  # str
                paths = directory.get("paths", "")  # list of str

                if owner == ARTIFACT_OWNER_SYSTEM:
                    for root in self.src.source.fs.path("/").iterdir():
                        if not str(root) == "/sysvol":
                            yield from (
                                root.joinpath(path)
                                for path in paths
                                if root.joinpath(path).exists()
                            )
                elif owner == ARTIFACT_OWNER_USER:
                    for user_details in self.src.source.user_details.all_with_home():
                        yield from (
                            user_details.home_path.joinpath(path)
                            for path in paths
                            if user_details.home_path.joinpath(path).exists()
                        )

    def iter_entry(
        self, name: str = None, recurse: bool = False
    ) -> Generator[Path, None, None]:
        if name == None:
            artifact_entry = self.artifact_entry
        else:
            artifact_entry = name

        for dir in self.iter_directory():
            if dir.is_dir():
                if recurse == True:
                    yield from dir.rglob(artifact_entry)
                else:
                    yield from dir.glob(artifact_entry)
            else:
                yield Path(self.src.source)

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
                f"No entries found in the {self.artifact} from {self.evidence_id}"
            )
        else:
            yield first
            yield from entry

    def validate_record(self, index: int, record: ArtifactRecord) -> dict:
        if isinstance(record, ArtifactRecord):
            print(f"{self.artifact}-{index}: Parsed successfully")
        else:
            print(
                f"{self.artifact}-{index}: error during parsing, type: {type(record)}"
            )
            logging.error(
                f"{self.artifact}-{index}: error during parsing, type: {type(record)}"
            )
        return record
