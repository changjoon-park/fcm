import logging
from pathlib import Path
from datetime import timedelta, timezone
from typing import Generator
from dataclasses import dataclass, field

from dissect.target import Target
from dissect.target.filesystem import Filesystem

from lib.path_finder import ARTIFACT_PATH
from util.timestamp import Timestamp
from util.file_extractor import FileExtractor

SOURCE_TYPE_LOCAL = "Local"
SOURCE_TYPE_CONTAINER = "Container"

logger = logging.getLogger(__name__)


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
            logger.error(f"Invalid source: {self._container}")


@dataclass(kw_only=True)
class ForensicArtifact:
    src: Source
    artifact: str  # ? user input data, e.g., 'prefetch', 'sru_network'
    category: str
    _evidence_id: str = field(init=False)
    artifact_directory: list[str] = field(init=False)
    artifact_entry: str = field(init=False)
    result: dict = field(default_factory=dict)  # result: {name: [data, ...]}

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

    def validate_record(self, index: int, record: dict) -> dict:
        if isinstance(record, dict):
            print(f"{self.artifact}-{index}: Parsed successfully")
        else:
            print(
                f"{self.artifact}-{index}: error during parsing, type: {type(record)}"
            )
            logging.error(
                f"{self.artifact}-{index}: error during parsing, type: {type(record)}"
            )
        return record
