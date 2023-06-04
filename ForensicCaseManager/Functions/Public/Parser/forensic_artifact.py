import os
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Generator, Union
from dataclasses import dataclass, field

from dissect.target import Target
from dissect.target.filesystem import Filesystem
from path_finder import ARTIFACT_PATH
from util.ts import TimeStamp

SOURCE_TYPE_PATH = "Path"
SOURCE_TYPE_LOCAL = "Local"
SOURCE_TYPE_CONTAINER = "Container"

@dataclass
class Source:
    _path: str = None
    _local: bool = False
    _container: str = None
    source: Union[str, Target] = field(init=False)
    source_path: str = field(init=False)
    type: str = field(init=False)

    def __post_init__(self):
        if self._path:
            self.source = self._path
            self.source_path = self._path
            self.type = SOURCE_TYPE_PATH
            self._target = ""  #
        elif self._local:
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
    directory: list[str] = field(init=False)
    entry: str = field(init=False)
    result: dict = field(default_factory=dict)

    def __post_init__(self):
        self.directory, self.entry = ARTIFACT_PATH.get(self.artifact)
        self._target = self.src._target  #
        
    @property
    def ts(self) -> TimeStamp:
        try:
            bias: timedelta = self.src.source.datetime.tzinfo.bias
        except:
            bias: timedelta = timedelta(hours=9)  # KST(+09:00)
        return TimeStamp(tzinfo=timezone(bias))

    def _iter_filesystem(self, type: str = "ntfs") -> Generator[Filesystem, None, None]:
        if self.src.type == SOURCE_TYPE_LOCAL or self.src.type == SOURCE_TYPE_CONTAINER:
            yield from (
                fs for fs in self.src.source.filesystems
                if fs.__fstype__ == type
            )

    def _iter_directory(self) -> Generator[Path, None, None]:
        if self.src.type == SOURCE_TYPE_LOCAL or self.src.type == SOURCE_TYPE_CONTAINER:
            for dir in self.directory:
                if dir.startswith("%ROOT%"):
                    dir = Path(dir.replace("%ROOT%", ""))
                    yield from (
                        root.joinpath(dir)
                        for root in self.src.source.fs.path("/").iterdir()
                        if root.joinpath(dir).parts[1] != "sysvol" and root.joinpath(dir).exists()
                    )
                elif dir.startswith("%USER%"):
                    dir = Path(dir.replace("%USER%", ""))
                    yield from (
                        user_details.home_path.joinpath(dir)
                        for user_details in self.src.source.user_details.all_with_home()
                        if user_details.home_path.joinpath(dir).exists()
                    )
        elif self.src.type == SOURCE_TYPE_PATH:
            yield Path(self.src.source)

    def _iter_entry(self, name: str = None, recurse: bool = False) -> Generator[Path, None, None]:
        if name == None:
            entry = self.entry
        else:
            entry = name
            
        for dir in self._iter_directory():
            if dir.is_dir():
                if recurse == True:
                    yield from dir.rglob(entry)
                else:
                    yield from dir.glob(entry)
            else:
                yield Path(self.src.source)

    def _iter_key(self, name: str = None) -> Generator:
        if self.directory == None:
            if name == None:
                yield from self.entry
            else:
                yield from self.entry.get(name)

    def parse(self, descending: bool = False) -> None:
        """parse artifact. parsed results update 'self.result' variable.

        Args:
            descending (bool, optional)
                - sort parsed results by descending/ascending order. Defaults to False.
        """
        raise NotImplementedError

    def export(self, output_dir: Path, current_time: str = None) -> list[dict]:
        if not output_dir.exists():
            os.makedirs(output_dir, 0o777)
            
        if current_time == None:
            current_time = datetime.now().strftime("%Y%m%dT%H%M%S")

        result_files = []
        for name, data in self.result.items():
            result = "[" + ",\n".join(data) + "]"
            output_path = output_dir / f"{name}_{current_time}.json"
            with open(output_path, 'a+', encoding='utf-8') as f:
                f.write(result)

            result_file = {
                "category": self.category,
                "artifact": self.artifact,
                "record": name,
                "result": output_path
            }
            result_files.append(json.dumps(result_file, indent=2, default=str, ensure_ascii=False))
        return result_files