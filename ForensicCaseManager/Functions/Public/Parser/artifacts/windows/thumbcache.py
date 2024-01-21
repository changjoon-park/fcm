import logging
from pathlib import Path
from typing import Iterator, Optional, Union

from lib.thumbcache.index import IndexEntry, ThumbnailIndex
from lib.thumbcache.thumbcache_file import ThumbcacheEntry, ThumbcacheFile
from lib.thumbcache.exceptions import Error
from lib.thumbcache.tools.extract_with_index import dump_entry_data_through_index

from core.forensic_artifact import Source, ForensicArtifact

logger = logging.getLogger(__name__)


class ThumbcacheParser:
    """This class combines the thumbnailindex and thumbcachefile.

    The class looks up all files inside ``path`` that have the same ``prefix``.

    Args:
        path: The directory that contains the thumbcache files.
        prefix: The start of the name to search for.
    """

    def __init__(self, path: Path, prefix: str = "thumbcache") -> None:
        self._mapping: dict[str, Path] = {}
        self.index_file, self.cache_files = self._populate_files(path, prefix)

    def _populate_files(self, path: Path, prefix: str) -> tuple[Path, list[Path]]:
        cache_files = []
        index_file = None
        for file in path.glob(f"{prefix}*"):
            if file.name.endswith("_idx.db"):
                index_file = file
            else:
                cache_files.append(file)
        return index_file, cache_files

    @property
    def mapping(self) -> dict[int, Path]:
        """Looks at the version field in the cache file header."""
        if not self._mapping:
            for file in self.cache_files:
                with file.open("rb") as cache_file:
                    t_file = ThumbcacheFile(cache_file)
                    key = t_file.type
                self._mapping.update({key: file})
        return self._mapping

    def entries(self) -> Iterator[tuple[Path, ThumbcacheEntry]]:
        """Iterates through all the specific entries from the thumbcache files."""
        used_entries = list(self.index_entries())

        for entry in used_entries:
            yield from self._entries_from_offsets(entry.cache_offsets)

    def index_entries(self) -> Iterator[IndexEntry]:
        """Iterates through all the index entries that are in use."""
        with self.index_file.open("rb") as i_file:
            for entry in ThumbnailIndex(i_file).entries():
                yield entry

    def _entries_from_offsets(
        self, offsets: list[int]
    ) -> Iterator[tuple[Path, ThumbcacheEntry]]:
        """Retrieves Thumbcache entries from a ThumbcacheFile using offsets."""
        for idx, offset in enumerate(offsets):
            if offset == 0xFFFFFFFF:
                continue

            cache_path = self.mapping.get(idx)

            with cache_path.open("rb") as cache_file:
                yield cache_path, ThumbcacheFile(cache_file)[offset]


class Thumbcache(ForensicArtifact):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self, descending: bool = False) -> None:
        thumbcache = sorted(
            [
                self.validate_record(index=index, record=record)
                for index, record in enumerate(self.thumbcache())
            ],
            key=lambda record: record[
                "identifier"
            ],  # Sorting based on the 'identifier' field
            reverse=descending,
        )
        iconcache = sorted(
            [
                self.validate_record(index=index, record=record)
                for index, record in enumerate(self.iconcache())
            ],
            key=lambda record: record[
                "identifier"
            ],  # Sorting based on the 'identifier' field
            reverse=descending,
        )

    def _create_entries(self, cache: ThumbcacheParser) -> Iterator[dict]:
        for path, entry in cache.entries():
            yield {
                "identifier": entry.identifier,
                "in_use": None,
                "hash": entry.hash,
                "data_size": len(entry.data),
                "extension": entry.extension,
                "flags": None,
                "header_checksum": entry.header_checksum,
                "data_checksum": entry.data_checksum,
                "last_modified": None,
                "path": str(path),
            }
        for index_entry in cache.index_entries():
            yield {
                "identifier": index_entry.identifier.hex(),
                "in_use": index_entry.in_use(),
                "hash": None,
                "data_size": None,
                "extension": None,
                "flags": index_entry.flags,
                "header_checksum": None,
                "data_checksum": None,
                "last_modified": index_entry.last_modified,
                "path": str(cache.index_file),
            }

    def _parse_thumbcache(
        self, prefix: str, output_dir: Optional[Path]
    ) -> Iterator[Union[dict, dict, dict]]:
        for cache_path in self.check_empty_entry(self.iter_directory()):
            try:
                # If an output directory is specified, dump the data to the output directory.
                if output_dir:
                    dump_entry_data_through_index(cache_path, output_dir, prefix)

                # Create a ThumbcacheParser object and yield the entries.
                cache = ThumbcacheParser(cache_path, prefix=prefix)
                yield from self._create_entries(cache=cache)

            except Error as e:
                # A specific thumbcache exception occurred, log the error.
                logger.log.error(e)
            except Exception as e:
                # A different exception occurred, log the exception.
                logger.critical(e, exc_info=True)
                pass

    def thumbcache(self, output_dir: Optional[Path] = None) -> Iterator[dict]:
        yield from self._parse_thumbcache(prefix="thumbcache", output_dir=output_dir)

    def iconcache(self, output_dir: Optional[Path] = None) -> Iterator[dict]:
        yield from self._parse_thumbcache(prefix="iconcache", output_dir=output_dir)
