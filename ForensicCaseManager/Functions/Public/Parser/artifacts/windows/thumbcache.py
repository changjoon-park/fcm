import json
from pathlib import Path
from typing import Iterator, Optional, Union

from dissect.thumbcache import Error, Thumbcache
from dissect.thumbcache.tools.extract_with_index import dump_entry_data_through_index
from dissect.target.helpers.record import TargetRecordDescriptor

from dissect.target.plugins.os.windows.thumbcache import (
    IndexRecord,
    ThumbcacheRecord,
    IconcacheRecord,
)
from forensic_artifact import Source, ForensicArtifact


class Thumbcache(ForensicArtifact):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self) -> None:
        """
        Return files located in the recycle bin ($Recycle.Bin).

        Write RecycleBinRecords with fields:
          hostname (string): The target hostname
          domain (string): The target domain
          ts (datetime): The time of deletion
          path (uri): The file original location before deletion
          filesize (filesize): Filesize of the deleted file
          sid (string): SID of the user deleted the file, parsed from $I filepath
          user (string): Username matching SID, lookup using Dissect user plugin
          deleted_path (uri): Location of the deleted file after deletion $R file
          source (uri): Location of $I meta file on disk
        """

        recyclebin = [
            json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
            for record in self.read_records()
        ]

        self.result = {"recyclebin": recyclebin}

    def _create_entries(self, cache: Thumbcache, record_type: TargetRecordDescriptor):
        for path, entry in cache.entries():
            yield record_type(
                identifier=entry.identifier,
                hash=entry.hash,
                extension=entry.extension,
                header_checksum=entry.header_checksum,
                data_checksum=entry.data_checksum,
                path=str(path),
                data_size=len(entry.data),
            )
        for index_entry in cache.index_entries():
            yield IndexRecord(
                identifier=index_entry.identifier.hex(),
                in_use=index_entry.in_use(),
                flags=index_entry.flags,
                last_modified=index_entry.last_modified,
                path=str(cache.index_file),
            )

    def _parse_thumbcache(
        self,
        record_type: TargetRecordDescriptor,
        prefix: str,
        output_dir: Optional[Path],
    ) -> Iterator[Union[ThumbcacheRecord, IconcacheRecord, IndexRecord]]:
        for cache_path in self.get_cache_paths():
            try:
                if output_dir:
                    dump_entry_data_through_index(cache_path, output_dir, prefix)
                else:
                    cache = Thumbcache(cache_path, prefix=prefix)
                    yield from self._create_entries(cache, record_type)

            except Error as e:
                # A specific thumbcache exception occurred, log the error.
                self.target.log.error(e)
            except Exception as e:
                # A different exception occurred, log the exception.
                self.target.log.critical(e, exc_info=True)
                pass

    def thumbcache(
        self, output_dir: Optional[Path] = None
    ) -> Iterator[ThumbcacheRecord]:
        yield from self._parse_thumbcache(ThumbcacheRecord, "thumbcache", output_dir)

    def iconcache(self, output_dir: Optional[Path] = None) -> Iterator[IconcacheRecord]:
        yield from self._parse_thumbcache(IconcacheRecord, "iconcache", output_dir)
