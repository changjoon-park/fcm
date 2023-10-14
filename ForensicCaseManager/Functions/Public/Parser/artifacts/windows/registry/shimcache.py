import json
from io import BytesIO
from typing import Generator

from flow.record.fieldtypes import uri

from dissect.target.exceptions import RegistryError

from dissect.target.plugins.os.windows.regf.shimcache import (
    ShimcacheRecord,
    ShimCache as ShimCacheParser,
    CRCMismatchException,
    ShimCacheGeneratorType,
)

from forensic_artifact import Source, ForensicArtifact


class ShimCache(ForensicArtifact):
    """
    Shimcache plugin.
    """

    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self, descending: bool = False):
        sorted_shimcache = sorted(
            [record._packdict() for record in self.shimcache()],
            key=lambda x: x["name"],
            reverse=descending,
        )
        shimcache = [
            json.dumps(entry, indent=2, default=str, ensure_ascii=False)
            for entry in sorted_shimcache
        ]

        self.result = {
            "shimcache": shimcache,
        }

    def shimcache(self) -> ShimcacheRecord:
        """Return the shimcache.

        The ShimCache or AppCompatCache stores registry keys related to properties from older Windows versions for
        compatibility purposes. Since it contains information about files such as the last
        modified date and the file size, it can be useful in forensic investigations.

        Sources:
            - https://www.andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/

        Yields ShimcacheRecords with the following fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            last_modified (datetime): The last modified date.
            name (string): The value name.
            index (varint): The index of the entry.
            path (uri): The parsed path.
        """
        for reg_path in self._iter_key():
            for key in self.src.source.registry.keys(reg_path):
                for value_name in ("AppCompatCache", "CacheMainSdb"):
                    try:
                        data = key.value(value_name).value
                    except RegistryError:
                        continue

                    try:
                        cache = ShimCacheParser(
                            BytesIO(data),
                            self.src.source.ntversion,
                            value_name != "AppCompatCache",
                        )
                    except NotImplementedError:
                        # self.target.log.warning("Not implemented ShimCache version: %s %s", key, value_name)
                        continue
                    except EOFError:
                        # self.target.log.warning("Error parsing ShimCache entry: %s %s", key, value_name)
                        continue

                    yield from self._get_records(value_name, cache)

    def _get_records(
        self, name: str, cache: Generator[ShimCacheGeneratorType, None, None]
    ) -> Generator[ShimcacheRecord, None, None]:
        for index, item in enumerate(cache):
            if isinstance(item, CRCMismatchException):
                # self.target.log.warning("A CRC mismatch occured for entry: %s", item)
                continue

            ts, path = item

            path = uri.from_windows(self.src.source.resolve(path))

            yield ShimcacheRecord(
                last_modified=ts,
                name=name,
                index=index,
                path=path,
                _target=self._target,
            )
