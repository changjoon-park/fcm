import json
from typing import Generator, BinaryIO
from pathlib import Path

from flow.record.fieldtypes import uri

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugins.os.windows.prefetch import (
    prefetch,
    prefetch_version_structs,
)

from util.lzxpress_huffman import LZXpressHuffman
from forensic_artifact import Source, ForensicArtifact


GroupedPrefetchRecord = TargetRecordDescriptor(
    "windows/prefetch",
    [
        ("datetime", "ts"),  # Run timestamp.
        ("uri", "filename"),  # The filename.
        ("uri", "prefetch"),  # The prefetch entry.
        ("uri[]", "linkedfiles"),  # A list of linked files
        ("uint32", "runcount"),  # The run count.
        ("datetime[]", "previousruns"),  # Previous run non zero timestamps
    ],
)


class PrefetchParser:
    def __init__(self, fh: BinaryIO):
        header_detect = prefetch.PREFETCH_HEADER_DETECT(fh.read(8))
        if header_detect.signature == b"MAM\x04":
            fh.seek(0)
            fh = LZXpressHuffman.decompress(fh=fh)

        self.fh = fh
        self.fh.seek(0)
        self.header = prefetch.PREFETCH_HEADER(self.fh)
        self.version = self.identify()
        self.volumes = None
        self.metrics = None
        self.fn = None
        self.parse()

    def identify(self):
        self.fh.seek(0)
        version = self.header.version
        if version in prefetch_version_structs.keys():
            return version

    def parse(self):
        try:
            file_info_header, file_metrics_header = prefetch_version_structs.get(
                self.version
            )
            self.fh.seek(84)
            self.fn = file_info_header(self.fh)
            self.metrics = self.parse_metrics(metric_array_struct=file_metrics_header)
        except KeyError:
            raise NotImplementedError()

    def parse_metrics(self, metric_array_struct):
        metrics = []
        self.fh.seek(self.fn.metrics_array_offset)
        for _ in range(self.fn.number_of_file_metrics_entries):
            entry = metric_array_struct(self.fh)
            filename = self.read_filename(
                self.fn.filename_strings_offset + entry.filename_string_offset,
                entry.filename_string_number_of_characters,
            )
            metrics.append(uri.from_windows(filename.decode("utf-16-le")))
        return metrics

    def read_filename(self, off, size):
        offset = self.fh.tell()
        self.fh.seek(off)
        data = self.fh.read(size * 2)
        self.fh.seek(offset)  # reset pointer
        return data

    @property
    def latest_timestamp(self):
        """Get the latest execution timestamp inside the prefetch file."""
        return self.fn.last_run_time

    @property
    def previous_timestamps(self):
        """Get the previous timestamps from the prefetch file."""
        try:
            # We check if timestamp actually has a value
            return [
                timestamp for timestamp in self.fn.last_run_remains if timestamp != 0
            ]
        except AttributeError:
            # Header version 17 doesn't contain last_run_remains
            return []


class Prefetch(ForensicArtifact):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self, descending: bool = False) -> Path:
        """Return the content of all prefetch files.

        Prefetch is a memory management feature in Windows. It contains information (for example run count and
        timestamp) about executable applications that have been executed recently or are frequently executed.

        Sources:
            - https://www.geeksforgeeks.org/prefetch-files-in-windows/

        Write RecycleBinRecords with fields:
            hostname: The target hostname.
            domain: The target domain.
            ts: Run timestamp.
            filename: The filename.
            prefetch: The prefetch entry.
            linkedfiles: A list of linked files
            runcount: The run count.
            previousruns: Previous run non zero timestamps
        """

        prefetch = sorted(
            [
                json.dumps(
                    record._packdict(), indent=2, default=str, ensure_ascii=False
                )
                for record in self.prefetch()
            ],
            reverse=descending,
        )

        self.result = {"prefetch": prefetch}

    def prefetch(self) -> Generator[GroupedPrefetchRecord, None, None]:
        for entry in self._iter_entry():
            try:
                prefetch = PrefetchParser(fh=entry.open("rb"))
                filename = prefetch.header.name.decode(
                    "utf-16-le", errors="ignore"
                ).split("\x00")[0]
                ts = self.ts.wintimestamp(prefetch.latest_timestamp)
                previousruns = [
                    self.ts.wintimestamp(ts) for ts in prefetch.previous_timestamps
                ]

                yield GroupedPrefetchRecord(
                    ts=ts,
                    filename=filename,
                    prefetch=entry.name,
                    linkedfiles=prefetch.metrics,
                    runcount=prefetch.fn.run_count,
                    previousruns=previousruns,
                    _target=self._target,
                )
            except:
                pass
