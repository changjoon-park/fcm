import os
import logging
from datetime import datetime
from typing import Generator, BinaryIO, Optional
from pathlib import Path
from io import BytesIO

from pydantic import ValidationError
from dissect import cstruct
from flow.record.fieldtypes import uri

from forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings.artifacts import Tables, ArtifactSchema

logger = logging.getLogger(__name__)

c_prefetch = """
    struct PREFETCH_HEADER_DETECT {
        char signature[4];
        uint32 size;
    };

    struct PREFETCH_HEADER {
        uint32 version;
        char signature[4];
        uint32 unknown;
        uint32 size;
        char name[60];
        uint32 hash;
        uint32 flag;
    };

    struct FILE_INFORMATION_26 {
        uint32 metrics_array_offset;
        uint32 number_of_file_metrics_entries;
        uint32 trace_chain_array_offset;
        uint32 number_of_trace_chain_array_entries;
        uint32 filename_strings_offset;
        uint32 filename_strings_size;
        uint32 volumes_information_offset;
        uint32 number_of_volumes;
        uint32 volumes_information_size;
        uint32 unknown[2];
        uint64 last_run_time;
        uint64 last_run_remains[7];
        uint64 unknown[2];
        uint32 run_count;
        uint32 unknown;
        uint32 unknown;
        char unknown[88];
    };

    struct FILE_INFORMATION_17 {
        uint32 metrics_array_offset;
        uint32 number_of_file_metrics_entries;
        uint32 trace_chain_array_offset;
        uint32 number_of_trace_chain_array_entries;
        uint32 filename_strings_offset;
        uint32 filename_strings_size;
        uint32 volumes_information_offset;
        uint32 number_of_volumes;
        uint32 volumes_information_size;
        uint32 last_run_time;
        uint32 unknown;
        uint32 run_count;
        uint32 unknown;
    };

    struct FILE_INFORMATION_23 {
        uint32 metrics_array_offset;
        uint32 number_of_file_metrics_entries;
        uint32 trace_chain_array_offset;
        uint32 number_of_trace_chain_array_entries;
        uint32 filename_strings_offset;
        uint32 filename_strings_size;
        uint32 volumes_information_offset;
        uint32 number_of_volumes;
        uint32 volumes_information_size;
        uint32 unknown[2];
        uint64 last_run_time;
        uint64 last_run_remains[2];
        uint32 run_count;
        uint32 unknown;
        uint32 unknown;
        char unknown[80];
    };

    struct VOLUME_INFORMATION_17 {
        uint32 device_path_offset;
        uint32 device_path_number_of_characters;
        uint64 creation_time;
        uint32 serial_number;
        uint32 file_reference_offset;
        uint32 file_reference_size;
        uint32 directory_strings_array_offset;
        uint32 number_of_directory_strings;
        uint32 unknown;
    };

    struct VOLUME_INFORMATION_30 {
        uint32 device_path_offset;
        uint32 device_path_number_of_characters;
        uint64 creation_time;
        uint32 serial_number;
        uint32 file_reference_offset;
        uint32 file_reference_size;
        uint32 directory_strings_array_offset;
        uint32 number_of_directory_strings;
        char unknown[4];
        char unknown[24];
        char unknown[4];
        char unknown[24];
        char unknown[4];
    };

    struct TRACE_CHAIN_ARRAY_ENTRY_17 {
        uint32 next_array_entry_index;
        uint32 total_block_load_count;
        uint32 unknown;
        uint32 unknown;
        uint32 unknown;
    };

    struct FILE_METRICS_ARRAY_ENTRY_17 {
        uint32 start_time;
        uint32 duration;
        uint32 filename_string_offset;
        uint32 filename_string_number_of_characters;
        uint32 flags;
    };

    struct FILE_METRICS_ARRAY_ENTRY_23 {
        uint32 start_time;
        uint32 duration;
        uint32 average_duration;
        uint32 filename_string_offset;
        uint32 filename_string_number_of_characters;
        uint32 flags;
        uint64 ntfs_reference;
    };
    """
prefetch = cstruct.cstruct()
prefetch.load(c_prefetch)

prefetch_version_structs = {
    17: (prefetch.FILE_INFORMATION_17, prefetch.FILE_METRICS_ARRAY_ENTRY_17),
    23: (prefetch.FILE_INFORMATION_23, prefetch.FILE_METRICS_ARRAY_ENTRY_23),
    30: (prefetch.FILE_INFORMATION_26, prefetch.FILE_METRICS_ARRAY_ENTRY_23),
}


class PrefetchRecord(ArtifactRecord):
    """Prefetch record."""

    ts: datetime
    filename: str
    prefetch: str
    linkedfiles: list[str]
    runcount: int
    previousruns: Optional[list[datetime]]

    class Config:
        table_name: str = Tables.WIN_PREFETCH.value


class PrefetchParser:
    def __init__(self, fh: BinaryIO):
        header_detect = prefetch.PREFETCH_HEADER_DETECT(fh.read(8))
        if header_detect.signature == b"MAM\x04":
            if os.name == "nt":
                from util.lzxpress_huffman import LZXpressHuffman

                fh.seek(0)
                fh = LZXpressHuffman.decompress(fh=fh)
            else:
                from dissect.util import lzxpress_huffman

                fh = BytesIO(lzxpress_huffman.decompress(fh))

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
    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

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
        try:
            prefetch = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.prefetch())
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
        except Exception as e:
            self.log_error(e)
            return

        self.records.append(prefetch)

    def prefetch(self) -> Generator[dict, None, None]:
        for entry in self.check_empty_entry(self.iter_entry()):
            try:
                prefetch = PrefetchParser(fh=entry.open("rb"))
                filename = prefetch.header.name.decode(
                    "utf-16-le", errors="ignore"
                ).split("\x00")[0]
                ts = self.ts.wintimestamp(prefetch.latest_timestamp)
                previousruns = [
                    self.ts.wintimestamp(ts) for ts in prefetch.previous_timestamps
                ]

                parsed_data = {
                    "ts": ts,
                    "filename": filename,
                    "prefetch": entry.name,
                    "linkedfiles": prefetch.metrics,
                    "runcount": prefetch.fn.run_count,
                    "previousruns": previousruns,
                    "evidence_id": self.evidence_id,
                }

                try:
                    yield PrefetchRecord(**parsed_data)
                except ValidationError as e:
                    self.log_error(e)
                    continue
            except Exception as e:
                self.log_error(e)
                continue
