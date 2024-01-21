import os
import logging
from datetime import datetime
from typing import Generator, BinaryIO, Optional
from collections import namedtuple
from dataclasses import dataclass, field

from pydantic import ValidationError
from ctypes import c_char, c_uint16, c_uint32, c_uint64, c_ubyte, LittleEndianStructure

from lib.olefile import olefile
from util.sysutil import TDataAccess
from lib.lnk.const import *
from lib.lnk.lnk import TLNKFileParser
from util.delphi import ExtractFileName, ExtractFilePath, ExtractFileExt, StrToIntDef
from lib.jumplist.app_id_list import app_id_list
from core.forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings.artifacts import Tables, ArtifactSchema

logger = logging.getLogger(__name__)

FILE_ATTRIBUTE_READONLY = 0x00000001
FILE_ATTRIBUTE_HIDDEN = 0x00000002
FILE_ATTRIBUTE_SYSTEM = 0x00000004
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_ARCHIVE = 0x00000020


LinkFileEntry = namedtuple(
    "LinkFileEntry",
    [
        "created_time",
        "modified_time",
        "accessed_time",
        # "file_name",
        "file_attributes",
        "file_size",
        "drive_type",
        "volume_label",
        "volume_serial_number",
        "machine_id",
        "mac_address",
    ],
)


class JumpListRecord(ArtifactRecord):
    """JumpList record."""

    last_opened: datetime
    file_name: str
    file_ext: str
    path: str
    size: Optional[str]
    # target_created: str
    # target_modified: str
    # target_accessed: str
    volume_label: Optional[str]
    volume_serial_number: Optional[str]
    drive_type: str
    app_id: str
    app_name: str
    access_count: str
    entry_id: str
    machine_id: str
    mac_address: str

    class Config:
        table_name: str = Tables.WIN_JUMPLIST.value


# DestListEntry : https://bonggang.tistory.com/120
class TDestListEntry(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("Checksum", c_uint64),
        ("NewVolumeID", c_ubyte * 16),
        ("NewObjectID", c_ubyte * 16),
        ("BirthVolumeID", c_ubyte * 16),
        ("BirthObjectID", c_ubyte * 16),
        ("NetBIOSName", c_char * 16),
        ("EntryID", c_uint32),
        ("_f08", c_ubyte * 8),
        ("last_recorded_aceess_time", c_uint64),  # FILETIME
        ("Enty_pin_status", c_uint32),  # FF FF FF FF
        ("_f11", c_uint32),  # FF FF FF FF
        ("access_count", c_uint32),
        ("_f13", c_ubyte * 8),  # 00 00 00 00 00 00 00 00
        ("length_of_unicode", c_uint16),
    ]


@dataclass
class JumpListParser:
    fh: BinaryIO
    dest_list: list = field(default_factory=list)
    link_file_data: dict[int, LinkFileEntry] = field(default_factory=dict)

    def parse(self):
        ole = olefile.OleFileIO(self.fh)
        for item in ole.listdir():
            if item == ["DestList"]:
                self.parse_dest_list(ole, item)
            else:
                self.parse_link_files(ole, item)

        # After completing the parsing of jump list and link files
        # integrate the link file data with the dest list
        self.integrate_link_file_data()

    def parse_dest_list(self, ole, item):
        with ole.openstream(item) as stream:
            data = TDataAccess(stream.read())
            self.process_dest_list_entries(data)

    def process_dest_list_entries(self, data: TDataAccess):
        # Skip the header
        data.position = 32

        # Process each entry
        while True:
            entry = data.read_recdata(TDestListEntry)
            if not entry:
                break
            self.process_single_entry(data, entry)

    def process_single_entry(self, data: TDataAccess, entry: TDestListEntry) -> None:
        try:
            file_name = data.read(entry.length_of_unicode * 2).decode("utf-16")
            filePath = (
                ExtractFilePath(file_name) if file_name.find("://") == -1 else file_name
            )
            computerName = entry.NetBIOSName.decode("utf-8")
            self.dest_list.append(
                [
                    "",
                    entry.last_recorded_aceess_time,
                    entry.access_count,
                    entry.EntryID,
                    computerName,
                    ExtractFileName(file_name),
                    filePath,
                    ExtractFileExt(file_name).lower(),
                ]
            )
        except UnicodeDecodeError as e:
            logger.error(f"Error decoding file name: {e}")
        except Exception as e:
            logger.error(f"Error parsing DestListEntry: {e}")

        # Skip the padding
        data.position += 4

    def parse_link_files(self, ole, item) -> None:
        try:
            entry_id = int(item[0], 16)  # Convert hex string to integer
            with ole.openstream(item) as stream:
                lnk_file_data = stream.read()

            lnk_parser = TLNKFileParser(lnk_file_data, entry_id)
            link_data = lnk_parser.parse_data()["LinkHeaderInfo"]
            self.process_link_data(link_data, entry_id)
        except Exception as e:
            logger.error(f"Error parsing link file: {e}")

    def process_link_data(self, link_data, entry_id) -> None:
        # Initialize variables to store extracted information
        created_time, accessed_time, modified_time = "", "", ""
        file_size, file_attributes, file_name = "", "", ""
        drive_type, volume_label, volume_serial_number = "", "", ""
        machine_id, mac_address = "", ""

        for value in link_data:
            # Extracting information based on the value type or name
            name, val = value[2], value[3]
            if name == "Base Path":
                file_name = val
            elif name == RS_TargetFileCreateDT:
                created_time = val
            elif name == RS_TargetFileAccessDT:
                accessed_time = val
            elif name == RS_TargetFileModifyDT:
                modified_time = val
            elif name == RS_TargetFileSize:
                file_size = val
            elif name == RS_TargetFileProp:
                file_attributes = self.format_file_attributes(int(val, 0))
            elif name == "볼륨 종류":
                drive_type = val
            elif name == "볼륨 이름":
                volume_label = val
            elif name == "Drive Serial Number":
                volume_serial_number = val
            elif name == "Machine Id":
                machine_id = val
            elif name == "Mac Address":
                mac_address = val

        # Add the extracted information to the list
        self.link_file_data[entry_id] = LinkFileEntry(
            created_time,
            modified_time,
            accessed_time,
            # file_name,
            file_attributes,
            file_size,
            drive_type,
            volume_label,
            volume_serial_number,
            machine_id,
            mac_address,
        )

    def format_file_attributes(self, attributes):
        attribute_str = []
        if attributes & FILE_ATTRIBUTE_ARCHIVE:
            attribute_str.append("Archive")
        if attributes & FILE_ATTRIBUTE_READONLY:
            attribute_str.append("Read-only")
        if attributes & FILE_ATTRIBUTE_DIRECTORY:
            attribute_str.append("Directory")
        if attributes & FILE_ATTRIBUTE_SYSTEM:
            attribute_str.append("System")
        if attributes & FILE_ATTRIBUTE_HIDDEN:
            attribute_str.append("Hidden")
        return ", ".join(attribute_str)

    def integrate_link_file_data(self):
        if len(self.dest_list) > 1:
            for index, record in enumerate(self.dest_list):
                if index == 0:
                    # Extend the fields with the names from LinkFileEntry namedtuple
                    record.extend(LinkFileEntry._fields)
                    continue

                entry_id = record[3]  # Assuming this is the correct way to get entry_id

                # Retrieve the entry data from link_file_data, if available
                entry_data = self.link_file_data.get(
                    entry_id, LinkFileEntry("", "", "", "", "", "", "", "", "", "")
                )

                # Extend the record with values from the entry data
                record.extend(entry_data)


class JumpList(ForensicArtifact):
    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    def parse(self, descending: bool = False) -> None:
        try:
            jumplist = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.jumplist())
                ),
                key=lambda record: record.last_opened,
                reverse=descending,
            )
        except Exception as e:
            self.log_error(e)
            return

        self.records.append(jumplist)

    def parse_jumplist_entry(self, entry):
        # Initialize the JumpList parser with the file handle
        parser = JumpListParser(fh=entry.open("rb"))

        # Parse the JumpList entry
        parser.parse()

        # Get the parsed results
        parse_results = parser.dest_list

        if parse_results:
            # Get the application name from the app_id_list
            entry_filename = os.path.split(entry)[1]
            app_id = entry_filename[: entry_filename.rfind(".")]
            application_name = app_id_list.get(app_id, None)

            # Loop through the parsed results
            for result in parse_results:
                yield self.format_record(result, app_id, application_name)

    def format_record(self, result, app_id, application_name):
        try:
            record_time = (
                self.ts.wintimestamp(result[1]) if result[1] is not None else ""
            )
            path = result[6] + result[5]

            parsed_data = {
                "last_opened": self.ts.to_localtime(record_time),
                "file_name": str(self.fe.extract_filename(path=path)),
                "file_ext": str(self.fe.extract_file_extention(path=path)),
                "path": str(path),
                "size": str(result[12]),
                # "target_created": target_created,
                # "target_modified": target_modified,
                # "target_accessed": target_accessed,
                "volume_label": str(result[14]),
                "volume_serial_number": str(result[15]),
                "drive_type": str(result[13]),
                "app_id": str(app_id),
                "app_name": str(application_name),
                "access_count": str(result[2]),
                "entry_id": str(result[3]),
                "machine_id": str(result[16]),
                "mac_address": str(result[17]),
                "evidence_id": self.evidence_id,
            }

            try:
                return JumpListRecord(**parsed_data)
            except ValidationError as e:
                self.log_error(e)
                return
        except Exception as e:
            self.log_error(e)
            return

    def jumplist(self) -> Generator[dict, None, None]:
        for entry in self.check_empty_entry(self.iter_entry()):
            try:
                yield from self.parse_jumplist_entry(entry)
            except Exception as e:
                logger.exception("Error parsing JumpList entry: %s", entry)
                continue
