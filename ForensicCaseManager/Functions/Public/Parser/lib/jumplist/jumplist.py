from typing import BinaryIO
import os.path
from ctypes import c_char, c_uint16, c_uint32, c_uint64, c_ubyte, LittleEndianStructure
from lib.olefile import olefile
from util.sysutil import TDataAccess
from lib.lnk.const import *
from lib.lnk.lnk import TLNKFileParser
from util.delphi import ExtractFileName, ExtractFilePath, ExtractFileExt, StrToIntDef


FILE_ATTRIBUTE_READONLY = 0x00000001
FILE_ATTRIBUTE_HIDDEN = 0x00000002
FILE_ATTRIBUTE_SYSTEM = 0x00000004
FILE_ATTRIBUTE_DIRECTORY = 0x00000010
FILE_ATTRIBUTE_ARCHIVE = 0x00000020


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


class TJumpListParser:
    def __init__(self, fh: BinaryIO):
        self.fh = fh
        self.dest_list = []
        self.parse()

    def parse(self):
        # .automaticdestinations-ms
        _tmp = {}
        ole = olefile.OleFileIO(self.fh)
        for item in ole.listdir():
            if item == ["DestList"]:
                with ole.openstream(item) as self.fh:
                    data = TDataAccess(self.fh.read())
                data.position = 32
                while True:
                    entry = data.read_recdata(TDestListEntry)
                    if not entry:
                        break
                    try:
                        fileName = data.read(entry.length_of_unicode * 2).decode(
                            "utf-16"
                        )
                        filePath = (
                            ExtractFilePath(fileName)
                            if fileName.find("://") == -1
                            else fileName
                        )
                        computerName = entry.NetBIOSName.decode("utf-8")
                        self.dest_list.append(
                            [
                                "",
                                entry.last_recorded_aceess_time,
                                entry.access_count,
                                entry.EntryID,
                                computerName,
                                ExtractFileName(fileName),
                                filePath,
                                ExtractFileExt(fileName).lower(),
                            ]
                        )
                    except Exception:
                        pass
                    data.position += 4
            else:
                entryid = int(item[0], 16)  # entryid는 entry.EntryID 다.
                f = ole.openstream(item)
                LNKFileParser = TLNKFileParser(f.read(), entryid)
                r = LNKFileParser.parse_data()["LinkHeaderInfo"]
                del r[0]

                fname = ""
                ctime = ""
                atime = ""
                mtime = ""
                fattr = ""
                fsize = ""
                drive_type = ""
                volume_label = ""
                drive_serial_number = ""
                machine_id = ""
                mac_address = ""

                for v in r:
                    name = v[2]
                    val = v[3]
                    if (ctime == "") and (name == RS_TargetFileCreateDT):
                        ctime = val
                    if (atime == "") and (name == RS_TargetFileAccessDT):
                        atime = val
                    if (mtime == "") and (name == RS_TargetFileModifyDT):
                        mtime = val
                    if (fsize == "") and (name == RS_TargetFileSize):
                        fsize = val
                    if (fattr == "") and (name == RS_TargetFileProp):
                        fattr = val
                    if (fname == "") and (name == "Base Path"):
                        fname = val
                    if (fname == "") and (name == "볼륨 종류"):
                        drive_type = val
                    if (fname == "") and (name == "볼륨 이름"):
                        volume_label = val
                    if (fname == "") and (name == "Drive Serial Number"):
                        drive_serial_number = val
                    if (fname == "") and (name == "Machine Id"):
                        machine_id = val
                    if (fname == "") and (name == "Mac Address"):
                        mac_address = val
                del r
                fattr_str = ""
                fattr = StrToIntDef(fattr, 0)
                if fattr:
                    if fattr & FILE_ATTRIBUTE_ARCHIVE:
                        fattr_str += "A"
                    if fattr & FILE_ATTRIBUTE_READONLY:
                        fattr_str += "R"
                    if fattr & FILE_ATTRIBUTE_DIRECTORY:
                        fattr_str += "D"
                    if fattr & FILE_ATTRIBUTE_SYSTEM:
                        fattr_str += "S"
                    if fattr & FILE_ATTRIBUTE_HIDDEN:
                        fattr_str += "H"
                    fattr_str = "%s (%x)" % (fattr_str, fattr)
                del fattr
                _tmp[entryid] = {
                    "CreatedTime": ctime,
                    "ModifiedTime": mtime,
                    "AccessedTime": atime,
                    "FileAttr": fattr_str,
                    "FileSize": fsize,
                    "DriveType": drive_type,
                    "VolumeLabel": volume_label,
                    "VolumeSerialNumber": drive_serial_number,
                    "MachineId": machine_id,
                    "MacAddress": mac_address,
                }

        if len(self.dest_list) > 1:
            for i, r in enumerate(self.dest_list):
                if i == 0:
                    r.extend(list(_tmp[entryid].keys()))  # 필드 확장
                    continue
                entryid = r[3]
                try:
                    v = list(_tmp[entryid].values())
                except Exception as e:
                    v = ["", "", "", "", ""]
                r.extend(v)
        del _tmp
