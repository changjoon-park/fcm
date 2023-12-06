from ctypes import sizeof, c_char_p, c_uint32, c_ushort, c_ubyte, cast, POINTER, LittleEndianStructure
import struct

class TGUID(LittleEndianStructure):
    _fields_ = [
        ('D1', c_uint32),
        ('D2', c_ushort),
        ('D3', c_ushort),
        ('D4', c_ubyte * 8)
    ]


def GUIDToString(v):
    r = '%.8X-%.4X-%.4X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X%.2X' % (
    v.D1, v.D2, v.D3, v.D4[0], v.D4[1], v.D4[2], v.D4[3], v.D4[4], v.D4[5], v.D4[6], v.D4[7])
    return r


def _cast(buf, fmt):
    return cast(c_char_p(buf), POINTER(fmt)).contents


class TDataAccess:
    def __init__(self, blob='', pos=0):
        self.position = pos
        self.data = blob
        self.size = len(blob)

    def __del__(self):
        self.data = ''
        pass

    def loadFile(self, fileName):
        f = open(fileName, 'rb')
        self.data = f.read()
        self.size = len(self.data)
        f.close()
        return len(self.data)

    def read(self, length, fmt='', offset=-1):
        """
      이진데이터(blob)내 지정 위치(offset)의 데이터를 읽는다.
      v = read(1, 'B')
      v = read(1, 'B', pos)
      v = read(4, offset = pos)
    """
        if offset == -1: offset = self.position
        self.position = offset + length
        blob = self.data if (offset == 0) and (self.position == self.size) else self.data[offset: self.position]
        if blob != b'':
            if fmt == '':
                v = blob
            else:
                v = struct.unpack(fmt, blob)
                if len(v) == 1: v = v[0]
            return v
        else:
            return None

    def read_recdata(self, rectype, offset=-1):
        """
      이진데이터(blob)내 지정 위치(offset)의 레코드 데이터를 읽는다.
      from ctypes import *
      class TDestListEntry(LittleEndianStructure):
        ('Checksum', c_uint64),
        ('NewVolumeID', c_ubyte * 16),
        ('NewObjectID', c_ubyte * 16)

      e = read_recdata(sizeof(TDestListEntry), TDestListEntry)
      e = read_recdata(sizeof(TDestListEntry), TDestListEntry, pos)
    """
        if offset == -1: offset = self.position
        self.position = offset + sizeof(rectype)
        return _cast(self.data[offset: self.position], rectype) if self.position <= self.size else None

    def tell(self):
        return self.position

    def savetofile(self, filename):
        with open(filename, 'wb') as f:
            f.write(self.data)
