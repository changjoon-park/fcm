import io
import struct
from typing import BinaryIO
from lib import \
    compressors as comp  # https://github.com/coderforlife/ms-compress/blob/master/test/compressors.py

class LZXpressHuffman:

    @classmethod
    def decompress(cls, fh: BinaryIO):
        obj = cls()
        
        if obj.__iscompfile(fh=fh):
            data = obj.__decomp_MAMFile(fh=fh)
        else:
            raise "Not Prefetch File"
        return data
        
    def __decomp_MAMFile(self, fh: BinaryIO):
        """
            MAM\x84 : superfetch
            MAM\x04 : prefetch
        """

        fh.seek(0)
        data = fh.read()

        try:
            id = data[0:3].decode('utf8')  # MAM
        except Exception:
            id = ''
        b1 = ord(data[3:4])  # b'\x84' , b'\x04'
        if (id != 'MAM') or (not b1 in [0x84, 0x04]):
            return None

        decomp_size = struct.unpack('<i', data[4:8])[0]
        compdata_stpos = 8
        if b1 == 0x84:
            compdata_stpos += 4

        data = data[compdata_stpos:]
        dest_data = bytearray(decomp_size)
        dest_data = comp.XpressHuffman['OpenSrc'].Decompress(data, dest_data)
        return io.BytesIO(bytes(dest_data))

    def __iscompfile(self, fh: BinaryIO):
        try:
            fh.seek(0)
            h = fh.read(3).decode('utf8')
        except UnicodeDecodeError:
            h = ''
        return h == 'MAM'
