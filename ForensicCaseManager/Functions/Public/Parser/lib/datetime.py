from ctypes import LittleEndianStructure, c_uint32
from lib.filetimes import filetime_to_dt
import datetime

def filetime_to_datetime(filetime, inchour = 0):
  ''' v = filetime_to_datetime(ft, 9).isoformat() '''
  if __debug__: assert type(filetime) is int
  try:
    return filetime_to_dt(filetime) + datetime.timedelta(hours=inchour)
  except Exception:
    return None

# TFileTime
class FILETIME(LittleEndianStructure):
    _fields_ = [
        ('LowDateTime', c_uint32),
        ('HighDateTime', c_uint32)
    ]

def FileTime(v):
    '''
    v = filetime_to_datetime(FileTime(ft), 9).isoformat()
    v = filetime_to_datetime(FileTime(ft), 9)
    v = filetime_to_datetime(FileTime(ft))
    '''
    if __debug__: assert type(v) is FILETIME
    return (v.HighDateTime << 32) + v.LowDateTime
