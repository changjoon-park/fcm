from datetime import datetime
from pathlib import Path

# for cross platform

def extract_basename(path: str) -> str:
    path = Path(path)
    return path.stem

def extract_filename(path: str) -> str:
    path = Path(path)
    return path.name
    
def extract_fileext(path: str) -> str:
    path = Path(path)
    return path.suffix.strip(".")

def extract_mactime(path: str) -> tuple[datetime, datetime, datetime]:
    if (path := Path(path)).exists():
        m_timestamp = path.stat().st_mtime
        a_timestamp = path.stat().st_atime
        c_timestamp = path.stat().st_ctime
        
        m_time = datetime.fromtimestamp(m_timestamp)
        a_time = datetime.fromtimestamp(a_timestamp)
        c_time = datetime.fromtimestamp(c_timestamp)
        
        return (m_time, a_time, c_time)
    else:
        return (None, None, None)