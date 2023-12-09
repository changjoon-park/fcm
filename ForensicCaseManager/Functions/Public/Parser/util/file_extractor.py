import logging
from datetime import datetime
from pathlib import Path

# for cross platform


class FileExtractor:
    def extract_basename(self, path: str) -> str:
        return Path(path).stem

    def extract_filename(self, path: str) -> str:
        return Path(path).name

    def extract_file_extention(self, path: str) -> str:
        return Path(path).suffix.strip(".")

    def extract_file_size(self, path: str) -> int:
        if (path := Path(path)).exists():
            return path.stat().st_size
        else:
            logging.debug(f"File not found: {path}")
            return None

    def extract_file_mactime(self, path: str) -> tuple[datetime, datetime, datetime]:
        if (path := Path(path)).exists():
            m_timestamp = path.stat().st_mtime
            a_timestamp = path.stat().st_atime
            c_timestamp = path.stat().st_ctime

            m_time = datetime.fromtimestamp(m_timestamp)
            a_time = datetime.fromtimestamp(a_timestamp)
            c_time = datetime.fromtimestamp(c_timestamp)

            return (m_time, a_time, c_time)
        else:
            logging.debug(f"File not found: {path}")
            return (None, None, None)
