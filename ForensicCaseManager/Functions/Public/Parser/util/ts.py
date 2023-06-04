import struct
from datetime import datetime, timedelta, tzinfo, timezone
from platform import system
from typing import Dict

class TimeStamp:
    def __init__(self, tzinfo: timezone) -> None:
        self.tzinfo: timezone = tzinfo
    
    def _calculate_timestamp(self, ts: float) -> datetime:
        try:
            if system().lower() in ("windows", "emscripten"):
                """Calculate timestamps relative from Unix epoch.

                Python on Windows and WASM (Emscripten) have problems calculating timestamps before 1970 (Unix epoch).
                Calculating relatively from the epoch is required to correctly calculate those timestamps.
                This method is slower, so we split the implementation between Windows, WASM and other platforms.
                """
                _EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
                dt = _EPOCH + timedelta(seconds=ts)
            else:
                """Calculate timestamps normally."""
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            return self.to_localtime(dt=dt)
        except:
            """
                'datetime' data type of <TargetRecordDescriptor>
                can only receive datetime except for 'None' type.
                Thus, empty string("") occurs error so this function returns None.
            """
            return None
        
    def to_localtime(self, dt: datetime) -> datetime:
        return datetime.fromtimestamp(dt.timestamp(), tz=self.tzinfo)

    def now(self) -> datetime:
        """Return an aware datetime object of the current time in UTC."""
        return datetime.now(tz=self.tzinfo)

    def unix_now(self) -> int:
        """Return a Unix timestamp of the current time."""
        return self.to_unix(self.now())

    def unix_now_ms(self) -> int:
        """Return a Unix millisecond timestamp of the current time."""
        return self.to_unix_ms(self.now())

    def unix_now_us(self) -> int:
        """Return a Unix microsecond timestamp of the current time."""
        return self.to_unix_us(self.now())

    def unix_now_ns(self) -> int:
        """Return a Unix nanosecond timestamp of the current time."""
        return self.to_unix_ns(self.now())

    def to_unix(self, dt: datetime) -> int:
        """Converts datetime objects into Unix timestamps.

        This is a convenience method.

        Args:
            dt: The datetime object.

        Returns:
            Unix timestamp from the passed datetime object.
        """
        return int(dt.timestamp())

    def to_unix_ms(self, dt: datetime) -> int:
        """Converts datetime objects into Unix millisecond timestamps.

        This is a convenience method.

        Args:
            dt: The datetime object.

        Returns:
            Unix millisecond timestamp from the passed datetime object.
        """
        return int(dt.timestamp() * 1e3)

    def to_unix_us(self, dt: datetime) -> int:
        """Converts datetime objects into Unix microsecond timestamps.

        This is a convenience method.

        Args:
            dt: The datetime object.

        Returns:
            Unix microsecond timestamp from the passed datetime object.
        """
        return int(dt.timestamp() * 1e6)

    def to_unix_ns(self, dt: datetime) -> int:
        """Converts datetime objects into Unix nanosecond timestamps.

        This is a convenience method.

        Args:
            dt: The datetime object.

        Returns:
            Unix nanosecond timestamp from the passed datetime object.
        """
        return self.to_unix_us(dt) * 1000

    def from_unix(self, ts: float) -> datetime:
        """Converts Unix timestamps to aware datetime objects in UTC.

        This is a convenience method.

        Args:
            ts: The Unix timestamp.

        Returns:
            Datetime object from the passed timestamp.
        """
        return self._calculate_timestamp(ts)

    def from_unix_ms(self, ts: float) -> datetime:
        """Converts Unix timestamps in milliseconds to aware datetime objects in UTC.

        Args:
            ts: The Unix timestamp in milliseconds.

        Returns:
            Datetime object from the passed timestamp.
        """
        return self.from_unix(float(ts) * 1e-3)

    def from_unix_us(self, ts: float) -> datetime:
        """Converts Unix timestamps in microseconds to aware datetime objects in UTC.

        Args:
            ts: The Unix timestamp in microseconds.

        Returns:
            Datetime object from the passed timestamp.
        """
        return self.from_unix(float(ts) * 1e-6)

    def from_unix_ns(self, ts: float) -> datetime:
        """Converts Unix timestamps in nanoseconds to aware datetime objects in UTC.

        Args:
            ts: The Unix timestamp in nanoseconds.

        Returns:
            Datetime object from the passed timestamp.
        """
        return self.from_unix(float(ts) * 1e-9)

    def xfstimestamp(self, seconds: int, nano: int) -> datetime:
        """Converts XFS timestamps to aware datetime objects in UTC.

        Args:
            seconds: The XFS timestamp seconds component
            nano: The XFS timestamp nano seconds component
        Returns:
            Datetime object from the passed timestamp.
        """
        return self._calculate_timestamp(float(seconds) + (1e-9 * nano))

    def wintimestamp(self, ts: int) -> datetime:
        """Converts Windows timestamps to aware datetime objects in UTC.

        Args:
            ts: The Windows timestamp.

        Returns:
            Datetime object from the passed timestamp.
        """
        return self._calculate_timestamp(float(ts) * 1e-7 - 11644473600)  # Thanks FireEye

    def oatimestamp(self, ts: float) -> datetime:
        """Converts OLE Automation timestamps to aware datetime objects in UTC.

        Args:
            ts: The OLE Automation timestamp.

        Returns:
            Datetime object from the passed timestamp.
        """
        if not isinstance(ts, float):
            # Convert from int to float
            (ts,) = struct.unpack("<d", struct.pack("<Q", ts & 0xFFFFFFFFFFFFFFFF))
        return self._calculate_timestamp((ts - 25569) * 86400)

    def webkittimestamp(self, ts: int) -> datetime:
        """Converts WebKit timestamps to aware datetime objects in UTC.

        Args:
            ts: The WebKit timestamp.

        Returns:
            Datetime object from the passed timestamp.
        """
        return self._calculate_timestamp(float(ts) * 1e-6 - 11644473600)

    def cocoatimestamp(self, ts: int) -> datetime:
        """Converts Apple Cocoa Core Data timestamps to aware datetime objects in UTC.

        Args:
            ts: The Apple Cocoa Core Data timestamp.

        Returns:
            Datetime object from the passed timestamp.
        """
        return self._calculate_timestamp(float(ts) + 978307200)

    def uuid1timestamp(self, ts: int) -> datetime:
        """Converts UUID version 1 timestamps to aware datetime objects in UTC.

        UUID v1 timestamps have an epoch of 1582-10-15 00:00:00.

        Args:
            ts: The UUID version 1 timestamp

        Returns:
            Datetime object from the passed timestamp.
        """
        return self._calculate_timestamp(float(ts) * 1e-7 - 12219292800)

    def dostimestamp(self, ts: int, centiseconds: int = 0, swap: bool = False) -> datetime:
        """Converts MS-DOS timestamps to naive datetime objects.

        MS-DOS timestamps are recorded in local time, so we leave it up to the
        caller to add optional timezone information.

        According to http://www.vsft.com/hal/dostime.htm

        Args:
            timestap: MS-DOS timestamp
            centisecond: Optional ExFAT centisecond offset. Yes centisecond...
            swap: Optional swap flag if date and time bytes are swapped.

        Returns:
            Datetime object from the passed timestamp.
        """
        DOS_EPOCH_YEAR = 1980

        # MS-DOS Date Time Format is actually 2 UINT16_T's first 16 bits are the time, second 16 bits are date
        # the year is an offset of the MS-DOS epoch year, which is 1980

        if swap:
            year = ((ts >> 9) & 0x7F) + DOS_EPOCH_YEAR
            month = (ts >> 5) & 0x0F
            day = ts & 0x1F

            hours = (ts >> 27) & 0x1F
            minutes = (ts >> 21) & 0x3F
            seconds = ((ts >> 16) & 0x1F) * 2
        else:  # non-swapped way
            year = ((ts >> 25) & 0x7F) + DOS_EPOCH_YEAR
            month = (ts >> 21) & 0x0F
            day = (ts >> 16) & 0x1F

            hours = (ts >> 11) & 0x1F
            minutes = (ts >> 5) & 0x3F
            seconds = (ts & 0x1F) * 2

        # Note that according to the standard, centiseconds can be at most 199, so
        # extra_seconds will be at most 1.
        extra_seconds, centiseconds = divmod(centiseconds, 100)
        microseconds = centiseconds * 10000
        timestamp = datetime(year, month, day, hours, minutes, seconds + extra_seconds, microseconds)

        return timestamp


class UTC(tzinfo):
    """tzinfo class for timezones that have a fixed-offset from UTC

    Args:
        tz_dict: Dictionary of ``{"name": "timezone name", "offset": offset_from_UTC_in_minutes}``
    """

    def __init__(self, tz_dict: Dict[str, int]):
        # offset should be in minutes
        self.name = tz_dict["name"]
        self.offset = timedelta(minutes=tz_dict["offset"])

    def utcoffset(self, dt):
        return self.offset

    def tzname(self, dt):
        return self.name

    def dst(self, dt):
        # do not account for daylight saving
        return timedelta(0)
