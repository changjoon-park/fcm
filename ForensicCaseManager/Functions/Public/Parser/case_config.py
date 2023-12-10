import uuid
from collections import namedtuple
from dataclasses import dataclass, field
from pathlib import Path

from database_manager import DatabaseManager
from settings import *  # database name, schema, categories, artifacts,
from artifacts.windows import (
    recyclebin,
    prefetch,
    jumplist,
    thumbcache,
    sru,
    windows_timeline,
    file_history,
    eventlog,
)
from artifacts.windows.registry import (
    amcache,
    user_account,
    userassist,
    shimcache,
    bam,
    network_info,
    shellbags,
    usb,
    autorun,
    system_info,
    mru,
)
from artifacts.application.browsers import chrome, edge, iexplore

Plugin = namedtuple("Plugin", ["artifact", "category"])


@dataclass(kw_only=True)
class CaseConfig:
    root_directory: Path
    case_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    case_name: str
    database: Path = field(init=False)
    db_manager: DatabaseManager = field(init=False)

    # Class-level constant for database name
    DATABASE_NAME = DATABASE_NAME

    # Class-level constant for artifact categories
    ARTIFACT_CATEGORIES = [
        (1, CAT_APPLICATION_EXECUTION),
        (2, CAT_FILE_FOLDER_OPENING),
        (3, CAT_DELETED_ITEMS_FILE_EXISTENCE),
        (4, CAT_BROWSER_ACTIVITY),
        (5, CAT_CLOUD_STORAGE),
        (6, CAT_ACCOUNT_USAGE),
        (7, CAT_NETWORK_ACTIVITY_PHYSICAL_LOCATION),
        (8, CAT_SYSTEM_INFORMATION),
        (9, CAT_EXTERNAL_DEVICE_USB_USAGE),
    ]

    # Class-level constant for artifact schema
    ARTIFACT_SCHEMA = {
        ART_RECYCLEBIN: [
            ARTIFACT_SCHEMA_WINDOWS / "recyclebin.yaml",
        ],
        ART_PREFETCH: [
            ARTIFACT_SCHEMA_WINDOWS / "prefetch.yaml",
        ],
        ART_SRU_NETWORK: [
            ARTIFACT_SCHEMA_WINDOWS / "sru_network_data.yaml",
            ARTIFACT_SCHEMA_WINDOWS / "sru_network_connectivity.yaml",
        ],
        ART_SRU_APPLICATION: [
            ARTIFACT_SCHEMA_WINDOWS / "sru_application.yaml",
        ],
        ART_FILE_HISTORY: [
            ARTIFACT_SCHEMA_WINDOWS / "file_history.yaml",
        ],
        ART_JUMPLIST: [
            ARTIFACT_SCHEMA_WINDOWS / "jumplist.yaml",
        ],
        ART_WINDOWS_TIMELINE: [
            ARTIFACT_SCHEMA_WINDOWS / "windows_timeline.yaml",
        ],
    }

    # Class-level constant for plugins
    PLUGINS = {
        ART_CHROME: Plugin(
            artifact=chrome.Chrome,
            category=CAT_BROWSER_ACTIVITY,
        ),  # ! Browser
        ART_EDGE: Plugin(
            artifact=edge.Edge,
            category=CAT_BROWSER_ACTIVITY,
        ),
        ART_IEXPLORER: Plugin(
            artifact=iexplore.InternetExplorer,
            category=CAT_BROWSER_ACTIVITY,
        ),
        # "MFT": Plugin(artifact=mft.MFT, category="todo"),  # FileSystem
        # "UsnJrnl": Plugin(artifact=UsnJrnl, category=CAT_DELETED_ITEMS_FILE_EXISTENCE),
        ART_RECYCLEBIN: Plugin(
            artifact=recyclebin.RecycleBin,
            category=CAT_DELETED_ITEMS_FILE_EXISTENCE,
        ),  # ! Windows
        ART_PREFETCH: Plugin(
            artifact=prefetch.Prefetch,
            category=CAT_APPLICATION_EXECUTION,
        ),
        ART_FILE_HISTORY: Plugin(
            artifact=file_history.FileHistory,
            category=CAT_FILE_FOLDER_OPENING,
        ),
        ART_SRU_NETWORK: Plugin(
            artifact=sru.SRU,
            category=CAT_NETWORK_ACTIVITY_PHYSICAL_LOCATION,
        ),
        ART_SRU_APPLICATION: Plugin(
            artifact=sru.SRU,
            category=CAT_APPLICATION_EXECUTION,
        ),
        # "Lnk": Plugin(artifact=LinkFile, category=CAT_FILE_FOLDER_OPENING),
        ART_JUMPLIST: Plugin(
            artifact=jumplist.JumpList,
            category=CAT_FILE_FOLDER_OPENING,
        ),
        ART_WINDOWS_TIMELINE: Plugin(
            artifact=windows_timeline.WindowsTimeline,
            category=CAT_APPLICATION_EXECUTION,
        ),
        ART_LOGON_EVENT: Plugin(
            artifact=eventlog.ForensicEvent,
            category=CAT_ACCOUNT_USAGE,
        ),  # ! EventLog
        ART_USB_EVENT: Plugin(
            artifact=eventlog.ForensicEvent,
            category=CAT_EXTERNAL_DEVICE_USB_USAGE,
        ),
        ART_WLAN: Plugin(
            artifact=eventlog.ForensicEvent,
            category=CAT_NETWORK_ACTIVITY_PHYSICAL_LOCATION,
        ),
        ART_AMCACHE: Plugin(
            artifact=amcache.Amcache,
            category=CAT_APPLICATION_EXECUTION,
        ),  # ! Registry
        ART_USER_ACCOUNT: Plugin(
            artifact=user_account.UserAccount,
            category=CAT_ACCOUNT_USAGE,
        ),
        ART_USER_ASSIST: Plugin(
            artifact=userassist.UserAssist,
            category=CAT_APPLICATION_EXECUTION,
        ),
        ART_SHIMCACHE: Plugin(
            artifact=shimcache.ShimCache,
            category=CAT_APPLICATION_EXECUTION,
        ),
        ART_BAM: Plugin(
            artifact=bam.BAM,
            category=CAT_APPLICATION_EXECUTION,
        ),
        ART_NETWORK_INFO: Plugin(
            artifact=network_info.NetworkInfo,
            category=CAT_NETWORK_ACTIVITY_PHYSICAL_LOCATION,
        ),
        ART_SHELLBAGS: Plugin(
            artifact=shellbags.ShellBags,
            category=CAT_FILE_FOLDER_OPENING,
        ),
        ART_USB_REGISTRY: Plugin(
            artifact=usb.USB,
            category=CAT_EXTERNAL_DEVICE_USB_USAGE,
        ),
        ART_AUTORUN: Plugin(
            artifact=autorun.AutoRun,
            category=CAT_SYSTEM_INFORMATION,
        ),
        ART_SYSTEM_INFO: Plugin(
            artifact=system_info.SystemInfo,
            category=CAT_SYSTEM_INFORMATION,
        ),
        # "MRU": Plugin(artifact=MRU, category=CAT_FILE_FOLDER_OPENING),
    }

    def __post_init__(self):
        self.database = self.root_directory / self.case_name / self.DATABASE_NAME
        self.db_manager = DatabaseManager(database=self.database)
