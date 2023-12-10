from settings import *  # artifacts,

from collections import namedtuple

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

# ! Artifact Caegories:

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


# ! Aritfact Schema:

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
    ART_EVENT_LOGON: [
        ARTIFACT_SCHEMA_WINDOWS / "event_logon.yaml",
    ],
    ART_EVENT_USB: [
        ARTIFACT_SCHEMA_WINDOWS / "event_usb.yaml",
    ],
}


# ! Artifacts: program input(artifact) must be same as these artifact name

WINDOWS_PLUGINS = {
    # ? Browser
    ART_CHROME: Plugin(
        artifact=chrome.Chrome,
        category=CAT_BROWSER_ACTIVITY,
    ),
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
    # ? Windows
    ART_RECYCLEBIN: Plugin(
        artifact=recyclebin.RecycleBin,
        category=CAT_DELETED_ITEMS_FILE_EXISTENCE,
    ),
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
    # ? Event Log
    ART_EVENT_LOGON: Plugin(
        artifact=eventlog.ForensicEvent,
        category=CAT_ACCOUNT_USAGE,
    ),
    ART_EVENT_USB: Plugin(
        artifact=eventlog.ForensicEvent,
        category=CAT_EXTERNAL_DEVICE_USB_USAGE,
    ),
    ART_EVENT_WLAN: Plugin(
        artifact=eventlog.ForensicEvent,
        category=CAT_NETWORK_ACTIVITY_PHYSICAL_LOCATION,
    ),
    # ? Windows Registry
    ART_AMCACHE: Plugin(
        artifact=amcache.Amcache,
        category=CAT_APPLICATION_EXECUTION,
    ),
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
