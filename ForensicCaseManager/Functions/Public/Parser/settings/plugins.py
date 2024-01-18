from collections import namedtuple

from settings.config import *  # artifacts,
from settings.artifacts import Artifact

from artifacts.filesystem import usnjrnl

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
    reg_amcache,
    reg_userassist,
    reg_shimcache,
    reg_bam,
    reg_usb,
    reg_autorun,
    reg_shellbags,
    reg_systeminfo,
    reg_networkinfo,
    reg_useraccount,
    mru,
)
from artifacts.apps.browsers import chrome, edge, iexplore

Plugin = namedtuple("Plugin", ["ForensicArtifact", "category"])

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


# ! Artifacts: program input(artifact) must be same as these artifact name

WINDOWS_PLUGINS = {
    # ? Browser
    ART_CHROME: Plugin(
        ForensicArtifact=chrome.Chrome,
        category=CAT_BROWSER_ACTIVITY,
    ),
    ART_EDGE: Plugin(
        ForensicArtifact=edge.Edge,
        category=CAT_BROWSER_ACTIVITY,
    ),
    ART_IEXPLORER: Plugin(
        ForensicArtifact=iexplore.InternetExplorer,
        category=CAT_BROWSER_ACTIVITY,
    ),
    # ? FileSystem
    # "MFT": Plugin(artifact=mft.MFT, category="todo"),  # FileSystem
    ART_USNJRNL: Plugin(
        ForensicArtifact=usnjrnl.UsnJrnl,
        category=CAT_DELETED_ITEMS_FILE_EXISTENCE,
    ),
    # ? Windows
    ART_RECYCLEBIN: Plugin(
        ForensicArtifact=recyclebin.RecycleBin,
        category=CAT_DELETED_ITEMS_FILE_EXISTENCE,
    ),
    ART_PREFETCH: Plugin(
        ForensicArtifact=prefetch.Prefetch,
        category=CAT_APPLICATION_EXECUTION,
    ),
    ART_FILE_HISTORY: Plugin(
        ForensicArtifact=file_history.FileHistory,
        category=CAT_FILE_FOLDER_OPENING,
    ),
    ART_SRU_NETWORK: Plugin(
        ForensicArtifact=sru.SRU,
        category=CAT_NETWORK_ACTIVITY_PHYSICAL_LOCATION,
    ),
    ART_SRU_APPLICATION: Plugin(
        ForensicArtifact=sru.SRU,
        category=CAT_APPLICATION_EXECUTION,
    ),
    # "Lnk": Plugin(ForensicArtifact=LinkFile, category=CAT_FILE_FOLDER_OPENING),
    ART_JUMPLIST: Plugin(
        ForensicArtifact=jumplist.JumpList,
        category=CAT_FILE_FOLDER_OPENING,
    ),
    ART_THUMBCACHE: Plugin(
        ForensicArtifact=thumbcache.Thumbcache,
        category=CAT_FILE_FOLDER_OPENING,
    ),
    ART_WINDOWS_TIMELINE: Plugin(
        ForensicArtifact=windows_timeline.WindowsTimeline,
        category=CAT_APPLICATION_EXECUTION,
    ),
    # ? Event Log
    ART_EVENT_LOGON: Plugin(
        ForensicArtifact=eventlog.ForensicEvent,
        category=CAT_ACCOUNT_USAGE,
    ),
    ART_EVENT_USB: Plugin(
        ForensicArtifact=eventlog.ForensicEvent,
        category=CAT_EXTERNAL_DEVICE_USB_USAGE,
    ),
    ART_EVENT_WLAN: Plugin(
        ForensicArtifact=eventlog.ForensicEvent,
        category=CAT_NETWORK_ACTIVITY_PHYSICAL_LOCATION,
    ),
    # ? Windows Registry
    Artifact.REG_AMCACHE.value: Plugin(
        ForensicArtifact=reg_amcache.Amcache,
        category=CAT_APPLICATION_EXECUTION,
    ),
    ART_REGISTRY_USERACCOUNT: Plugin(
        ForensicArtifact=reg_useraccount.UserAccount,
        category=CAT_ACCOUNT_USAGE,
    ),
    ART_REGISTRY_USERASSIST: Plugin(
        ForensicArtifact=reg_userassist.UserAssist,
        category=CAT_APPLICATION_EXECUTION,
    ),
    ART_REGISTRY_SHIMCACHE: Plugin(
        ForensicArtifact=reg_shimcache.ShimCache,
        category=CAT_APPLICATION_EXECUTION,
    ),
    ART_REGISTRY_BAM: Plugin(
        ForensicArtifact=reg_bam.BAM,
        category=CAT_APPLICATION_EXECUTION,
    ),
    ART_REGISTRY_NETWORKINFO: Plugin(
        ForensicArtifact=reg_networkinfo.NetworkInfo,
        category=CAT_NETWORK_ACTIVITY_PHYSICAL_LOCATION,
    ),
    ART_REGISTRY_SHELLBAGS: Plugin(
        ForensicArtifact=reg_shellbags.Shellbags,
        category=CAT_FILE_FOLDER_OPENING,
    ),
    Artifact.REG_USB.value: Plugin(
        ForensicArtifact=reg_usb.USB,
        category=CAT_EXTERNAL_DEVICE_USB_USAGE,
    ),
    ART_REGISTRY_AUTORUN: Plugin(
        ForensicArtifact=reg_autorun.AutoRun,
        category=CAT_SYSTEM_INFORMATION,
    ),
    ART_REGISTRY_SYSTEMINFO: Plugin(
        ForensicArtifact=reg_systeminfo.SystemInfo,
        category=CAT_SYSTEM_INFORMATION,
    ),
    # "MRU": Plugin(ForensicArtifact=MRU, category=CAT_FILE_FOLDER_OPENING),
}
