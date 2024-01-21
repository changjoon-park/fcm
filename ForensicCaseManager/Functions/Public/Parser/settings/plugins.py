from collections import namedtuple

from settings.artifacts import Artifacts
from settings.config import *
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

# ! Artifacst Caegories:

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
    Artifacts.APP_CHROME.value: Plugin(
        ForensicArtifact=chrome.Chrome,
        category=CAT_BROWSER_ACTIVITY,
    ),
    Artifacts.APP_EDGE.value: Plugin(
        ForensicArtifact=edge.Edge,
        category=CAT_BROWSER_ACTIVITY,
    ),
    Artifacts.APP_IEXPLORER.value: Plugin(
        ForensicArtifact=iexplore.InternetExplorer,
        category=CAT_BROWSER_ACTIVITY,
    ),
    # ? FileSystem
    # "MFT": Plugin(artifact=mft.MFT, category="todo"),  # FileSystem
    Artifacts.FS_USNJRNL.value: Plugin(
        ForensicArtifact=usnjrnl.UsnJrnl,
        category=CAT_DELETED_ITEMS_FILE_EXISTENCE,
    ),
    # ? Windows
    Artifacts.WIN_RECYCLEBIN.value: Plugin(
        ForensicArtifact=recyclebin.RecycleBin,
        category=CAT_DELETED_ITEMS_FILE_EXISTENCE,
    ),
    Artifacts.WIN_PREFETCH.value: Plugin(
        ForensicArtifact=prefetch.Prefetch,
        category=CAT_APPLICATION_EXECUTION,
    ),
    Artifacts.WIN_FILE_HISTORY.value: Plugin(
        ForensicArtifact=file_history.FileHistory,
        category=CAT_FILE_FOLDER_OPENING,
    ),
    Artifacts.WIN_SRU_NETWORK.value: Plugin(
        ForensicArtifact=sru.SRU,
        category=CAT_NETWORK_ACTIVITY_PHYSICAL_LOCATION,
    ),
    Artifacts.WIN_SRU_APPLICATION.value: Plugin(
        ForensicArtifact=sru.SRU,
        category=CAT_APPLICATION_EXECUTION,
    ),
    # "Lnk": Plugin(ForensicArtifact=LinkFile, category=CAT_FILE_FOLDER_OPENING),
    Artifacts.WIN_JUMPLIST.value: Plugin(
        ForensicArtifact=jumplist.JumpList,
        category=CAT_FILE_FOLDER_OPENING,
    ),
    Artifacts.WIN_THUMBCACHE.value: Plugin(
        ForensicArtifact=thumbcache.Thumbcache,
        category=CAT_FILE_FOLDER_OPENING,
    ),
    Artifacts.WIN_WINDOWSTIMELINE.value: Plugin(
        ForensicArtifact=windows_timeline.WindowsTimeline,
        category=CAT_APPLICATION_EXECUTION,
    ),
    # ? Event Log
    Artifacts.WIN_EVENT_LOGON.value: Plugin(
        ForensicArtifact=eventlog.ForensicEvent,
        category=CAT_ACCOUNT_USAGE,
    ),
    Artifacts.WIN_EVENT_USB.value: Plugin(
        ForensicArtifact=eventlog.ForensicEvent,
        category=CAT_EXTERNAL_DEVICE_USB_USAGE,
    ),
    Artifacts.WIN_EVENT_WLAN.value: Plugin(
        ForensicArtifact=eventlog.ForensicEvent,
        category=CAT_NETWORK_ACTIVITY_PHYSICAL_LOCATION,
    ),
    # ? Windows Registry
    Artifacts.REG_AMCACHE.value: Plugin(
        ForensicArtifact=reg_amcache.Amcache,
        category=CAT_APPLICATION_EXECUTION,
    ),
    Artifacts.REG_USERACCOUNT.value: Plugin(
        ForensicArtifact=reg_useraccount.UserAccount,
        category=CAT_ACCOUNT_USAGE,
    ),
    Artifacts.REG_USERASSIST.value: Plugin(
        ForensicArtifact=reg_userassist.UserAssist,
        category=CAT_APPLICATION_EXECUTION,
    ),
    Artifacts.REG_SHIMCACHE.value: Plugin(
        ForensicArtifact=reg_shimcache.ShimCache,
        category=CAT_APPLICATION_EXECUTION,
    ),
    Artifacts.REG_BAM.value: Plugin(
        ForensicArtifact=reg_bam.BAM,
        category=CAT_APPLICATION_EXECUTION,
    ),
    Artifacts.REG_NETWORKINFO.value: Plugin(
        ForensicArtifact=reg_networkinfo.NetworkInfo,
        category=CAT_NETWORK_ACTIVITY_PHYSICAL_LOCATION,
    ),
    Artifacts.REG_SHELLBAGS.value: Plugin(
        ForensicArtifact=reg_shellbags.Shellbags,
        category=CAT_FILE_FOLDER_OPENING,
    ),
    Artifacts.REG_USB.value: Plugin(
        ForensicArtifact=reg_usb.USB,
        category=CAT_EXTERNAL_DEVICE_USB_USAGE,
    ),
    Artifacts.REG_AUTORUN.value: Plugin(
        ForensicArtifact=reg_autorun.AutoRun,
        category=CAT_SYSTEM_INFORMATION,
    ),
    Artifacts.REG_SYSTEMINFO.value: Plugin(
        ForensicArtifact=reg_systeminfo.SystemInfo,
        category=CAT_SYSTEM_INFORMATION,
    ),
    # "MRU": Plugin(ForensicArtifact=MRU, category=CAT_FILE_FOLDER_OPENING),
}
