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
    Artifacts.CHROMIUM.value: Plugin(
        ForensicArtifact=chrome.Chrome,
        category=CAT_BROWSER_ACTIVITY,
    ),
    Artifacts.IEXPLORER.value: Plugin(
        ForensicArtifact=iexplore.InternetExplorer,
        category=CAT_BROWSER_ACTIVITY,
    ),
    # ? FileSystem
    # "MFT": Plugin(artifact=mft.MFT, category="todo"),  # FileSystem
    Artifacts.USNJRNL.value: Plugin(
        ForensicArtifact=usnjrnl.UsnJrnl,
        category=CAT_DELETED_ITEMS_FILE_EXISTENCE,
    ),
    # ? Windows
    Artifacts.RECYCLEBIN.value: Plugin(
        ForensicArtifact=recyclebin.RecycleBin,
        category=CAT_DELETED_ITEMS_FILE_EXISTENCE,
    ),
    Artifacts.PREFETCH.value: Plugin(
        ForensicArtifact=prefetch.Prefetch,
        category=CAT_APPLICATION_EXECUTION,
    ),
    Artifacts.FILEHISTORY.value: Plugin(
        ForensicArtifact=file_history.FileHistory,
        category=CAT_FILE_FOLDER_OPENING,
    ),
    Artifacts.SRU_NETWORK.value: Plugin(
        ForensicArtifact=sru.SRU,
        category=CAT_NETWORK_ACTIVITY_PHYSICAL_LOCATION,
    ),
    Artifacts.SRU_APPLICATION.value: Plugin(
        ForensicArtifact=sru.SRU,
        category=CAT_APPLICATION_EXECUTION,
    ),
    # "Lnk": Plugin(ForensicArtifact=LinkFile, category=CAT_FILE_FOLDER_OPENING),
    Artifacts.JUMPLIST.value: Plugin(
        ForensicArtifact=jumplist.JumpList,
        category=CAT_FILE_FOLDER_OPENING,
    ),
    Artifacts.THUMBCACHE.value: Plugin(
        ForensicArtifact=thumbcache.Thumbcache,
        category=CAT_FILE_FOLDER_OPENING,
    ),
    Artifacts.WINDOWSTIMELINE.value: Plugin(
        ForensicArtifact=windows_timeline.WindowsTimeline,
        category=CAT_APPLICATION_EXECUTION,
    ),
    Artifacts.EVENT_LOGON.value: Plugin(
        ForensicArtifact=eventlog.ForensicEvent,
        category=CAT_ACCOUNT_USAGE,
    ),
    Artifacts.EVENT_USB.value: Plugin(
        ForensicArtifact=eventlog.ForensicEvent,
        category=CAT_EXTERNAL_DEVICE_USB_USAGE,
    ),
    Artifacts.EVENT_WLAN.value: Plugin(
        ForensicArtifact=eventlog.ForensicEvent,
        category=CAT_NETWORK_ACTIVITY_PHYSICAL_LOCATION,
    ),
    # ? Windows Registry
    Artifacts.AMCACHE.value: Plugin(
        ForensicArtifact=reg_amcache.Amcache,
        category=CAT_APPLICATION_EXECUTION,
    ),
    Artifacts.USERACCOUNT.value: Plugin(
        ForensicArtifact=reg_useraccount.UserAccount,
        category=CAT_ACCOUNT_USAGE,
    ),
    Artifacts.USERASSIST.value: Plugin(
        ForensicArtifact=reg_userassist.UserAssist,
        category=CAT_APPLICATION_EXECUTION,
    ),
    Artifacts.SHIMCACHE.value: Plugin(
        ForensicArtifact=reg_shimcache.ShimCache,
        category=CAT_APPLICATION_EXECUTION,
    ),
    Artifacts.BAM.value: Plugin(
        ForensicArtifact=reg_bam.BAM,
        category=CAT_APPLICATION_EXECUTION,
    ),
    Artifacts.NETWORKINFO.value: Plugin(
        ForensicArtifact=reg_networkinfo.NetworkInfo,
        category=CAT_NETWORK_ACTIVITY_PHYSICAL_LOCATION,
    ),
    Artifacts.SHELLBAGS.value: Plugin(
        ForensicArtifact=reg_shellbags.Shellbags,
        category=CAT_FILE_FOLDER_OPENING,
    ),
    Artifacts.USB.value: Plugin(
        ForensicArtifact=reg_usb.USB,
        category=CAT_EXTERNAL_DEVICE_USB_USAGE,
    ),
    Artifacts.AUTORUN.value: Plugin(
        ForensicArtifact=reg_autorun.AutoRun,
        category=CAT_SYSTEM_INFORMATION,
    ),
    Artifacts.SYSTEMINFO.value: Plugin(
        ForensicArtifact=reg_systeminfo.SystemInfo,
        category=CAT_SYSTEM_INFORMATION,
    ),
    # "MRU": Plugin(ForensicArtifact=MRU, category=CAT_FILE_FOLDER_OPENING),
}
