from enum import Enum
from collections import namedtuple

from artifacts.filesystem import mft, usnjrnl
from artifacts.windows import (
    recyclebin,
    prefetch,
    jumplist,
    thumbcache,
    sru,
    windows_timeline,
    filehistory,
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


Artifact = namedtuple("Artifact", ["name", "category", "ForensicArtifact"])


class Categories(Enum):
    APPLICATION_EXECUTION = 1
    FILE_FOLDER_OPENING = 2
    DELETED_ITEMS_FILE_EXISTENCE = 3
    BROWSER_ACTIVITY = 4
    CLOUD_STORAGE = 5
    ACCOUNT_USAGE = 6
    NETWORK_ACTIVITY_PHYSICAL_LOCATION = 7
    SYSTEM_INFORMATION = 8
    EXTERNAL_DEVICE_USB_USAGE = 9


class Artifacts(Enum):
    ## Applications
    CHROME = Artifact(
        name="chrome",
        category=Categories.BROWSER_ACTIVITY.value,
        ForensicArtifact=chrome.Chrome,
    )
    EDGE = Artifact(
        name="edge",
        category=Categories.BROWSER_ACTIVITY.value,
        ForensicArtifact=edge.Edge,
    )
    IEXPLORER = Artifact(
        name="iexplorer",
        category=Categories.BROWSER_ACTIVITY.value,
        ForensicArtifact=iexplore.InternetExplorer,
    )

    ## Filesystem
    MFT = Artifact(
        name="mft",
        category=Categories.FILE_FOLDER_OPENING.value,
        ForensicArtifact=mft.MFT,
    )
    USNJRNL = Artifact(
        name="usnjrnl",
        category=Categories.DELETED_ITEMS_FILE_EXISTENCE.value,
        ForensicArtifact=usnjrnl.UsnJrnl,
    )

    ## Windows
    RECYCLEBIN = Artifact(
        name="recyclebin",
        category=Categories.DELETED_ITEMS_FILE_EXISTENCE.value,
        ForensicArtifact=recyclebin.RecycleBin,
    )
    PREFETCH = Artifact(
        name="prefetch",
        category=Categories.APPLICATION_EXECUTION.value,
        ForensicArtifact=prefetch.Prefetch,
    )
    SRU_NETWORK = Artifact(
        name="sru_network",
        category=Categories.NETWORK_ACTIVITY_PHYSICAL_LOCATION.value,
        ForensicArtifact=sru.SRU,
    )
    SRU_APPLICATION = Artifact(
        name="sru_application",
        category=Categories.APPLICATION_EXECUTION.value,
        ForensicArtifact=sru.SRU,
    )
    FILEHISTORY = Artifact(
        name="filehistory",
        category=Categories.FILE_FOLDER_OPENING.value,
        ForensicArtifact=filehistory.FileHistory,
    )
    THUMBCACHE = Artifact(
        name="thumbcache",
        category=Categories.FILE_FOLDER_OPENING.value,
        ForensicArtifact=thumbcache.Thumbcache,
    )
    JUMPLIST = Artifact(
        name="jumplist",
        category=Categories.FILE_FOLDER_OPENING.value,
        ForensicArtifact=jumplist.JumpList,
    )
    WINDOWSTIMELINE = Artifact(
        name="windowstimeline",
        category=Categories.FILE_FOLDER_OPENING.value,
        ForensicArtifact=windows_timeline.WindowsTimeline,
    )

    ## Event Log
    EVENT_LOGON = Artifact(
        name="event_logon",
        category=Categories.ACCOUNT_USAGE.value,
        ForensicArtifact=eventlog.ForensicEvent,
    )
    EVENT_USB = Artifact(
        name="event_usb",
        category=Categories.EXTERNAL_DEVICE_USB_USAGE.value,
        ForensicArtifact=eventlog.ForensicEvent,
    )
    EVENT_WLAN = Artifact(
        name="event_wlan",
        category=Categories.NETWORK_ACTIVITY_PHYSICAL_LOCATION.value,
        ForensicArtifact=eventlog.ForensicEvent,
    )

    ## Registry
    AMCACHE = Artifact(
        name="amcache",
        category=Categories.APPLICATION_EXECUTION.value,
        ForensicArtifact=reg_amcache.Amcache,
    )
    USERACCOUNT = Artifact(
        name="useraccount",
        category=Categories.ACCOUNT_USAGE.value,
        ForensicArtifact=reg_useraccount.UserAccount,
    )
    USERASSIST = Artifact(
        name="userassist",
        category=Categories.APPLICATION_EXECUTION.value,
        ForensicArtifact=reg_userassist.UserAssist,
    )
    SHIMCACHE = Artifact(
        name="shimcache",
        category=Categories.APPLICATION_EXECUTION.value,
        ForensicArtifact=reg_shimcache.ShimCache,
    )
    BAM = Artifact(
        name="bam",
        category=Categories.APPLICATION_EXECUTION.value,
        ForensicArtifact=reg_bam.BAM,
    )
    NETWORKINFO = Artifact(
        name="networkinfo",
        category=Categories.NETWORK_ACTIVITY_PHYSICAL_LOCATION.value,
        ForensicArtifact=reg_networkinfo.NetworkInfo,
    )
    SHELLBAGS = Artifact(
        name="shellbags",
        category=Categories.FILE_FOLDER_OPENING.value,
        ForensicArtifact=reg_shellbags.Shellbags,
    )
    REG_USB = Artifact(
        name="reg_usb",
        category=Categories.EXTERNAL_DEVICE_USB_USAGE.value,
        ForensicArtifact=reg_usb.USB,
    )
    AUTORUN = Artifact(
        name="autorun",
        category=Categories.SYSTEM_INFORMATION.value,
        ForensicArtifact=reg_autorun.AutoRun,
    )
    SYSTEMINFO = Artifact(
        name="systeminfo",
        category=Categories.SYSTEM_INFORMATION.value,
        ForensicArtifact=reg_systeminfo.SystemInfo,
    )
    # MRU = Artifact(name="mru", category=Categories.FILE_FOLDER_OPENING.value)
