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
    amcache,
    autorun,
    bam,
    networkinfo,
    shellbags,
    shimcache,
    systeminfo,
    useraccount,
    userassist,
    reg_usb,
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
        ForensicArtifact=sru.SruNetwork,
    )
    SRU_APPLICATION = Artifact(
        name="sru_application",
        category=Categories.APPLICATION_EXECUTION.value,
        ForensicArtifact=sru.SruApplication,
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
        name="logon_event",
        category=Categories.ACCOUNT_USAGE.value,
        ForensicArtifact=eventlog.LogonEvent,
    )
    EVENT_USB = Artifact(
        name="usb_event",
        category=Categories.EXTERNAL_DEVICE_USB_USAGE.value,
        ForensicArtifact=eventlog.UsbEvent,
    )
    EVENT_WLAN = Artifact(
        name="wlan_event",
        category=Categories.NETWORK_ACTIVITY_PHYSICAL_LOCATION.value,
        ForensicArtifact=eventlog.WlanEvent,
    )

    ## Registry
    AMCACHE = Artifact(
        name="amcache",
        category=Categories.APPLICATION_EXECUTION.value,
        ForensicArtifact=amcache.Amcache,
    )
    USERACCOUNT = Artifact(
        name="useraccount",
        category=Categories.ACCOUNT_USAGE.value,
        ForensicArtifact=useraccount.UserAccount,
    )
    USERASSIST = Artifact(
        name="userassist",
        category=Categories.APPLICATION_EXECUTION.value,
        ForensicArtifact=userassist.UserAssist,
    )
    SHIMCACHE = Artifact(
        name="shimcache",
        category=Categories.APPLICATION_EXECUTION.value,
        ForensicArtifact=shimcache.ShimCache,
    )
    BAM = Artifact(
        name="bam",
        category=Categories.APPLICATION_EXECUTION.value,
        ForensicArtifact=bam.BAM,
    )
    NETWORKINFO = Artifact(
        name="networkinfo",
        category=Categories.NETWORK_ACTIVITY_PHYSICAL_LOCATION.value,
        ForensicArtifact=networkinfo.NetworkInfo,
    )
    SHELLBAGS = Artifact(
        name="shellbags",
        category=Categories.FILE_FOLDER_OPENING.value,
        ForensicArtifact=shellbags.Shellbags,
    )
    REG_USB = Artifact(
        name="reg_usb",
        category=Categories.EXTERNAL_DEVICE_USB_USAGE.value,
        ForensicArtifact=reg_usb.USB,
    )
    AUTORUN = Artifact(
        name="autorun",
        category=Categories.SYSTEM_INFORMATION.value,
        ForensicArtifact=autorun.AutoRun,
    )
    SYSTEMINFO = Artifact(
        name="systeminfo",
        category=Categories.SYSTEM_INFORMATION.value,
        ForensicArtifact=systeminfo.SystemInfo,
    )
    # MRU = Artifact(name="mru", category=Categories.FILE_FOLDER_OPENING.value)
