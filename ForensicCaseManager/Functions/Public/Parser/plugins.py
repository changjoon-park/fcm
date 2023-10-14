from collections import namedtuple

from artifacts.filesystem.mft import Mft
from artifacts.filesystem.usnjrnl import UsnJrnl

from artifacts.windows.recyclebin import RecycleBin
from artifacts.windows.prefetch import Prefetch
from artifacts.windows.jumplist import JumpList
from artifacts.windows.thumbcache import Thumbcache
from artifacts.windows.sru import SRU
from artifacts.windows.windows_timeline import WindowsTimeline
from artifacts.windows.filehistory import FileHistory
from artifacts.windows.eventlog import ForensicEvent

from artifacts.windows.registry.amcache import Amcache
from artifacts.windows.registry.user_account import UserAccount
from artifacts.windows.registry.userassist import UserAssist
from artifacts.windows.registry.shimcache import ShimCache
from artifacts.windows.registry.bam import BAM
from artifacts.windows.registry.network_info import NetworkInfo
from artifacts.windows.registry.shellbags import ShellBags
from artifacts.windows.registry.usb import USB
from artifacts.windows.registry.autorun import AutoRun
from artifacts.windows.registry.system_info import SystemInfo
from artifacts.windows.registry.mru import MRU

from artifacts.application.browsers.chrome import Chrome
from artifacts.application.browsers.edge import Edge
from artifacts.application.browsers.iexplore import InternetExplorer


Plugin = namedtuple("Plugin", ["artifact", "category"])

CATEGORY_APPLICATION_EXECUTION = "Application Execution"
CATEGORY_FILE_FOLDER_OPENING = "File and Folder Opening"
CATEGORY_DELETED_ITEMS_FILE_EXISTENCE = "Deleted Items and File Existence"
CATEGORY_BROWSER_ACTIVITY = "Browser Activity"
CATEGORY_CLOUD_STORAGE = "Cloud Storage"
CATEGORY_ACCOUNT_USAGE = "Account Usage"
CATEGORY_NETWORK_ACTIVITY_PHYSICAL_LOCATION = "Network Activity"
CATEGORY_SYSTEM_INFORMATION = "System Information"
CATEGORY_EXTERNAL_DEVICE_USB_USAGE = "External Device And USB Usage"

PLUGINS = {
    "Chrome": Plugin(artifact=Chrome, category=CATEGORY_BROWSER_ACTIVITY),  # ! Browser
    "Edge": Plugin(artifact=Edge, category=CATEGORY_BROWSER_ACTIVITY),
    "iExplorer": Plugin(artifact=InternetExplorer, category=CATEGORY_BROWSER_ACTIVITY),
    # "MFT": Plugin(artifact=mft.MFT, category="todo"),  # FileSystem
    # "UsnJrnl": Plugin(artifact=UsnJrnl, category=CATEGORY_DELETED_ITEMS_FILE_EXISTENCE),
    "RecycleBin": Plugin(artifact=RecycleBin, category=CATEGORY_DELETED_ITEMS_FILE_EXISTENCE),  # ! Windows
    "Prefetch": Plugin(artifact=Prefetch, category=CATEGORY_APPLICATION_EXECUTION),
    "FileHistory": Plugin(artifact=FileHistory, category=CATEGORY_FILE_FOLDER_OPENING),
    # "SRU(Network)": Plugin(artifact=SRU, category=CATEGORY_NETWORK_ACTIVITY_PHYSICAL_LOCATION),
    # "SRU(App)": Plugin(artifact=SRU, category=CATEGORY_APPLICATION_EXECUTION),
    # "Lnk": Plugin(artifact=LinkFile, category=CATEGORY_FILE_FOLDER_OPENING),
    "JumpList": Plugin(artifact=JumpList, category=CATEGORY_FILE_FOLDER_OPENING),
    # "WindowsTimeline": Plugin(artifact=WindowsTimeline, category=CATEGORY_APPLICATION_EXECUTION),
    "LogonEvent": Plugin(artifact=ForensicEvent, category=CATEGORY_ACCOUNT_USAGE),  # ! EventLog
    "USB(EventLog)": Plugin(artifact=ForensicEvent, category=CATEGORY_EXTERNAL_DEVICE_USB_USAGE),
    "WLAN": Plugin(artifact=ForensicEvent, category=CATEGORY_NETWORK_ACTIVITY_PHYSICAL_LOCATION),
    "Amcache": Plugin(artifact=Amcache, category=CATEGORY_APPLICATION_EXECUTION),  # ! Registry
    "UserAccount": Plugin(artifact=UserAccount, category=CATEGORY_ACCOUNT_USAGE),
    "UserAssist": Plugin(artifact=UserAssist, category=CATEGORY_APPLICATION_EXECUTION),
    "ShimCache": Plugin(artifact=ShimCache, category=CATEGORY_APPLICATION_EXECUTION),
    "BAM": Plugin(artifact=BAM, category=CATEGORY_APPLICATION_EXECUTION),
    "NetworkInfo": Plugin(artifact=NetworkInfo, category=CATEGORY_NETWORK_ACTIVITY_PHYSICAL_LOCATION),
    "ShellBags": Plugin(artifact=ShellBags, category=CATEGORY_FILE_FOLDER_OPENING),
    "USB(Registry)": Plugin(artifact=USB, category=CATEGORY_EXTERNAL_DEVICE_USB_USAGE),
    "AutoRun": Plugin(artifact=AutoRun, category=CATEGORY_SYSTEM_INFORMATION),
    "SystemInfo": Plugin(artifact=SystemInfo, category=CATEGORY_SYSTEM_INFORMATION),
    # "MRU": Plugin(artifact=MRU, category=CATEGORY_FILE_FOLDER_OPENING),
}