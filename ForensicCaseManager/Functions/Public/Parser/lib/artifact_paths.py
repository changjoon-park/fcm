import yaml
from pathlib import Path
from collections import namedtuple

from settings import *

current_directory = Path(__file__).parent.absolute()

# schema file path
schema_registry = current_directory / "schemas" / "path_registry.yaml"

ArtifactPath = namedtuple("ArtifactPath", ["directory", "entry"])

with open(schema_registry, "r") as file:
    registry_path = yaml.safe_load(file).get("registry_path")

## BROWSER
ARTIFACT_DIRECTORY_CHROME = [
    {
        "owner": ARTIFACT_OWNER_USER,
        "paths": [
            "AppData/Local/Google/Chrome/User Data/Default",
            "AppData/Local/Google/Chrome/continuousUpdates/User Data/Default",
            "Local Settings/Application Data/Google/Chrome/User Data/Default",
            "AppData/local/Google/Chromium/User Data/Default",
            "snap/chromium/common/chromium/Default",
        ],
    }
]
ARTIFACT_DIRECTORY_EDGE = [
    {
        "owner": ARTIFACT_OWNER_USER,
        "paths": [
            "AppData/Local/Microsoft/Edge/User Data/Default",
            "Library/Application Support/Microsoft Edge/Default",
        ],
    }
]
ARTIFACT_DIRECTORY_INTERNET_EXPLORER = [
    {
        "owner": ARTIFACT_OWNER_USER,
        "paths": [
            "AppData/Local/Microsoft/Windows/WebCache",
        ],
    }
]
ARTIFACT_DIRECTORY_FIREFOX = [
    {
        "owner": ARTIFACT_OWNER_USER,
        "paths": [
            "AppData/Roaming/Mozilla/Firefox/Profiles",
            "AppData/local/Mozilla/Firefox/Profiles",
        ],
    }
]

## FILESYSTEM
ARTIFACT_DIRECTORY_MFT = [
    {
        "owner": ARTIFACT_OWNER_SYSTEM,
        "paths": [
            "/",
        ],
    }
]
ARTIFACT_DIRECTORY_USNJRNL = [
    {
        "owner": ARTIFACT_OWNER_SYSTEM,
        "paths": [
            "$Extend",
        ],
    },
]

## REGISTRY
ARTIFACT_DIRECTORY_AMCACHE = [
    {
        "owner": ARTIFACT_OWNER_SYSTEM,
        "paths": [
            "Windows/appcompat/Programs",
        ],
    }
]  # Amcache
REGISTRY_KEY_USER_ACCOUNT = {
    "Users": ["HKEY_LOCAL_MACHINE\\SAM\\SAM\\Domains\\Account\\Users"],
    "ProfileList": [
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"
    ],
}
REGISTRY_KEY_BAM = [
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\dam\\UserSettings",
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
    "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings",
]
REGISTRY_KEY_SHELLBAGS = [
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Shell",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\ShellNoRoam",
    "HKEY_CURRENT_USER\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell",
    "HKEY_CURRENT_USER\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\ShellNoRoam",
    "HKEY_CURRENT_USER\\Software\\Classes\\Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\Shell",
    "HKEY_CURRENT_USER\\Software\\Classes\\Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\ShellNoRoam",
    "HKEY_CURRENT_USER\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
]
REGISTRY_KEY_SHIMCACHE = [
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache",
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatibility",
]
REGISTRY_KEY_USERASSIST = [
    "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
]
REGISTRY_KEY_NETWORKINFO = {
    "Signatures": [
        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Signatures"
    ],
    "Profiles": [
        "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Profiles"
    ],
    "Interfaces": [
        "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces"
    ],
}
REGISTRY_KEY_USB = {
    "USB": [
        "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB",
    ],
    "USBSTOR": [
        "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR",
    ],
    "DeviceContainers": [
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceContainers",
    ],
    "HID": [
        "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\HID",
    ],
    "SCSI": [
        "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\SCSI",
    ],
}
REGISTRY_KEY_AUTORUN = [
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Setup",
    "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceE",
    "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Setup",
    "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
    "HKEY_LOCAL_MACHINE\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Setup",
    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
    "HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
    "HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\Setup",
    "HKEY_CURRENT_USER\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
]
REGISTRY_KEY_SYSTEMINFO = {
    "ComputerName": [
        "HKLM\\SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName"
    ],
    "CurrentVersion": [
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
    ],
    "Environment": [
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
    ],
    "CodePage": [
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage",
    ],
    "FileSystem": [
        "HKLM\\SYSTEM\\ControlSet001\\Control\\FileSystem",
    ],
    "Windows": [
        "HKLM\\SYSTEM\\ControlSet001\\Control\\Windows",
    ],
}

## WINDOWS
ARTIFACT_DIRECTORY_RECYCLEBIN = [
    {
        "owner": ARTIFACT_OWNER_SYSTEM,
        "paths": [
            "$recycle.bin",
        ],
    }
]
ARTIFACT_DIRECTORY_PREFETCH = [
    {
        "owner": ARTIFACT_OWNER_SYSTEM,
        "paths": [
            "windows/prefetch",
        ],
    },
]
ARTIFACT_DIRECTORY_WINDOWS_TIMELINE = [
    {
        "owner": ARTIFACT_OWNER_USER,
        "paths": [
            "AppData/Local/ConnectedDevicesPlatform",
        ],
    }
]
ARTIFACT_DIRECTORY_LNK = [
    {
        "owner": ARTIFACT_OWNER_SYSTEM,
        "paths": [
            "ProgramData/Microsoft/Windows/Start Menu/Programs",
        ],
    },
    {
        "owner": ARTIFACT_OWNER_USER,
        "paths": [
            "Desktop",
            "AppData/Roaming/Microsoft/Windows/Recent",
            "AppData/Roaming/Microsoft/Office/Recent",
        ],
    },
]
ARTIFACT_DIRECTORY_JUMPLIST = [
    {
        "owner": ARTIFACT_OWNER_USER,
        "paths": [
            "AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations",
            "AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations",
        ],
    }
]
ARTIFACT_DIRECTORY_SRU = [
    {
        "owner": ARTIFACT_OWNER_SYSTEM,
        "paths": [
            "Windows/System32/sru",
        ],
    }
]
ARTIFACT_DIRECTORY_THUMBCACHE = [
    {
        "owner": ARTIFACT_OWNER_USER,
        "paths": [
            "AppData/Local/Microsoft/Windows/Explorer",
        ],
    }
]
ARTIFACT_DIRECTORY_FILEHISTORY = [
    {
        "owner": ARTIFACT_OWNER_USER,
        "paths": [
            "AppData/Local/Microsoft/Edge/User Data/Default",
            "Library/Application Support/Microsoft Edge/Default",
            "AppData/Local/Microsoft/Windows/WebCache",
        ],
    }
]
ARTIFACT_DIRECTORY_EVENTLOG = [
    {
        "owner": ARTIFACT_OWNER_SYSTEM,
        "paths": [
            "Windows/System32/winevt/Logs",
        ],
    }
]


ARTIFACT_PATH = {
    ART_CHROME: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_CHROME, entry=None
    ),  # ! Browser
    ART_EDGE: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_EDGE,
        entry=None,
    ),
    ART_IEXPLORER: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_INTERNET_EXPLORER, entry="WebCacheV01.dat"
    ),
    # "MFT": ArtifactPath(directory=ARTIFACT_DIRECTORY_MFT, entry="$MFT"),  # ! FileSystem
    ART_USNJRNL: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_USNJRNL,
        entry="$J",
    ),
    ART_RECYCLEBIN: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_RECYCLEBIN, entry="$I*"
    ),  # ! Windows
    ART_PREFETCH: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_PREFETCH,
        entry="*.pf",
    ),
    ART_SRU_NETWORK: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_SRU,
        entry="SRUDB.dat",
    ),
    ART_SRU_APPLICATION: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_SRU, entry="SRUDB.dat"
    ),
    ART_FILE_HISTORY: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_FILEHISTORY, entry=None
    ),
    ART_THUMBCACHE: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_THUMBCACHE,
        entry="*.db",
    ),
    # "Lnk": ArtifactPath(directory=ARTIFACT_DIRECTORY_LNK, entry="*.lnk"),
    ART_JUMPLIST: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_JUMPLIST, entry="*.automaticDestinations-ms"
    ),
    ART_WINDOWS_TIMELINE: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_WINDOWS_TIMELINE, entry="ActivitiesCache.db"
    ),
    ART_EVENT_LOGON: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_EVENTLOG, entry=None
    ),  # ! EventLog
    ART_EVENT_USB: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_EVENTLOG,
        entry=None,
    ),
    ART_EVENT_WLAN: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_EVENTLOG,
        entry=None,
    ),
    ART_REGISTRY_AMCACHE: ArtifactPath(
        directory=ARTIFACT_DIRECTORY_AMCACHE, entry="Amcache.hve"
    ),  # ! Registry
    ART_REGISTRY_USERASSIST: ArtifactPath(
        directory="registry",
        entry=REGISTRY_KEY_USERASSIST,
    ),
    ART_REGISTRY_SHIMCACHE: ArtifactPath(
        directory="registry",
        entry=REGISTRY_KEY_SHIMCACHE,
    ),
    ART_REGISTRY_BAM: ArtifactPath(
        directory="registry",
        entry=REGISTRY_KEY_BAM,
    ),
    ART_REGISTRY_USERACCOUNT: ArtifactPath(
        directory="registry",
        entry=REGISTRY_KEY_USER_ACCOUNT,
    ),
    ART_REGISTRY_NETWORKINFO: ArtifactPath(
        directory="registry",
        entry=REGISTRY_KEY_NETWORKINFO,
    ),
    ART_REGISTRY_SHELLBAGS: ArtifactPath(
        directory="registry",
        entry=REGISTRY_KEY_SHELLBAGS,
    ),
    ART_REGISTRY_USB: ArtifactPath(
        directory="registry",
        entry=registry_path.get("usb"),
    ),
    ART_REGISTRY_AUTORUN: ArtifactPath(
        directory="registry",
        entry=REGISTRY_KEY_AUTORUN,
    ),
    ART_REGISTRY_SYSTEMINFO: ArtifactPath(
        directory="registry",
        entry=REGISTRY_KEY_SYSTEMINFO,
    ),
}
