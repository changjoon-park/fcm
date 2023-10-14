from collections import namedtuple

ArtifactPath = namedtuple("ArtifactPath", ["directory", "entry"])

## BROWSER
ARTIFACT_DIRECTORY_CHROME = [
    "%USER%/AppData/Local/Google/Chrome/User Data/Default",
    "%USER%/AppData/Local/Google/Chrome/continuousUpdates/User Data/Default",
    "%USER%/Local Settings/Application Data/Google/Chrome/User Data/Default",
    "%USER%/AppData/local/Google/Chromium/User Data/Default",
    "%USER%/snap/chromium/common/chromium/Default",
]
ARTIFACT_DIRECTORY_EDGE = [
    "%USER%/AppData/Local/Microsoft/Edge/User Data/Default",
    "%USER%/Library/Application Support/Microsoft Edge/Default",
]
ARTIFACT_DIRECTORY_INTERNET_EXPLORER = [
    "%USER%/AppData/Local/Microsoft/Windows/WebCache",
]
ARTIFACT_DIRECTORY_FIREFOX = [
    "%USER%/AppData/Roaming/Mozilla/Firefox/Profiles",
    "%USER%/AppData/local/Mozilla/Firefox/Profiles",
]

## FILESYSTEM
ARTIFACT_DIRECTORY_MFT = [
    "%ROOT%",
]
ARTIFACT_DIRECTORY_USNJRNL = ["%ROOT%/$Extend"]

## REGISTRY
ARTIFACT_DIRECTORY_AMCACHE = ["%ROOT%/Windows/appcompat/Programs"]  # Amcache

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
REGISTRY_KEY_NETWORK_INFO = {
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
    "USB": ["HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB"],
    "USBSTOR": ["HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR"],
    "DeviceContainers": ["HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceContainers"],
    "HID": ["HKLM\\SYSTEM\\CurrentControlSet\\Enum\\HID"],
    "SCSI": ["HKLM\\SYSTEM\\CurrentControlSet\\Enum\\SCSI"],
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
REGISTRY_KEY_SYSTEM_INFO = {
    "ComputerName": [
        "HKLM\\SYSTEM\\ControlSet001\\Control\\ComputerName\\ComputerName"
    ],
    "CurrentVersion": ["HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"],
    "Environment": [
        "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment"
    ],
    "CodePage": ["HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage"],
    "FileSystem": ["HKLM\\SYSTEM\\ControlSet001\\Control\\FileSystem"],
    "Windows": ["HKLM\\SYSTEM\\ControlSet001\\Control\\Windows"],
}

## WINDOWS
ARTIFACT_DIRECTORY_RECYCLEBIN = [
    "%ROOT%/$recycle.bin",
]
ARTIFACT_DIRECTORY_PREFETCH = [
    "%ROOT%/windows/prefetch",
]
ARTIFACT_DIRECTORY_WINDOWS_TIMELINE = ["%USER%/AppData/Local/ConnectedDevicesPlatform"]
ARTIFACT_DIRECTORY_LNK = [
    "%USER%/Desktop",
    "%USER%/AppData/Roaming/Microsoft/Windows/Recent",
    "%USER%/AppData/Roaming/Microsoft/Office/Recent",
    "%ROOT%/ProgramData/Microsoft/Windows/Start Menu/Programs",
]
ARTIFACT_DIRECTORY_JUMPLIST = [
    "%USER%/AppData/Roaming/Microsoft/Windows/Recent/AutomaticDestinations",
    "%USER%/AppData/Roaming/Microsoft/Windows/Recent/CustomDestinations",
]
ARTIFACT_DIRECTORY_WINDOWS_TIMELINE = ["%USER%/AppData/Local/ConnectedDevicesPlatform"]
ARTIFACT_DIRECTORY_SRU = ["%ROOT%/Windows/System32/sru"]
ARTIFACT_DIRECTORY_THUMBCACHE = ["%USER%/AppData/Local/Microsoft/Windows/Explorer"]
ARTIFACT_DIRECTORY_FILEHISTORY = [
    "%USER%/AppData/Local/Microsoft/Edge/User Data/Default",
    "%USER%/Library/Application Support/Microsoft Edge/Default",
    "%USER%/AppData/Local/Microsoft/Windows/WebCache",
]
ARTIFACT_DIRECTORY_EVENTLOG = ["%ROOT%/Windows/System32/winevt/Logs"]


ARTIFACT_PATH = {
    "Chrome": ArtifactPath(
        directory=ARTIFACT_DIRECTORY_CHROME, entry=None
    ),  # ! Browser
    "Edge": ArtifactPath(directory=ARTIFACT_DIRECTORY_EDGE, entry=None),
    "iExplorer": ArtifactPath(
        directory=ARTIFACT_DIRECTORY_INTERNET_EXPLORER, entry="WebCacheV01.dat"
    ),
    # "MFT": ArtifactPath(directory=ARTIFACT_DIRECTORY_MFT, entry="$MFT"),  # ! FileSystem
    "UsnJrnl": ArtifactPath(directory=ARTIFACT_DIRECTORY_USNJRNL, entry="$J"),
    "RecycleBin": ArtifactPath(
        directory=ARTIFACT_DIRECTORY_RECYCLEBIN, entry="$I*"
    ),  # ! Windows
    "Prefetch": ArtifactPath(directory=ARTIFACT_DIRECTORY_PREFETCH, entry="*.pf"),
    "SRU(Network)": ArtifactPath(directory=ARTIFACT_DIRECTORY_SRU, entry="SRUDB.dat"),
    # "SRU(App)": ArtifactPath(directory=ARTIFACT_DIRECTORY_SRU, entry="SRUDB.dat"),
    "FileHistory": ArtifactPath(directory=ARTIFACT_DIRECTORY_FILEHISTORY, entry=None),
    # "ThumbCache": ArtifactPath(directory=ARTIFACT_DIRECTORY_THUMBCACHE, entry=None),
    # "Lnk": ArtifactPath(directory=ARTIFACT_DIRECTORY_LNK, entry="*.lnk"),
    "JumpList": ArtifactPath(
        directory=ARTIFACT_DIRECTORY_JUMPLIST, entry="*.automaticDestinations-ms"
    ),
    "WindowsTimeline": ArtifactPath(
        directory=ARTIFACT_DIRECTORY_WINDOWS_TIMELINE, entry="ActivitiesCache.db"
    ),
    "LogonEvent": ArtifactPath(
        directory=ARTIFACT_DIRECTORY_EVENTLOG, entry=None
    ),  # ! EventLog
    "USB(EventLog)": ArtifactPath(directory=ARTIFACT_DIRECTORY_EVENTLOG, entry=None),
    "WLAN": ArtifactPath(directory=ARTIFACT_DIRECTORY_EVENTLOG, entry=None),
    "Amcache": ArtifactPath(
        directory=ARTIFACT_DIRECTORY_AMCACHE, entry="Amcache.hve"
    ),  # ! Registry
    "UserAssist": ArtifactPath(directory=None, entry=REGISTRY_KEY_USERASSIST),
    "ShimCache": ArtifactPath(directory=None, entry=REGISTRY_KEY_SHIMCACHE),
    "BAM": ArtifactPath(directory=None, entry=REGISTRY_KEY_BAM),
    "UserAccount": ArtifactPath(directory=None, entry=REGISTRY_KEY_USER_ACCOUNT),
    "NetworkInfo": ArtifactPath(directory=None, entry=REGISTRY_KEY_NETWORK_INFO),
    "ShellBags": ArtifactPath(directory=None, entry=REGISTRY_KEY_SHELLBAGS),
    "USB(Registry)": ArtifactPath(directory=None, entry=REGISTRY_KEY_USB),
    "AutoRun": ArtifactPath(directory=None, entry=REGISTRY_KEY_AUTORUN),
    "SystemInfo": ArtifactPath(directory=None, entry=REGISTRY_KEY_SYSTEM_INFO),
}
