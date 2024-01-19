import logging
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from collections import namedtuple

from icecream import ic
from settings.config import *
from settings.artifacts import Artifact

ArtifactPath = namedtuple("ArtifactPath", ["directory", "entry"])

current_directory = Path(__file__).parent.absolute()

logger = logging.getLogger(__name__)

from dataclasses import dataclass, field
import yaml
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


# Function to load schema data from multiple files
def load_schemas(schema_paths):
    schema_data = {}
    for name, path in schema_paths.items():
        with open(path, "r") as file:
            schema_data[name] = yaml.safe_load(file).get("Artifacts", {})
    return schema_data


# Assuming current_directory is defined elsewhere
schemas = {
    "registry": current_directory / "schemas" / "registry.yaml",
    "windows": current_directory / "schemas" / "windows.yaml",
}

schema_data = load_schemas(schemas)


@dataclass
class ArtifactSchema:
    name: str
    category: str
    root: str = field(default_factory=str)
    owner: str = field(default_factory=str)
    entries: dict[str] = field(default_factory=dict)
    _schema: dict = field(init=False, default_factory=dict)

    def __post_init__(self):
        self._load_schema()

    def _load_schema(self):
        for schema_type, schema in schema_data.items():
            if self.name in schema:
                self._schema = schema[self.name]
                self.root = self._schema.get("root", self.root)
                self.owner = self._schema.get("owner", self.owner)
                self.entries = self._schema.get("entries", self.entries)
                return
        logger.error(f"ArtifactSchema not found for {self.name} in any schema type")


# Example usage
# artifact_schema = ArtifactSchema(name="some_artifact_name", category="some_category")


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
