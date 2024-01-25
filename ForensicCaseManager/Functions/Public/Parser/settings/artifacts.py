import yaml
import logging
from pathlib import Path
from enum import Enum
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

current_directory = Path(__file__).parent.absolute()
schemas = {
    "registry": current_directory / "schemas" / "registry.yaml",
    "windows": current_directory / "schemas" / "windows.yaml",
    "filesystem": current_directory / "schemas" / "filesystem.yaml",
    "apps": current_directory / "schemas" / "apps.yaml",
}


# Function to load schema data from multiple files
def load_schemas(schema_paths):
    schema_data = {}
    for name, path in schema_paths.items():
        with open(path, "r") as file:
            schema_data[name] = yaml.safe_load(file).get("Artifacts", {})
    return schema_data


schema_data = load_schemas(schemas)


class Artifacts(Enum):
    ## Applications
    CHROMIUM = "chromium"
    IEXPLORER = "iexplorer"

    ## Filesystem
    MFT = "mft"
    USNJRNL = "usnjrnl"

    ## Windows
    RECYCLEBIN = "recyclebin"
    PREFETCH = "prefetch"
    SRU_NETWORK = "sru_network"
    SRU_APPLICATION = "sru_application"
    FILEHISTORY = "filehistory"
    THUMBCACHE = "thumbcache"
    JUMPLIST = "jumplist"
    WINDOWSTIMELINE = "windowstimeline"
    EVENT_LOGON = "event_logon"
    EVENT_USB = "event_usb"
    EVENT_WLAN = "event_wlan"

    ## Registry
    AMCACHE = "amcache"
    USERACCOUNT = "useraccount"
    USERASSIST = "userassist"
    SHIMCACHE = "shimcache"
    BAM = "bam"
    NETWORKINFO = "networkinfo"
    SHELLBAGS = "shellbags"
    USB = "reg_usb"
    AUTORUN = "autorun"
    SYSTEMINFO = "systeminfo"
    MRU = "mru"


class Tables(Enum):
    ## Applications
    APP_CHROMIUM_HISTORY = "app_chromium_history"
    APP_CHROMIUM_DOWNLOADS = "app_chromium_downloads"
    APP_CHROMIUM_KEYWORDSEARCHTERMS = "app_chromium_keywordsearchterms"
    APP_CHROMIUM_AUTOFILL = "app_chromium_autofill"
    APP_CHROMIUM_LOGINDATA = "app_chromium_logindata"
    APP_CHROMIUM_BOOKMARKS = "app_chromium_bookmarks"
    APP_IEXPLORE_HISTORY = "app_iexplore_history"
    APP_IEXPLORE_DOWNLOADS = "app_iexplore_downloads"

    ## Filesystem
    FS_USNJRNL = "fs_usnjrnl"

    ## Windows
    WIN_RECYCLEBIN = "win_recyclebin"
    WIN_PREFETCH = "win_prefetch"
    WIN_SRU_NETWORK = "win_sru_network"
    WIN_SRU_APPLICATION = "win_sru_application"
    WIN_FILE_HISTORY = "win_file_history"
    WIN_THUMBCACHE = "win_thumbcache"
    WIN_JUMPLIST = "win_jumplist"
    WIN_WINDOWSTIMELINE = "win_windowstimeline"
    WIN_EVENT_LOGON = "win_event_logon"
    WIN_EVENT_USB = "win_event_usb"
    WIN_EVENT_WLAN = "win_event_wlan"

    ## Registry
    REG_AMCACHE_APPLICATION = "reg_amcache_application"
    REG_AMCACHE_APPLICATION_FILE = "reg_amcache_application_file"
    REG_AMCACHE_FILE = "reg_amcache_file"
    REG_AMCACHE_PROGRAMS = "reg_amcache_programs"
    REG_AMCACHE_BINARY = "reg_amcache_binary"
    REG_AMCACHE_CONTAINER = "reg_amcache_container"
    REG_AMCACHE_SHORTCUT = "reg_amcache_shortcut"
    REG_AUTORUN = "reg_autorun"
    REG_BAM = "reg_bam"
    REG_NETWORK_INTERFACE = "reg_network_interface"
    REG_NETWORK_HISTORY = "reg_network_history"
    REG_SHELLBAGS = "reg_shellbags"
    REG_SHIMCACHE = "reg_shimcache"
    REG_SYSTEMINFO = "reg_systeminfo"
    REG_USB = "reg_usb"
    REG_USERACCOUNT_SAM = "reg_useraccount_sam"
    REG_USERACCOUNT_PROFILELIST = "reg_useraccount_profilelist"
    REG_USERASSIST = "reg_userassist"


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
