from pathlib import Path

current_directory = Path(__file__).parent.absolute()


# Root Directory Name
ROOT_DIRECTORY_NAME = "_fcm"

# Database Name
DATABASE_NAME = "forensic_data.sqlite"

# Artifact Schema
ARTIFACT_SCHEMA_WINDOWS = current_directory / "schema" / "windows"
ARTIFACT_SCHEMA_BROWSER = current_directory / "schema" / "application" / "browsers"

# Categories
CAT_APPLICATION_EXECUTION = "APPLICATION_EXECUTION"
CAT_FILE_FOLDER_OPENING = "FILE_FOLDER_OPENING"
CAT_DELETED_ITEMS_FILE_EXISTENCE = "DELETED_ITEMS_FILE_EXISTENCE"
CAT_BROWSER_ACTIVITY = "BROWSER_ACTIVITY"
CAT_CLOUD_STORAGE = "CLOUD_STORAGE"
CAT_ACCOUNT_USAGE = "ACCOUNT_USAGE"
CAT_NETWORK_ACTIVITY_PHYSICAL_LOCATION = "NETWORK_ACTIVITY_PHYSICAL_LOCATION"
CAT_SYSTEM_INFORMATION = "SYSTEM_INFORMATION"
CAT_EXTERNAL_DEVICE_USB_USAGE = "EXTERNAL_DEVICE_USB_USAGE"

# Artifacts
ART_CHROME = "chrome"
ART_EDGE = "edge"
ART_IEXPLORER = "iexplorer"
ART_MFT = "mft"
ART_USNJRNL = "usnjrnl"
ART_RECYCLEBIN = "recyclebin"
ART_PREFETCH = "prefetch"
ART_SRU_NETWORK = "sru_network"
ART_SRU_APP = "sru_app"
ART_FILE_HISTORY = "file_history"
ART_THUMBCACHE = "thumbcache"
ART_JUMPLIST = "jumplist"
ART_WINDOWS_TIMELINE = "windows_timeline"
ART_LOGON_EVENT = "logon_event"
ART_USB_EVENT = "usb_event"
ART_WLAN = "wlan"
ART_AMCACHE = "amcache"
ART_USER_ACCOUNT = "user_account"
ART_USER_ASSIST = "user_assist"
ART_SHIMCACHE = "shimcache"
ART_BAM = "bam"
ART_NETWORK_INFO = "network_info"
ART_SHELLBAGS = "shellbags"
ART_USB_REGISTRY = "usb_registry"
ART_AUTORUN = "autorun"
ART_SYSTEM_INFO = "system_info"
ART_MRU = "mru"
