from enum import Enum


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
    WIN_FILEHISTORY = "win_filehistory"
    WIN_THUMBCACHE = "win_thumbcache"
    WIN_JUMPLIST = "win_jumplist"
    WIN_WINDOWSTIMELINE = "win_windowstimeline"

    ## EventLog
    EVENT_LOGON = "event_logon"
    EVENT_USB = "event_usb"
    EVENT_WLAN = "event_wlan"

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
