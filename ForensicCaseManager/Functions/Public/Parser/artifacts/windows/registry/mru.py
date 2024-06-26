import json
import struct

from dissect.util.ts import wintimestamp

from dissect.target.exceptions import RegistryError
from dissect.target.plugins.os.windows.regf.shellbags import (
    FILE_ENTRY,
    parse_shell_item_list,
)

from dissect.target.plugins.os.windows.regf.mru import (
    RunMRURecord,
    RecentDocsRecord,
    OpenSaveMRURecord,
    LastVisitedMRURecord,
    ACMruRecord,
    MapNetworkDriveMRURecord,
    TerminalServerMRURecord,
    MSOfficeMRURecord,
)

from core.forensic_artifact import Source, ForensicArtifact


class MRU(ForensicArtifact):
    """Return MRU data stored at various registry keys.

    The Windows registry contains various keys about Most Recently Used (MRU) files.

    Sources:
        - https://winreg-kb.readthedocs.io/en/latest/sources/explorer-keys/Most-recently-used.html
    """

    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self):
        run = [
            json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
            for record in self.run()
        ]
        recentdocs = [
            json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
            for record in self.recentdocs()
        ]

        self.result = {
            "run": run,
            "recentdocs": recentdocs,
        }

    def run(self):
        """Return the RunMRU data.

        The ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU`` registry key contains information
        about the most recent commands that have been performed by the Run application

        Sources:
            - https://digitalf0rensics.wordpress.com/2014/01/17/windows-registry-and-forensics-part2/
        """
        KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"

        for key in self.src.source.registry.keys(KEY):
            yield from parse_mru_key(self.src.source, key, RunMRURecord)

    def recentdocs(self):
        """Return the RecentDocs data.

        The ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs`` registry key contains
        information about the last 10 documents that the currently logged on user accessed or executed via Windows
        Explorer.

        Sources:
            - https://digitalf0rensics.wordpress.com/2014/01/17/windows-registry-and-forensics-part2/
        """

        KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"

        for key in self.src.source.registry.keys(KEY):
            yield from parse_mru_ex_key(self.src.source, key, RecentDocsRecord)

    def opensave(self):
        """Return the OpenSaveMRU data.

        The ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU`` registry key
        contains information about the most recently opened or saved files.

        Sources:
            - https://digitalf0rensics.wordpress.com/2014/01/17/windows-registry-and-forensics-part2/
        """

        KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSaveMRU"

        for key in self.src.source.registry.keys(KEY):
            yield from parse_mru_key(self.src.source, key, OpenSaveMRURecord)

    def lastvisited(self):
        """Return the LastVisitedMRU data.

        The ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU`` registry key
        contains information about the executable used by an application to open the files that are documented at the
        OpenSaveMRU registry key. Also each value tracks the directory location for the last file that was accessed by
        that application.

        Sources:
            - https://digitalf0rensics.wordpress.com/2014/01/17/windows-registry-and-forensics-part2/
        """

        KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU"

        for key in self.src.source.registry.keys(KEY):
            user = self.src.source.registry.get_user(key)

            try:
                mrulist = key.value("MRUList").value
            except RegistryError:
                mrulist = None

            for value in key.values():
                if value.name == "MRUList":
                    continue

                entry_index = mrulist.index(value.name) if mrulist else None
                filename, path, _ = value.value.rsplit(b"\x00\x00")

                yield LastVisitedMRURecord(
                    regf_mtime=key.ts,
                    index=entry_index,
                    filename=filename.decode("utf-16-le"),
                    path=path.decode("utf-16-le"),
                    key=key.path,
                    _target=self.src.source,
                    _user=user,
                    _key=key,
                )

    def acmru(self):
        """Return the ACMru (Windows Search) data.

        The following keys are being searched:
          - ``HKCU\\Software\\Microsoft\\Search Assistant\\ACMru``:
            This registry key contains the most recent search history from Windows default search.
          - ``HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery``:
            This registry key contains the most recent search history from Windows Explorer. (Windows >=7)

        Sources:
            - https://digitalf0rensics.wordpress.com/2014/01/17/windows-registry-and-forensics-part2/

        Known categories:
            - 5001: Internet Search Assistant
            - 5603: Windows XP files and folder search
            - 5604: "Word or phrase in a file" dialog box
            - 5647: "For computers or people" selection in Search Results dialog box
        """

        KEY = "HKCU\\Software\\Microsoft\\Search Assistant\\ACMru"

        for key in self.src.source.registry.keys(KEY):
            user = self.src.source.registry.get_user(key)
            for subkey in key.subkeys():
                for value in subkey.values():
                    yield ACMruRecord(
                        regf_mtime=key.ts,
                        index=int(value.name),
                        category=subkey.name,
                        value=value.value,
                        key=key.path,
                        _target=self.src.source,
                        _user=user,
                        _key=subkey,
                    )

        KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery"

        for key in self.src.source.registry.keys(KEY):
            yield from parse_mru_ex_key(self.src.source, key, ACMruRecord)

    def networkdrive(self):
        """Return MRU of mapped network drives.

        The HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network Drive MRU registry key contains
        information about the most recently used mapped network drives.

        Sources:
            - https://winreg-kb.readthedocs.io/en/latest/sources/explorer-keys/Most-recently-used.html#keys-with-a-mrulist-value
        """  # noqa: E501

        KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Map Network Drive MRU"

        for key in self.src.source.registry.keys(KEY):
            yield from parse_mru_key(self.src.source, key, MapNetworkDriveMRURecord)

    def mstsc(self):
        """Return Terminal Server Client MRU data."""

        KEY = "HKCU\\Software\\Microsoft\\Terminal Server Client\\Default"

        for key in self.src.source.registry.keys(KEY):
            user = self.src.source.registry.get_user(key)

            for value in key.values():
                entry_index = int(value.name.split("MRU")[1])

                yield TerminalServerMRURecord(
                    regf_mtime=key.ts,
                    index=entry_index,
                    value=value.value,
                    key=key.path,
                    _target=self.src.source,
                    _user=user,
                    _key=key,
                )

    def msoffice(self):
        """Return MS Office MRU keys."""

        KEY = "HKCU\\Software\\Microsoft\\Office"
        SUBKEYS = [
            "Common",
            "Excel",
            "Groove",
            "OneNote",
            "Outlook",
            "PowerPoint",
            "Publisher",
            "Word",
        ]

        for key in self.src.source.registry.keys(KEY):
            for version_key in key.subkeys():
                if not version_key.name[0].isdigit():
                    continue

                for subkey in version_key.subkeys():
                    if subkey.name not in SUBKEYS:
                        continue

                    try:
                        yield from parse_office_mru(
                            self.src.source, subkey, MSOfficeMRURecord
                        )
                    except RegistryError:
                        pass


def parse_mru_key(target, key, record):
    user = target.registry.get_user(key)
    mrulist = key.value("MRUList").value

    for value in key.values():
        if value.name == "MRUList":
            continue

        entry_index = mrulist.index(value.name)
        entry_value = value.value

        yield record(
            regf_mtime=key.ts,
            index=entry_index,
            value=entry_value,
            key=key.path,
            _target=target,
            _user=user,
            _key=key,
        )

    for subkey in key.subkeys():
        yield from parse_mru_key(target, subkey, record)


def parse_mru_ex_key(target, key, record):
    user = target.registry.get_user(key)

    mrulist_ex = key.value("MRUListEx").value
    mrulist_ex = struct.unpack(f"<{len(mrulist_ex) // 4}I", mrulist_ex)

    for value in key.values():
        if value.name == "MRUListEx":
            continue

        entry_index = mrulist_ex.index(int(value.name))
        split_idx = value.value.index(b"\x00\x00")
        # Poor mans null terminated utf-16-le
        path, bag = value.value[: split_idx + 1], value.value[split_idx + 3 :]
        parsed_bag = list(parse_shell_item_list(bag))
        if len(parsed_bag) != 1 or not isinstance(parsed_bag, FILE_ENTRY):
            target.log.debug(
                "Unexpected shell bag entry in MRUListEx entry: %s:%s", key, value
            )

        yield record(
            regf_mtime=key.ts,
            index=entry_index,
            value=path.decode("utf-16-le"),
            key=key.path,
            _target=target,
            _user=user,
            _key=key,
        )


def parse_office_mru(target, key, record):
    try:
        yield from parse_office_mru_key(target, key.subkey("File MRU"), record)
    except RegistryError:
        pass

    try:
        yield from parse_office_mru_key(target, key.subkey("Place MRU"), record)
    except RegistryError:
        pass

    try:
        for subkey in key.subkey("User MRU").subkeys():
            yield from parse_office_mru(target, subkey, record)
    except RegistryError:
        pass


def parse_office_mru_key(target, key, record):
    user = target.registry.get_user(key)

    for value in key.values():
        if not value.name.startswith("Item"):
            continue

        entry_index = int(value.name.split(" ")[1])
        info_str, path = value.value.split("*", 1)

        info = {part[0]: int(part[1:], 16) for part in info_str.strip("[]").split("][")}

        yield record(
            ts=wintimestamp(info["T"]),
            regf_mtime=key.ts,
            index=entry_index,
            value=path,
            key=key.path,
            _target=target,
            _user=user,
            _key=key,
        )
