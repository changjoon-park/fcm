import json
from datetime import datetime

from flow.record.fieldtypes import uri

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.helpers import regutil

from forensic_artifact import Source, ForensicArtifact
from settings import (
    RSLT_REGISTRY_AMCACHE_APPLICATIONS,
    RSLT_REGISTRY_AMCACHE_APPLICATION_FILES,
)

AMCACHE_FILE_KEYS = {
    "0": "product_name",
    "1": "company_name",
    "2": "file_version_number",
    "3": "language_code",
    "4": "switch_back_context",
    "5": "file_version_string",
    "6": "file_size",
    "7": "pe_size_of_image",
    "8": "pe_header_hash",
    "9": "pe_header_checksum",
    "c": "file_description",
    "f": "link_timestamp",
    "11": "last_modified_timestamp",
    "12": "created_timestamp",
    "15": "full_path",
    "17": "last_modified_store_timestamp",
    "100": "program_id",
    "101": "sha1",
}

AMCACHE_PROGRAM_KEYS = {
    "a": "InstallDate",
    "0": "Name",
    "1": "Version",
    "2": "Publisher",
    "3": "LanguageCode",
    "6": "EntryType",
    "7": "UninstallKey",
    "d": "FilePaths",
    "f": "ProductCode",
    "10": "PackageCode",
    "11": "MisPackageCode",
    "12": "MisPackageCode2",
    "Files": "Files",
}

ShortcutAppcompatRecord = TargetRecordDescriptor(
    "windows/appcompat/ApplicationShortcut",
    [
        ("datetime", "mtime_regf"),
        ("uri", "path"),
    ],
)

FileAppcompatRecord = TargetRecordDescriptor(
    "windows/appcompat/file",
    [
        ("datetime", "last_modified_timestamp"),
        ("datetime", "last_modified_store_timestamp"),
        ("datetime", "link_timestamp"),
        ("datetime", "created_timestamp"),
        ("datetime", "mtime_regf"),
        ("varint", "reference"),
        ("uri", "path"),
        ("string", "language_code"),
        ("digest", "digests"),
        ("string", "program_id"),
        ("string", "pe_header_checksum"),
        ("string", "pe_size_of_image"),
        ("wstring", "product_name"),
        ("wstring", "company_name"),
        ("filesize", "file_size"),
    ],
)

ProgramsAppcompatRecord = TargetRecordDescriptor(
    "windows/appcompat/programs",
    [
        ("datetime", "install_date"),
        ("datetime", "mtime_regf"),
        ("wstring", "name"),
        ("string", "version"),
        ("wstring", "publisher"),
        ("string", "language_code"),
        ("string", "entry_type"),
        ("string", "uninstall_key"),
        ("uri", "path"),
        ("string", "product_code"),
        ("string", "package_code"),
        ("string", "msi_package_code"),
        ("string", "msi_package_code2"),
    ],
)

ApplicationAppcompatRecord = TargetRecordDescriptor(
    "windows/appcompat/InventoryApplication",
    [
        ("datetime", "install_date"),
        ("string", "name"),
        ("string", "type"),
        ("string", "publisher"),
        ("string", "uninstall_string"),
        ("uri", "root_dir_path"),
        ("string", "program_id"),
        ("string", "program_instance_id"),
        ("string", "msi_package_code"),
        ("string", "msi_product_code"),
        ("datetime", "mtime_regf"),
        ("datetime", "install_date_arp_last_modified"),
        ("datetime[]", "install_date_from_link_file"),
        ("string", "os_version_at_install_time"),
        ("string", "language_code"),
        ("string", "package_full_name"),
        ("string", "manifest_path"),
        ("string", "registry_key_path"),
        ("string", "source"),
    ],
)


ApplicationFileAppcompatRecord = TargetRecordDescriptor(
    "windows/appcompat/InventoryApplicationFile",
    [
        ("datetime", "mtime_regf"),
        ("wstring", "name"),
        ("filesize", "size"),
        ("wstring", "publisher"),
        ("wstring", "product_name"),
        ("string", "bin_file_version"),
        ("string", "product_version"),
        ("string", "bin_product_version"),
        ("string", "version"),
        ("string", "program_id"),
        ("uri", "path"),
        ("string", "hash_path"),
        ("datetime", "link_date"),
        ("digest", "digests"),
        ("string", "language"),
        ("varint", "is_pefile"),
        ("varint", "is_oscomponent"),
    ],
)

BinaryAppcompatRecord = TargetRecordDescriptor(
    "windows/appcompat/InventoryDriverBinary",
    [
        ("datetime", "mtime_regf"),
        ("uri", "driver_name"),
        ("uri", "inf"),
        ("string", "driver_version"),
        ("wstring", "product"),
        ("string", "product_version"),
        ("string", "wdf_version"),
        ("wstring", "driver_company"),
        ("string", "driver_package_strong_name"),
        ("string", "service"),
        ("string", "driver_signed"),
        ("varint", "driver_is_kernel_mode"),
        ("datetime", "last_write_time"),
        ("datetime", "driver_timestamp"),
        ("filesize", "image_size"),
    ],
)


ContainerAppcompatRecord = TargetRecordDescriptor(
    "windows/appcompat/DeviceContainer",
    [
        ("datetime", "mtime_regf"),
        ("string", "categories"),
        ("string", "discovery_method"),
        ("string", "friendly_name"),
        ("string", "icon"),
        ("varint", "is_active"),
        ("varint", "is_connected"),
        ("varint", "is_machine_container"),
        ("varint", "is_networked"),
        ("varint", "is_paired"),
        ("string", "manufacturer"),
        ("string", "model_id"),
        ("string", "model_name"),
        ("string", "model_number"),
        ("string", "primary_category"),
        ("string", "state"),
    ],
)


class AmcachePluginOldMixin:
    def _replace_indices_with_fields(self, mapping, record):
        record_data = {v.name: v.value for v in record.values()}
        result = {}
        for key in record_data:
            field = mapping[key] if key in mapping else key
            result[field] = record_data[key]
        return result

    def parse_file(self):
        key = "Root\\File"

        for entry in self.read_key_subkeys(key):
            for subkey in entry.subkeys():
                subkey_data = self._replace_indices_with_fields(
                    AMCACHE_FILE_KEYS, subkey
                )

                yield FileAppcompatRecord(
                    last_modified_store_timestamp=self.ts.wintimestamp(
                        subkey_data.get("last_modified_store_timestamp")
                    ),
                    last_modified_timestamp=self.ts.wintimestamp(
                        subkey_data.get("last_modified_timestamp")
                    ),
                    link_timestamp=subkey_data.get("link_timestamp"),
                    created_timestamp=self.ts.wintimestamp(
                        subkey_data.get("created_timestamp")
                    ),
                    mtime_regf=subkey.timestamp,
                    reference=int(subkey.name, 16),
                    path=uri.from_windows(subkey_data["full_path"])
                    if subkey_data.get("full_path")
                    else None,
                    language_code=subkey_data.get("language_code"),
                    digests=[
                        None,
                        subkey_data["sha1"][-40:] if subkey_data.get("sha1") else None,
                        None,
                    ],
                    program_id=subkey_data.get("program_id"),
                    pe_header_checksum=subkey_data.get("pe_header_checksum"),
                    pe_size_of_image=subkey_data.get("pe_size_of_image"),
                    product_name=subkey_data.get("product_name"),
                    company_name=subkey_data.get("company_name"),
                    file_size=subkey_data.get("file_size"),
                    _target=self.target,
                )

    def parse_programs(self):
        key = "Root\\Programs"

        for entry in self.read_key_subkeys(key):
            entry_data = self._replace_indices_with_fields(AMCACHE_PROGRAM_KEYS, entry)

            yield ProgramsAppcompatRecord(
                mtime_regf=entry.timestamp,
                install_date=self.ts.wintimestamp(entry_data.get("InstallDate")),
                name=entry_data.get("Name"),
                version=entry_data.get("Version"),
                publisher=entry_data.get("Publisher"),
                language_code=entry_data.get("LanguageCode"),
                entry_type=entry_data.get("EntryType"),
                uninstall_key=entry_data.get("UninstallKey"),
                product_code=entry_data.get("ProductCode"),
                package_code=entry_data.get("PackageCode"),
                msi_package_code=entry_data.get("MsiPackageCode"),
                msi_package_code2=entry_data.get("MsiPackageCode2"),
                _target=self.target,
            )

            if "FilePaths" in entry_data:
                for file_path_entry in entry_data["FilePaths"]:
                    yield ProgramsAppcompatRecord(
                        mtime_regf=entry.timestamp,
                        install_date=self.ts.wintimestamp(
                            entry_data.get("InstallDate")
                        ),
                        name=entry_data.get("Name"),
                        version=entry_data.get("Version"),
                        publisher=entry_data.get("Publisher"),
                        language_code=entry_data.get("LanguageCode"),
                        entry_type=entry_data.get("EntryType"),
                        uninstall_key=entry_data.get("UninstallKey"),
                        path=uri.from_windows(file_path_entry),
                        product_code=entry_data.get("ProductCode"),
                        package_code=entry_data.get("PackageCode"),
                        msi_package_code=entry_data.get("MsiPackageCode"),
                        msi_package_code2=entry_data.get("MsiPackageCode2"),
                        _target=self.target,
                    )

            if "Files" in entry_data:
                for file_entry in entry_data["Files"]:
                    yield ProgramsAppcompatRecord(
                        mtime_regf=entry.timestamp,
                        install_date=self.ts.wintimestamp(
                            entry_data.get("InstallDate")
                        ),
                        name=entry_data.get("Name"),
                        version=entry_data.get("Version"),
                        publisher=entry_data.get("Publisher"),
                        language_code=entry_data.get("LanguageCode"),
                        entry_type=entry_data.get("EntryType"),
                        uninstall_key=entry_data.get("UninstallKey"),
                        path=uri.from_windows(file_entry),
                        product_code=entry_data.get("ProductCode"),
                        package_code=entry_data.get("PackageCode"),
                        msi_package_code=entry_data.get("MsiPackageCode"),
                        msi_package_code2=entry_data.get("MsiPackageCode2"),
                        _target=self.target,
                    )

    def programs(self):
        """Return Programs records from Amcache hive."""
        if self.amcache:
            yield from self.parse_programs()

    def files(self):
        """Return File records from Amcache hive."""
        if self.amcache:
            yield from self.parse_file()


class Amcache(AmcachePluginOldMixin, ForensicArtifact):
    """Appcompat plugin for amcache.hve.

    Supported registry keys:

        for old version of Amcache:
        * File
        * Programs

        for new version of Amcache:
        • InventoryDriverBinary
        • InventoryDeviceContainer
        • InventoryApplication
        • InventoryApplicationFile
        * InventoryApplicationShortcut

    Resources:
        https://binaryforay.blogspot.com/2015/04/appcompatcache-changes-in-windows-10.html
        https://www.ssi.gouv.fr/uploads/2019/01/anssi-coriin_2019-analysis_amcache.pdf

    """

    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    @property
    def amcache(self):
        amcache = regutil.HiveCollection()
        for path in self.iter_entry():
            amcache.add(regutil.RegfHive(path))
        return amcache

    def read_key_subkeys(self, key):
        try:
            for entry in self.amcache.key(key).subkeys():
                yield entry
        # except RegistryKeyNotFoundError:
        #     raise 'Could not find registry key "{key}"'
        except:
            pass

    def parse(self, descending: bool = False):
        # files = [
        #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
        #     for record in self.files()
        # ]
        # programs = [
        #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
        #     for record in self.programs()
        # ]

        applications = sorted(
            [
                self.validate_record(index=index, record=record)
                for index, record in enumerate(self.applications())
            ],
            key=lambda record: record["install_date"],
            reverse=descending,
        )

        # TODO: bug fix on timestamp
        # application_files = sorted(
        #     [
        #         self.validate_record(index=index, record=record)
        #         for index, record in enumerate(self.application_files())
        #     ],
        #     key=lambda record: record["mtime_regf"],
        #     reverse=descending,
        # )

        application_files = [
            self.validate_record(index=index, record=record)
            for index, record in enumerate(self.application_files())
        ]

        # sorted_applications = sorted(
        #     [record._packdict() for record in self.applications()],
        #     key=lambda x: x["install_date"], reverse=descending
        # )
        # applications = [
        #     json.dumps(entry, indent=2, default=str, ensure_ascii=False)
        #     for entry in sorted_applications
        # ]

        # sorted_application_files = sorted(
        #     [record._packdict() for record in self.application_files()],
        #     key=lambda x: x["link_date"], reverse=descending
        # )
        # application_files = [
        #     json.dumps(entry, indent=2, default=str, ensure_ascii=False)
        #     for entry in sorted_application_files
        # ]
        # drivers = [
        #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
        #     for record in self.drivers()
        # ]
        # shortcuts = [
        #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
        #     for record in self.shortcuts()
        # ]
        # device_containers = [
        #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
        #     for record in self.device_containers()
        # ]

        self.result = {
            # "files": files,
            # "programs": programs,
            RSLT_REGISTRY_AMCACHE_APPLICATIONS: applications,
            RSLT_REGISTRY_AMCACHE_APPLICATION_FILES: application_files,
            # "drivers": drivers,
            # "shortcuts": shortcuts,
            # "device_containers": device_containers,
        }

    def parse_inventory_application(self):
        """Parse Root\\InventoryApplication registry key subkeys.

        Amcache is a registry hive that stores information about executed programs. The InventoryApplication key holds
        all application objects that are in cache.

        Sources:
            - https://docs.microsoft.com/en-us/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1803
            - https://docs.microsoft.com/en-us/windows/privacy/required-windows-diagnostic-data-events-and-fields-2004#microsoftwindowsinventorycoreinventoryapplicationadd
            - https://www.andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/

        """  # noqa

        key = "Root\\InventoryApplication"

        for entry in self.read_key_subkeys(key):
            entry_data = {v.name: v.value for v in entry.values()}

            # Example:
            # {
            #      "BundleManifestPath": "",
            #      "HiddenArp": 0,
            #      "InboxModernApp": 0,
            #      "InstallDate": "07/21/2021 10:50:31",
            #      "Language": 65535,
            #      "ManifestPath": "",
            #      "MsiPackageCode": "",
            #      "MsiProductCode": "",
            #      "Name": "Shadow Tactics: Blades of the Shogun Demo",
            #      "OSVersionAtInstallTime": "10.0.0.19043",
            #      "PackageFullName": "",
            #      "ProgramId": "000002f1bc1777c6cb2bc117ab9cbd6d92780000ffff",
            #      "ProgramInstanceId": "0000a90d11947726f9702ca9ca3c76dc7631e35e861f",
            #      "Publisher": "Mimimi Games",
            #      "RegistryKeyPath":
            #           "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Steam App 547490",
            #      "RootDirPath":
            #           "C:\\Program Files (x86)\\Steam\\steamapps\\common\\Shadow Tactics Blades of the Shogun Demo",
            #      "SentDetailedInv": 0,
            #      "Source": "Steam",
            #      "StoreAppType": "",
            #      "Type": "Application",
            #      "UninstallString": "\"C:\\Program Files (x86)\\Steam\\steam.exe\" steam://uninstall/547490",
            #      "Version": ""
            # }

            install_date = parse_win_datetime(entry_data.get("InstallDate"))
            if install_date:
                install_date = self.ts.to_localtime(install_date)
            else:
                install_date = self.ts.base_datetime_windows

            install_date_arp_last_modified = (
                entry_data["InstallDateArpLastModified"][0]
                if entry_data.get("InstallDateArpLastModified")
                else None
            )

            yield {
                "install_date": install_date,
                "name": entry_data.get("Name"),
                "type": entry_data.get("Type"),
                "publisher": entry_data.get("Publisher"),
                "uninstall_string": entry_data.get("UninstallString"),
                "root_dir_path": entry_data.get("RootDirPath"),
                "program_id": entry_data.get("ProgramId"),
                "program_instance_id": entry_data.get("ProgramInstanceId"),
                "msi_package_code": entry_data.get("MsiPackageCode"),
                "msi_product_code": entry_data.get("MsiProductCode"),
                "mtime_regf": entry.timestamp,
                "install_date_arp_last_modified": parse_win_datetime(
                    install_date_arp_last_modified
                ),
                "install_date_from_link_file": [
                    parse_win_datetime(dt)
                    for dt in entry_data.get("InstallDateFromLinkFile", [])
                ],
                "os_version_at_install_time": entry_data.get("OSVersionAtInstallTime"),
                "language_code": entry_data.get("Language"),
                "package_full_name": entry_data.get("PackageFullName"),
                "manifest_path": entry_data.get("ManifestPath"),
                "registry_key_path": entry_data.get("RegistryKeyPath"),
                "source": entry_data.get("Source"),
                "evidence_id": self.evidence_id,
            }

    def parse_inventory_application_file(self):
        """Parse Root\\InventoryApplicationFile registry key subkeys.

        Amcache is a registry hive that stores information about executed programs. The InventoryApplicationFile key
        holds the application files that are in cache.

        Sources:
            - https://docs.microsoft.com/en-us/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1803
            - https://docs.microsoft.com/en-us/windows/privacy/required-windows-diagnostic-data-events-and-fields-2004#microsoftwindowsinventorycoreinventoryapplicationadd
            - https://www.andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/

        """  # noqa
        key = "Root\\InventoryApplicationFile"

        for entry in self.read_key_subkeys(key):
            entry_data = {v.name: v.value for v in entry.values()}

            # Example:
            # {
            #     "AppxPackageFullName": "Microsoft.Microsoft3DViewer_7.2105.4012.0_x64__8wekyb3d8bbwe",
            #     "AppxPackageRelativeId": "Microsoft.Microsoft3DViewer",
            #     "BinFileVersion": "7.2105.4012.0",
            #     "BinProductVersion": "7.2105.4012.0",
            #     "BinaryType": "pe64_amd64",
            #     "FileId": "00008e01cdeb9a1c23cee421a647f29c45f67623be97",
            #     "Language": 0,
            #     "LinkDate": "05/04/2021 17:43:39",
            #     "LongPathHash": "3dviewer.exe|40f275349895ac70",
            #     "LowerCaseLongPath": "c:\\program files\\windowsapps\\microsoft.0_x64__8wekyb3d8bbwe\\3dviewer.exe",
            #     "Name": "3DViewer.exe",
            #     "OriginalFileName": "3dviewer.exe",
            #     "ProductName": "view 3d",
            #     "ProductVersion": "7.2105.4012.0",
            #     "ProgramId": "0000df892556c2f7a6b7fa69f7009b5c08cb00000904",
            #     "Publisher": "microsoft corporation",
            #     "Size": 19456,
            #     "Usn": 32259776,
            #     "Version": "7.2105.4012.0"
            # }

            sha1_digest = entry_data.get("FileId", None)
            # The FileId, if it exists, is always prefixed with 4 zeroes (0000)
            # and sometimes the FileId is an empty string.
            sha1_digest = sha1_digest[-40:] if sha1_digest else None

            link_date = parse_win_datetime(entry_data.get("LinkDate"))
            # TODO: bug fix on timestamp
            # if link_date:
            #     link_date = self.ts.to_localtime(link_date)
            # else:
            #     link_date = self.ts.base_datetime_windows

            yield {
                "link_date": link_date,
                "name": entry_data.get("Name"),
                "size": entry_data.get("Size"),
                "publisher": entry_data.get("Publisher"),
                "product_name": entry_data.get("ProductName"),
                "product_version": entry_data.get("ProductVersion"),
                "bin_file_version": entry_data.get("BinFileVersion"),
                "bin_product_version": entry_data.get("BinProductVersion"),
                "version": entry_data.get("Version"),
                "program_id": entry_data.get("ProgramId"),
                "path": uri.from_windows(entry_data.get("LowerCaseLongPath")),
                "mtime_regf": entry.timestamp,
                "hash_path": entry_data.get("LongPathHash"),
                "digests": [None, sha1_digest, None],
                "language": entry_data.get("Language"),
                "is_pefile": entry_data.get("BinaryType"),
                "is_oscomponent": None,
                "evidence_id": self.evidence_id,
            }

    def parse_inventory_driver_binary(self):
        """Return InventoryDriverBinary records from Amcache hive.

        Amcache is a registry hive that stores information about executed programs. The InventoryDriverBinary key holds
        the driver binaries that are in cache.

        Sources:
            - https://binaryforay.blogspot.com/2017/10/amcache-still-rules-everything-around.html
            - https://docs.microsoft.com/en-us/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1803
            - https://www.andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/
        """
        key = "Root\\InventoryDriverBinary"

        for entry in self.read_key_subkeys(key):
            entry_data = {v.name: v.value for v in entry.values()}

            yield BinaryAppcompatRecord(
                mtime_regf=entry.timestamp,
                driver_name=uri.from_windows(entry_data.get("DriverName")),
                inf=uri.from_windows(entry_data.get("Inf")),
                driver_version=entry_data.get("DriverVersion"),
                product=entry_data.get("Product"),
                product_version=entry_data.get("ProductVersion"),
                wdf_version=entry_data.get("WdfVersion"),
                driver_company=entry_data.get("DriverCompany"),
                driver_package_strong_name=entry_data.get("DriverPackageStrongName"),
                service=entry_data.get("Service"),
                driver_signed=entry_data.get("DriverSigned"),
                driver_is_kernel_mode=entry_data.get("DriverIsKernelMode"),
                last_write_time=parse_win_datetime(
                    entry_data.get("DriverLastWriteTime")
                ),
                driver_timestamp=self.ts.wintimestamp(
                    entry_data.get("DriverTimestamp")
                ),
                image_size=entry_data.get("ImageSize"),
                _target=self._target,
            )

    def parse_inventory_application_shortcut(self):
        """Return InventoryApplicationShortcut records from Amcache hive.

        Amcache is a registry hive that stores information about executed programs. The InventoryApplicationShortcut
        field holds the shortcuts that are in cache. The key values contain information about the target of the lnk
        file.

        Sources:
            - https://binaryforay.blogspot.com/2017/10/amcache-still-rules-everything-around.html
            - https://docs.microsoft.com/en-us/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1803
            - https://www.andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/
        """
        key = "Root\\InventoryApplicationShortcut"

        for entry in self.read_key_subkeys(key):
            yield ShortcutAppcompatRecord(
                mtime_regf=entry.timestamp,
                path=uri.from_windows(entry.value("ShortCutPath").value),
                _target=self._target,
            )

    def parse_inventory_device_container(self):
        """Return InventoryDeviceContainer records from Amcache hive.

        Amcache is a registry hive that stores information about executed programs. The InventoryDeviceContainer key
        holds the device containers that are in cache. Example devices are bluetooth, printers, audio, etc.

        Sources:
            - https://binaryforay.blogspot.com/2017/10/amcache-still-rules-everything-around.html
            - https://docs.microsoft.com/en-us/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1803
            - https://www.andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/
        """

        key = "Root\\InventoryDeviceContainer"

        for entry in self.read_key_subkeys(key):
            entry_data = {v.name: v.value for v in entry.values()}
            yield ContainerAppcompatRecord(
                mtime_regf=entry.timestamp,
                categories=entry_data.get("Categories"),
                discovery_method=entry_data.get("DiscoveryMethod"),
                friendly_name=entry_data.get("FriendlyName"),
                icon=entry_data.get("Icon"),
                is_active=entry_data.get("IsActive"),
                is_connected=entry_data.get("IsConnected"),
                is_machine_container=entry_data.get("IsMachineContainer"),
                is_networked=entry_data.get("IsNetworked"),
                is_paired=entry_data.get("IsPaired"),
                manufacturer=entry_data.get("Manufacturer"),
                model_id=entry_data.get("ModelID"),
                model_name=entry_data.get("ModelName"),
                model_number=entry_data.get("ModelNumber"),
                primary_category=entry_data.get("PrimaryCategory"),
                state=entry_data.get("State"),
                _target=self._target,
            )

    def applications(self):
        """Return InventoryApplication records from Amcache hive.

        Amcache is a registry hive that stores information about executed programs. The InventoryApplication key holds
        all application objects that are in cache.

        Sources:
            - https://docs.microsoft.com/en-us/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1803
            - https://www.andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/
        """
        if self.amcache:
            yield from self.parse_inventory_application()

    def application_files(self):
        """Return InventoryApplicationFile records from Amcache hive.

        Amcache is a registry hive that stores information about executed programs. The InventoryApplicationFile key
        holds the application files that are in cache.

        Sources:
            - https://docs.microsoft.com/en-us/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1803
            - https://www.andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/
        """
        if self.amcache:
            yield from self.parse_inventory_application_file()

    def drivers(self):
        """Return InventoryDriverBinary records from Amcache hive.

        Amcache is a registry hive that stores information about executed programs. The InventoryDriverBinary key holds
        the driver binaries that are in cache.

        Sources:
            - https://binaryforay.blogspot.com/2017/10/amcache-still-rules-everything-around.html
            - https://docs.microsoft.com/en-us/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1803
            - https://www.andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/
        """
        if self.amcache:
            yield from self.parse_inventory_driver_binary()

    def shortcuts(self):
        """Return InventoryApplicationShortcut records from Amcache hive.

        Amcache is a registry hive that stores information about executed programs. The InventoryApplicationShortcut
        field holds the shortcuts that are in cache. The key values contain information about the target of the lnk
        file.

        Sources:
            - https://binaryforay.blogspot.com/2017/10/amcache-still-rules-everything-around.html
            - https://docs.microsoft.com/en-us/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1803
            - https://www.andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/
        """
        if self.amcache:
            yield from self.parse_inventory_application_shortcut()

    def device_containers(self):
        """Return InventoryDeviceContainer records from Amcache hive.

        Amcache is a registry hive that stores information about executed programs. The InventoryDeviceContainer key
        holds the device containers that are in cache. Example devices are bluetooth, printers, audio, etc.

        Sources:
            - https://binaryforay.blogspot.com/2017/10/amcache-still-rules-everything-around.html
            - https://docs.microsoft.com/en-us/windows/privacy/basic-level-windows-diagnostic-events-and-fields-1803
            - https://www.andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/
        """
        if self.amcache:
            yield from self.parse_inventory_device_container()


def parse_win_datetime(value: str):
    if value:
        try:
            return datetime.strptime(value, "%m/%d/%Y %H:%M:%S")
        except:
            pass
