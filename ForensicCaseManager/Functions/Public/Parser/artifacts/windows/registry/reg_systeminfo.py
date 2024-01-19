import logging
from typing import Optional
from datetime import datetime
from pydantic import ValidationError

from dissect.target.exceptions import RegistryError

from forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings.artifact_paths import ArtifactSchema
from settings.artifacts import Tables

logger = logging.getLogger(__name__)


class SystemInfoRecord(ArtifactRecord):
    """System info registry record."""

    product: str
    install_date: datetime
    shutdown_time: datetime
    registered_organization: str
    registered_owner: str
    product_key: Optional[str]
    product_id: str
    edition_id: str
    release_id: str
    system_root: str
    path_name: str
    architecture: str
    timezone: str
    codepage: str

    class Config:
        table_name: str = Tables.REG_SYSTEMINFO.value


class SystemInfo(ForensicArtifact):
    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    def parse(self, descending: bool = False):
        try:
            system_info = [
                self.validate_record(index=index, record=record)
                for index, record in enumerate(self.system_info())
            ]
        except Exception as e:
            self.log_error(e)
            return

        self.records.append(system_info)

    @property
    def timezone(self):
        return self.src.source.datetime.tzinfo

    @property
    def last_shutdown_time(self):
        for reg_path in self.iter_entry(entry_name="Windows"):
            try:
                bin_value = (
                    self.src.source.registry.key(reg_path).value("ShutdownTime").value
                )
                return self.ts.wintimestamp(int.from_bytes(bin_value, "little"))
            except:
                logger.info(f"Failed to get last shutdown time from {reg_path}")
                return ""

    @property
    def codepage(self):
        for reg_path in self.iter_entry(entry_name="CodePage"):
            try:
                return self.src.source.registry.key(reg_path).value("ACP").value
            except RegistryError:
                logger.info(f"Failed to get codepage from {reg_path}")
                return ""

    @property
    def architecture(self):
        arch_strings = {
            "x86": 32,
            "IA64": 64,
            "ARM64": 64,
            "EM64T": 64,
            "AMD64": 64,
        }
        for reg_path in self.iter_entry(entry_name="Environment"):
            try:
                arch = (
                    self.src.source.registry.key(reg_path)
                    .value("PROCESSOR_ARCHITECTURE")
                    .value
                )
                bits = arch_strings.get(arch)

                if bits == 64:
                    return f"{arch}-win{bits}".lower()
                else:
                    return f"{arch}_{bits}-win{bits}".lower()
            except RegistryError:
                logger.info(f"Failed to get architecture from {reg_path}")
                pass

    # https://dfir.ru/2018/12/08/the-last-access-updates-are-almost-back/?fbclid=IwAR2Q6uj5EIAZ-HqBeRmYXecYCCQa693wc81HCm8KsRHDJ9rwOldaraipy-o
    # @property
    # def ntfs_disable_lastaccess_update(self):
    #     for reg_path in self.iter_entry(entry_name="FileSystem"):
    #         try:
    #             lastaccess_update_flag = self.src.source.registry.key(reg_path).value("NtfsDisableLastAccessUpdate").value
    #         except RegistryError:
    #             pass

    #     if lastaccess_update_flag:
    #         pass

    def get_current_version(self):
        key_map = {
            "Windows 10 Pro": "W269N-WFGWX-YVC9B-4J6C9-T83GX",
            "Windows 10 Pro N": "MH37W-N47XK-V7XM9-C7227-GCQG9",
            "Windows 10 Pro for Workstations": "NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J",
            "Windows 10 Pro for Workstations N": "9FNHH-K3HBT-3W4TD-6383H-6XYWF",
            "Windows 10 Pro Education": "6TP4R-GNPTD-KYYHQ-7B7DP-J447Y",
            "Windows 10 Pro Education N": "YVWGF-BXNMC-HTQYQ-CPQ99-66QFC",
            "Windows 10 Education": "NW6C2-QMPVW-D7KKK-3GKT6-VCFB2",
            "Windows 10 Education KN": "2WH4N-8QGBV-H22JP-CT43Q-MDWWJ",
            "Windows 10 Enterprise": "NPPR9-FWDCX-D2C8J-H872K-2YT43",
            "Windows 10 Enterprise KN": "DPH2V-TTNVB-4X9Q3-TJR4H-KHJW4",
            "Windows 10 Enterprise G": "YYVX9-NTFWV-6MDM3-9PT4T-4M68B",
            "Windows 10 Enterprise G N": "44RPN-FTY23-9VTTB-MP9BX-T84FV",
        }

        for reg_path in self.iter_entry(entry_name="CurrentVersion"):
            try:
                csd_version = (
                    self.src.source.registry.key(reg_path).value("CSDVersion").value
                )
            except:
                csd_version = str()

            try:
                r = self.src.source.registry.key(reg_path)
                product_name = r.value("ProductName").value
                current_version = r.value("CurrentVersion").value
                current_build_number = r.value("CurrentBuildNumber").value
                product_id = r.value("ProductId").value
                edition_id = r.value("EditionID").value
                release_id = r.value("ReleaseId").value
                system_root = r.value("SystemRoot").value
                path_name = r.value("PathName").value
                registered_organization = r.value("RegisteredOrganization").value
                registered_owner = r.value("RegisteredOwner").value
                install_date_unix = r.value("InstallDate").value
            except:
                product_name = ""
                current_version = ""
                current_build_number = ""
                product_id = ""
                edition_id = ""
                release_id = ""
                system_root = ""
                path_name = ""
                registered_organization = ""
                registered_owner = ""
                install_date_unix = ""

            product = f"{product_name} (NT {current_version}) {current_build_number} {csd_version}"

            try:
                install_date = self.ts.from_unix(install_date_unix)
            except:
                install_date = None

            return {
                "product": product,
                "install_date": install_date,
                "product_key": key_map.get(product_name),
                "registered_organization": registered_organization,
                "registered_owner": registered_owner,
                "product_id": product_id,
                "edition_id": edition_id,
                "release_id": release_id,
                "system_root": system_root,
                "path_name": path_name,
            }

    def system_info(self):
        current_version = self.get_current_version()

        parsed_data = {
            "product": current_version.get("product"),
            "install_date": current_version.get("install_date"),
            "shutdown_time": self.last_shutdown_time,
            "registered_organization": current_version.get("registered_organization"),
            "registered_owner": current_version.get("registered_owner"),
            "product_key": current_version.get("product_key"),
            "product_id": current_version.get("product_id"),
            "edition_id": current_version.get("edition_id"),
            "release_id": current_version.get("release_id"),
            "system_root": current_version.get("system_root"),
            "path_name": current_version.get("path_name"),
            "architecture": self.architecture,
            "timezone": str(self.timezone),
            "codepage": self.codepage,
            "evidence_id": self.evidence_id,
        }

        try:
            yield SystemInfoRecord(**parsed_data)
        except ValidationError as e:
            self.log_error(e)
            pass
