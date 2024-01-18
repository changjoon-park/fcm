import struct
from typing import Optional
from datetime import datetime
from pydantic import ValidationError

from dissect.target.exceptions import RegistryError
from util.converter import convertfrom_extended_ascii

from forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings.artifact_paths import ArtifactSchema


class NetworkInterfaceRecord(ArtifactRecord):
    """Network interface registry record."""

    ipaddr: Optional[str]
    dhcp_ipaddr: Optional[str]
    lease_obtained_time: datetime
    lease_terminates_time: datetime
    dhcp_server: Optional[str]

    class Config:
        record_name: str = "reg_network_interface"


class NetworkHistoryRecord(ArtifactRecord):
    """Network history registry record."""

    created: datetime
    last_connected: datetime
    profile_guid: str
    profile_name: str
    description: str
    dns_suffix: str
    first_network: str
    default_gateway_mac: str
    signature: str

    class Config:
        record_name: str = "reg_network_history"


class NetworkInfo(ForensicArtifact):
    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    def parse(self, descending: bool = False):
        try:
            network_history = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.network_history())
                ),
                key=lambda record: record.created,
                reverse=descending,
            )
            network_interface = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.network_interface())
                ),
                key=lambda record: record.lease_obtained_time,
                reverse=descending,
            )
        except Exception as e:
            self.log_error(e)
            return

        self.records.append(network_history)
        self.records.append(network_interface)

    def network_interface(self):
        entry_name = "Interfaces"
        for reg_path in self.iter_entry(entry_name=entry_name):
            for key in self.src.source.registry.keys(reg_path):
                for s in key.subkeys():
                    # try:
                    #     enable_dhcp_flag = s.value("EnableDHCP").value
                    # except:
                    #     raise RegistryError

                    try:
                        ipaddr = s.value("IPAddress").value
                        if isinstance(ipaddr, list):
                            ipaddr = ", ".join(ipaddr)
                            if ipaddr == "0.0.0.0":
                                continue
                    except:
                        ipaddr = None

                    try:
                        dhcp_ipaddr = s.value("DhcpIPAddress").value
                        dhcp_server = s.value("DhcpServer").value
                        if dhcp_ipaddr == "0.0.0.0":
                            continue
                    except:
                        dhcp_ipaddr = None
                        dhcp_server = None

                    try:
                        lease_obtained_time_unix = s.value("LeaseObtainedTime").value
                        lease_terminates_time_unix = s.value(
                            "LeaseTerminatesTime"
                        ).value
                    except:
                        lease_obtained_time_unix = None
                        lease_terminates_time_unix = None

                    if lease_obtained_time_unix:
                        lease_obtained_time = self.ts.from_unix(
                            lease_obtained_time_unix
                        )
                    else:
                        lease_obtained_time = None

                    if lease_terminates_time_unix:
                        lease_terminates_time = self.ts.from_unix(
                            lease_terminates_time_unix
                        )
                    else:
                        lease_terminates_time = None

                    if not lease_obtained_time:
                        lease_obtained_time = self.ts.base_datetime_windows

                    if not lease_terminates_time:
                        lease_terminates_time = self.ts.base_datetime_windows

                    parsed_data = {
                        "ipaddr": ipaddr,
                        "dhcp_ipaddr": dhcp_ipaddr,
                        "lease_obtained_time": lease_obtained_time,
                        "lease_terminates_time": lease_terminates_time,
                        "dhcp_server": dhcp_server,
                        "evidence_id": self.evidence_id,
                    }

                    try:
                        yield NetworkInterfaceRecord(**parsed_data)
                    except ValidationError as e:
                        self.log_error(e)
                        continue

    def network_history(self):
        """Return attached network history.

        The HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Signatures and
        HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Profiles registry keys contain information
        about the networks to which the system has been connected, both wireless and wired.

        Sources:
            - https://www.weaklink.org/2016/11/windows-network-profile-registry-keys/
        """
        entry_name = "Signatures"
        for reg_path in self.iter_entry(entry_name=entry_name):
            for key in self.src.source.registry.keys(reg_path):
                for kind in key.subkeys():
                    for sig in kind.subkeys():
                        guid = sig.value("ProfileGuid").value
                        profile = self.find_profile(guid)
                        profile_name = profile.value("ProfileName").value

                        try:
                            _ = profile_name.encode("ASCII")
                        except:
                            profile_name = convertfrom_extended_ascii(
                                string=profile_name, encoding="UTF-16-LE"
                            )

                        created = parse_ts(profile.value("DateCreated").value)
                        last_connected = parse_ts(
                            profile.value("DateLastConnected").value
                        )

                        parsed_data = {
                            "created": created,
                            "last_connected": last_connected,
                            "profile_guid": guid,
                            "profile_name": profile_name,
                            "description": sig.value("Description").value,
                            "dns_suffix": sig.value("DnsSuffix").value,
                            "first_network": sig.value("FirstNetwork").value,
                            "default_gateway_mac": sig.value(
                                "DefaultGatewayMac"
                            ).value.hex(),
                            "signature": sig.name,
                            "evidence_id": self.evidence_id,
                            "record_name": self.name,
                        }

                        try:
                            yield NetworkHistoryRecord(**parsed_data)
                        except ValidationError as e:
                            self.log_error(e)
                            continue

    def find_profile(self, guid):
        entry_name = "Profiles"
        for reg_path in self.iter_entry(entry_name=entry_name):
            for key in self.src.source.registry.keys(reg_path):
                try:
                    return key.subkey(guid)  # Just return the first one...
                except RegistryError as e:
                    self.log_error(e)
                    continue


def parse_ts(val):
    items = list(struct.unpack("<8H", val))
    # If we remove the weekday (at position 2), this is a valid datetime tuple
    items.pop(2)
    return datetime(*items)
