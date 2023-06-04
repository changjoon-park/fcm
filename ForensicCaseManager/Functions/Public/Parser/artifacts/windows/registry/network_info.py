import json
import datetime
import struct

from dissect.target.exceptions import RegistryError
from dissect.target.helpers.record import TargetRecordDescriptor

from util.converter import convertfrom_extended_ascii
from forensic_artifact import Source, ForensicArtifact

NetworkHistoryRecord = TargetRecordDescriptor(
    "windows/registry/nethist",
    [
        ("datetime", "created"),
        ("datetime", "last_connected"),
        ("string", "profile_guid"),
        ("string", "profile_name"),
        ("string", "description"),
        ("string", "dns_suffix"),
        ("string", "first_network"),
        ("string", "default_gateway_mac"),
        ("string", "signature"),
    ],
)

NetworkInterfaceRecord = TargetRecordDescriptor(
    "windows/registry/network_interface",
    [
        # ("bytes", "enable_dhcp"),
        ("string", "ipaddr"),
        ("string", "dhcp_ipaddr"),
        ("datetime", "lease_obtained_time"),
        ("datetime", "lease_terminates_time"),
        ("string", "dhcp_server"),
    ],
)

class NetworkInfo(ForensicArtifact):

    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(
            src=src,
            artifact=artifact,
            category=category
        )

    def parse(self, descending: bool = False):
        network_history = sorted([
            json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
            for record in self.network_history()], reverse=descending)

        network_interface = sorted([
            json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
            for record in self.network_interface()], reverse=descending)
        
        self.result = {
            "network_interface": network_interface,
            "network_history": network_history,
        }
        
    def network_interface(self):
        for reg_path in self._iter_key(name="Interfaces"):
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
                        lease_terminates_time_unix = s.value("LeaseTerminatesTime").value
                    except:
                        lease_obtained_time_unix = None
                        lease_terminates_time_unix = None

                    if lease_obtained_time_unix:
                        lease_obtained_time = self.ts.from_unix(lease_obtained_time_unix)
                    else:
                        lease_obtained_time = None
                        
                    if lease_terminates_time_unix:
                        lease_terminates_time = self.ts.from_unix(lease_terminates_time_unix)
                    else:
                        lease_terminates_time = None

                    yield NetworkInterfaceRecord(
                        ipaddr=ipaddr,
                        dhcp_ipaddr=dhcp_ipaddr,
                        lease_obtained_time=lease_obtained_time,
                        lease_terminates_time=lease_terminates_time,
                        dhcp_server=dhcp_server,
                        _target=self._target,
                    )

    def network_history(self):
        """Return attached network history.

        The HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Signatures and
        HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Networklist\\Profiles registry keys contain information
        about the networks to which the system has been connected, both wireless and wired.

        Sources:
            - https://www.weaklink.org/2016/11/windows-network-profile-registry-keys/
        """
        for reg_path in self._iter_key(name="Signatures"):
            for key in self.src.source.registry.keys(reg_path):
                for kind in key.subkeys():
                    for sig in kind.subkeys():
                        guid = sig.value("ProfileGuid").value
                        profile = self.find_profile(guid)
                        profile_name = profile.value("ProfileName").value
                        
                        try:
                            _ = profile_name.encode("ASCII")
                        except:
                            profile_name = convertfrom_extended_ascii(string=profile_name, encoding="UTF-16-LE")

                        created = parse_ts(profile.value("DateCreated").value)
                        last_connected = parse_ts(profile.value("DateLastConnected").value)

                        yield NetworkHistoryRecord(
                            created=created,
                            last_connected=last_connected,
                            profile_guid=guid,
                            profile_name=profile.value("ProfileName").value,
                            description=sig.value("Description").value,
                            dns_suffix=sig.value("DnsSuffix").value,
                            first_network=sig.value("FirstNetwork").value,
                            default_gateway_mac=sig.value("DefaultGatewayMac").value.hex(),
                            signature=sig.name,
                            _target=self._target,
                        )

    
    def find_profile(self, guid):
        for reg_path in self._iter_key(name="Profiles"):
            for key in self.src.source.registry.keys(reg_path):
                try:
                    return key.subkey(guid)  # Just return the first one...
                except RegistryError:
                    pass


def parse_ts(val):
    items = list(struct.unpack("<8H", val))
    # If we remove the weekday (at position 2), this is a valid datetime tuple
    items.pop(2)
    return datetime.datetime(*items)
