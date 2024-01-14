import logging
import json
import struct

from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from dissect.target.exceptions import RegistryValueNotFoundError
from dissect.target.plugin import internal

from forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings import RSLT_REGISTRY_USB

logger = logging.getLogger(__name__)

USB_DEVICE_PROPERTY_KEYS = {
    "first_install": (
        "0064",
        "00000064",
    ),  # Windows 7 and higher. USB device first install date
    "first_insert": (
        "0065",
        "00000065",
    ),  # Windows 7 and higher. USB device first insert date.
    "last_insert": (
        "0066",
        "00000066",
    ),  # Windows 8 and higher. USB device last insert date.
    "last_removal": (
        "0067",
        "00000067",
    ),  # Windows 8 and higer. USB device last removal date.
}


class UsbstorRecord(ArtifactRecord):
    """USB registry record."""

    first_install: datetime
    product: str
    version: str
    vendor: str
    friendlyname: str
    serial: str
    vid: Optional[str]
    pid: Optional[str]
    device_type: str
    containerid: str
    first_insert: datetime
    last_insert: datetime
    last_removal: Optional[datetime]
    info_origin: str

    class Config:
        record_name: str = "reg_usb_usbstor"


@dataclass
class USB(ForensicArtifact):
    """USB plugin."""

    src: Source
    artifact: str
    category: str

    def __post_init__(self):
        self.record_schema = UsbstorRecord

    def parse(self, descending: bool = False):
        try:
            usbstor = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.usbstor())
                ),
                key=lambda record: record.first_insert,
                reverse=descending,
            )
        except Exception as e:
            logger.error(f"Error while parsing {self.artifact} from {self.evidence_id}")
            logger.error(e)
            return

        # usbstor = (
        #     self.validate_record(index=index, record=record)
        #     for index, record in enumerate(self.usbstor())
        # )
        self.result.append(usbstor)

    #
    # for record in usbstor:
    #     yield record

    #     usbstor = [
    #         self.validate_record(index=index, record=record)
    #         for index, record in enumerate(self.usbstor())
    #     ]
    #     self.result.append(usbstor)
    #     ic(self.result)

    @internal
    def unpack_timestamps(self, usb_reg_properties) -> dict:
        """
        Params:
            usb_reg_properties (Regf): A registry object with USB properties
        Returns:
            timestamps (Dict): A dict containing parsed timestamps within passed registry object
        """
        usb_reg_properties = usb_reg_properties.subkey(
            "{83da6326-97a6-4088-9453-a1923f573b29}"
        )
        timestamps = {}

        for device_property, usbstor_values in USB_DEVICE_PROPERTY_KEYS.items():
            for usb_val in usbstor_values:
                if usb_val in [x.name for x in usb_reg_properties.subkeys()]:
                    version_key = usb_reg_properties.subkey(usb_val)
                    if "00000000" in version_key.subkeys():
                        data_value = version_key.subkey("00000000").value("Data").value
                    else:
                        data_value = version_key.value("(Default)").value
                    timestamps[device_property] = self.ts.wintimestamp(
                        struct.unpack("<Q", data_value)[0]
                    )
                    break
                else:
                    timestamps[device_property] = None
        return timestamps

    @internal
    def parse_device_name(self, device_name) -> dict:
        device_info = device_name.split("&")
        device_type = device_info[0]
        vendor = device_info[1].split("Ven_")[1]
        product = device_info[2].split("Prod_")[1]
        version = None if len(device_info) < 4 else device_info[3].split("Rev_")[1]

        return dict(
            device_type=device_type, vendor=vendor, product=product, version=version
        )

    def usbstor(self):
        """Return information about attached USB devices.

        Use the registry to find information about USB devices that have been attached to the system, for example the
        HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR registry key.

        Yields UsbstorRecord with fields:
            hostname (string): The target hostname
            domain (string): The target domain
            type (string): Type of USB device
            serial (string): Serial number of USB storage device
            vid (string): Vendor ID of USB storage device
            pid (string): Product ID of the USB storage device
            rev (string): Version of the USB storage device
            containerid (string):
            friendlyname (string): Display name of the USB storage device
            first_insert (datetime): First insertion date of USB storage device
            first_install (datetime): First instalation date of USB storage device
            last_insert (datetime): Most recent insertion (arrival) date of USB storage device
            last_removal (datetime): Most recent removal (unplug) date of USB storage device
            info_origin (string): Location of info present in output
        """

        for reg_path in self.check_empty_entry(self.iter_key(name="USBSTOR")):
            for key in self.src.source.registry.keys(reg_path):
                info_origin = "\\".join((key.path, key.name))
                usb_stor = key.subkeys()

                for usb_type in usb_stor:
                    device_info = self.parse_device_name(device_name=usb_type.name)
                    usb_devices = usb_type.subkeys()
                    for usb_device in usb_devices:
                        properties = list(usb_device.subkeys())
                        serial = usb_device.name
                        try:
                            friendlyname = usb_device.value("FriendlyName").value
                            # NOTE: make this more gracefull, windows 10 does not have the LogConf subkey
                            timestamps = (
                                self.unpack_timestamps(properties[2])
                                if len(properties) == 3
                                else self.unpack_timestamps(properties[1])
                            )
                            # ContainerIDs can be found back in USB and WdpBusEnumRoot
                            containerid = usb_device.value("ContainerID").value
                        except RegistryValueNotFoundError:
                            friendlyname = None
                            timestamps = {
                                "first_install": self.ts.base_datetime_windows,
                                "first_insert": self.ts.base_datetime_windows,
                                "last_insert": self.ts.base_datetime_windows,
                                "last_removal": self.ts.base_datetime_windows,
                            }
                            containerid = None

                        first_install = timestamps.get(
                            "first_install", self.ts.base_datetime_windows
                        )
                        first_insert = timestamps.get(
                            "first_insert", self.ts.base_datetime_windows
                        )
                        last_insert = timestamps.get(
                            "last_insert", self.ts.base_datetime_windows
                        )
                        last_removal = timestamps.get(
                            "last_removal", self.ts.base_datetime_windows
                        )

                        yield UsbstorRecord(
                            first_install=first_install,
                            product=device_info.get("product", None),
                            version=device_info.get("version", None),
                            vendor=device_info.get("vendor", None),
                            friendlyname=friendlyname,
                            serial=serial,
                            vid=None,
                            pid=None,
                            device_type=device_info.get("device_type", None),
                            containerid=containerid,
                            first_insert=first_insert,
                            last_insert=last_insert,  # AKA first arrival
                            last_removal=last_removal,
                            info_origin=info_origin,
                            evidence_id=self.evidence_id,
                        )
