import json
import struct

from dissect.target.exceptions import RegistryValueNotFoundError
from dissect.target.plugin import internal
from dissect.target.helpers.record import TargetRecordDescriptor

from forensic_artifact import Source, ForensicArtifact

UsbRegistryRecord = TargetRecordDescriptor(
    "windows/registry/usb",
    [
        ("datetime", "first_insert"),
        ("string", "product"),
        ("string", "version"),
        ("string", "vendor"),
        ("string", "friendlyname"),
        ("string", "serial"),
        ("string", "vid"),
        ("string", "pid"),
        ("string", "rev"),
        ("string", "device_type"),
        ("string", "containerid"),
        ("datetime", "first_install"),
        ("datetime", "last_insert"),
        ("datetime", "last_removal"),
        ("string", "info_origin"),
    ],
)


USB_DEVICE_PROPERTY_KEYS = {
    "first_install": ("0064", "00000064"),  # Windows 7 and higher. USB device first install date
    "first_insert": ("0065", "00000065"),  # Windows 7 and higher. USB device first insert date.
    "last_insert": ("0066", "00000066"),  # Windows 8 and higher. USB device last insert date.
    "last_removal": ("0067", "00000067"),  # Windows 8 and higer. USB device last removal date.
}


class USB(ForensicArtifact):
    """USB plugin."""

    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(
            src=src,
            artifact=artifact,
            category=category
        )

    def parse(self, descending: bool = False):
        usbstor = sorted([
            json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
            for record in self.usbstor()], reverse=descending)
                            
        self.result = {
            "usbstor": usbstor,
        }
        
    @internal
    def unpack_timestamps(self, usb_reg_properties):
        """
        Params:
            usb_reg_properties (Regf): A registry object with USB properties
        Returns:
            timestamps (Dict): A dict containing parsed timestamps within passed registry object
        """
        usb_reg_properties = usb_reg_properties.subkey("{83da6326-97a6-4088-9453-a1923f573b29}")
        timestamps = {}

        for device_property, usbstor_values in USB_DEVICE_PROPERTY_KEYS.items():
            for usb_val in usbstor_values:
                if usb_val in [x.name for x in usb_reg_properties.subkeys()]:
                    version_key = usb_reg_properties.subkey(usb_val)
                    if "00000000" in version_key.subkeys():
                        data_value = version_key.subkey("00000000").value("Data").value
                    else:
                        data_value = version_key.value("(Default)").value
                    timestamps[device_property] = self.ts.wintimestamp(struct.unpack("<Q", data_value)[0])
                    break
                else:
                    timestamps[device_property] = None
        return timestamps

    @internal
    def parse_device_name(self, device_name):
        device_info = device_name.split("&")
        device_type = device_info[0]
        vendor = device_info[1].split("Ven_")[1]
        product = device_info[2].split("Prod_")[1]
        version = None if len(device_info) < 4 else device_info[3].split("Rev_")[1]

        return dict(device_type=device_type, vendor=vendor, product=product, version=version)

    def usbstor(self):
        """Return information about attached USB devices.

        Use the registry to find information about USB devices that have been attached to the system, for example the
        HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR registry key.

        Yields UsbRegistryRecord with fields:
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

        for reg_path in self._iter_key(name="USBSTOR"):
            for k in self.src.source.registry.keys(reg_path):
                info_origin = "\\".join((k.path, k.name))
                usb_stor = k.subkeys()

                for usb_type in usb_stor:
                    device_info = self.parse_device_name(usb_type.name)
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
                                "first_install": None,
                                "first_insert": None,
                                "last_insert": None,
                                "last_removal": None,
                            }
                            containerid = None

                        yield UsbRegistryRecord(
                            first_install=timestamps["first_install"],
                            product=device_info["product"],
                            version=device_info["version"],
                            vendor=device_info["vendor"],
                            friendlyname=friendlyname,
                            serial=serial,
                            vid=None,
                            pid=None,
                            device_type=device_info["device_type"],
                            containerid=containerid,
                            first_insert=timestamps["first_insert"],
                            last_insert=timestamps["last_insert"],  # AKA first arrival
                            last_removal=timestamps["last_removal"],
                            info_origin=info_origin,
                            _target=self._target,
                        )