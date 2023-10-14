import json
from typing import Generator

from dissect.eventlog.evtx import Evtx
from dissect.target.helpers.record import TargetRecordDescriptor

from forensic_artifact import Source, ForensicArtifact


LogonEventRecord = TargetRecordDescriptor(
    "eventlog/logonoff",
    [
        ("datetime", "ts"),
        ("string", "task"),
        ("string", "subject_user_sid"),
        ("string", "subject_user_name"),
        ("string", "subject_domain_name"),
        ("string", "subject_logon_id"),
        ("string", "target_user_sid"),
        ("string", "target_user_name"),
        ("string", "target_domain_name"),
        ("string", "target_server_name"),
        ("string", "target_info"),
        ("string", "target_logon_id"),
        ("string", "logon_type"),
        ("string", "workstation_name"),
        ("string", "ip_address"),
        ("string", "ip_port"),
        ("uint32", "event_id"),
        ("uint32", "event_record_id"),
        ("string", "channel"),
        ("string", "provider"),
    ],
)

UsbEventRecord = TargetRecordDescriptor(
    "eventlog/usb",
    [
        ("datetime", "ts"),
        ("string", "task"),
        ("float", "capacity_gb"),
        ("string", "manufacturer"),
        ("string", "model"),
        ("string", "revision"),
        ("string", "serialnumber"),
        ("string", "parent_id"),
        ("bytes", "mbr"),
        # ("bytes", "vbr0"),
        # ("bytes", "vbr1"),
        # ("bytes", "vbr2"),
        # ("bytes", "vbr3"),
        ("uint32", "event_id"),
        ("uint32", "event_record_id"),
        ("string", "channel"),
        ("string", "provider"),
    ],
)

WlanEventRecord = TargetRecordDescriptor(
    "eventlog/wlan",
    [
        ("datetime", "ts"),
        ("string", "task"),
        ("string", "interface_guid"),
        ("string", "interface_description"),
        ("string", "connection_mode"),
        ("string", "profile_name"),
        ("string", "ssid"),
        ("string", "failure_reason"),
        ("string", "reason_code"),
        ("string", "bsstype"),
        ("string", "phytype"),
        ("string", "authentication_algorithm"),
        ("string", "cipher_algorithm"),
        ("string", "connection_id"),
        ("uint32", "event_id"),
        ("uint32", "event_record_id"),
        ("string", "channel"),
        ("string", "provider"),
    ],
)


class ForensicEvent(ForensicArtifact):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self, descending: bool = False):
        if self.artifact == "LogonEvent":
            logon_event = sorted(
                [
                    json.dumps(
                        record._packdict(), indent=2, default=str, ensure_ascii=False
                    )
                    for record in self.logon_event()
                ],
                reverse=descending,
            )

            self.result = {
                "logon_event": logon_event,
            }
        elif self.artifact == "USB(EventLog)":
            usb_event = sorted(
                [
                    json.dumps(
                        record._packdict(), indent=2, default=str, ensure_ascii=False
                    )
                    for record in self.usb_event()
                ],
                reverse=descending,
            )

            self.result = {
                "usb_event": usb_event,
            }
        elif self.artifact == "WLAN":
            wlan_event = sorted(
                [
                    json.dumps(
                        record._packdict(), indent=2, default=str, ensure_ascii=False
                    )
                    for record in self.wlan_event()
                ],
                reverse=descending,
            )

            self.result = {
                "wlan_event": wlan_event,
            }

    def logon_event(self) -> Generator[LogonEventRecord, None, None]:
        logon_event = {
            4624: "Account Logon",
            4625: "Account Logon Failed",
            4634: "Account Logoff",
            4647: "Account Logoff",
            4648: "Account Logon",
            # 6005: "System Boot",
            # 6006: "System Shutdown",
        }
        logon_type_dsecription = {
            2: "2: Interactive",
            3: "3: Network",
            4: "4: Batch",
            5: "5: Service",
            7: "7: Unlock",
            8: "8: NetworkClearText",
            9: "9: NewCredentials",
            10: "10: RemoteInteractive",
            11: "11: CachedInteractive",
        }
        exclude_list = [
            "Font Driver Host",
            "NT AUTHORITY",
            "NT VIRTUAL MACHINE",
            "Window Manager",
            "NT Service",
        ]

        for entry in self._iter_entry(name="Security.evtx"):
            try:
                evtx = Evtx(fh=entry.open("rb"))
            except:
                pass

            for event in evtx:
                event_id = event.get("EventID")

                if task := logon_event.get(event_id, None):
                    if (
                        target_domain_name := event.get("TargetDomainName")
                    ) in exclude_list:
                        continue

                    logon_type = event.get("LogonType")
                    logon_type = logon_type_dsecription.get(logon_type)

                    yield LogonEventRecord(
                        ts=self.ts.to_localtime(
                            event.get("TimeCreated_SystemTime").value
                        ),
                        task=task,
                        event_id=event_id,
                        event_record_id=event.get("EventRecordID"),
                        subject_user_sid=event.get("SubjectUserSid"),
                        subject_user_name=event.get("SubjectUserName"),
                        subject_domain_name=event.get("SubjectDomainName"),
                        subject_logon_id=event.get("SubjectLogonId"),
                        target_user_sid=event.get("TargetUserSid"),
                        target_user_name=event.get("TargetUserName"),
                        target_domain_name=target_domain_name,
                        target_server_name=event.get("TargetServerName"),
                        target_info=event.get("TargetInfo"),
                        target_logon_id=event.get("TargetLogonId"),
                        logon_type=logon_type,
                        workstation_name=event.get("WorkstationName"),
                        ip_address=event.get("IpAddress"),
                        ip_port=event.get("IpPort"),
                        channel=event.get("Channel"),
                        provider=event.get("Provider_Name"),
                        _target=self._target,
                    )
                else:
                    continue

    def usb_event(self) -> Generator[UsbEventRecord, None, None]:
        SIZE_GB = 1024 * 1024 * 1024

        for entry in self._iter_entry(
            name="Microsoft-Windows-Partition%4Diagnostic.evtx"
        ):
            try:
                evtx = Evtx(fh=entry.open("rb"))
            except:
                pass

            for event in evtx:
                if (event_id := event.get("EventID")) == 1006:
                    if capacity := event.get("Capacity"):
                        size_gb = capacity / SIZE_GB
                        capacity_gb = round(size_gb, 2)
                        task = "USB Connected"
                    else:
                        task = "USB Disconnected"

                    yield UsbEventRecord(
                        ts=self.ts.to_localtime(
                            event.get("TimeCreated_SystemTime").value
                        ),
                        task=task,
                        event_id=event_id,
                        event_record_id=event.get("EventRecordID"),
                        capacity_gb=capacity_gb,
                        manufacturer=event.get("Manufacturer"),
                        model=event.get("Model"),
                        revision=event.get("Revision"),
                        serialnumber=event.get("SerialNumber"),
                        mbr=event.get("Mbr"),
                        parent_id=event.get("ParentId"),
                        channel=event.get("Channel"),
                        provider=event.get("Provider_Name"),
                        _target=self._target,
                    )
                else:
                    continue

    def wlan_event(self) -> Generator[WlanEventRecord, None, None]:
        for entry in self._iter_entry(
            name="Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx"
        ):
            try:
                evtx = Evtx(fh=entry.open("rb"))
            except:
                pass

            for event in evtx:
                event_id = event.get("EventID")
                if event_id == 8001:
                    task = "Wifi Connected"
                elif event_id == 8002:
                    task = "Wifi Connection Failed"
                elif event_id == 8003:
                    task = "Wifi Disconnected"
                else:
                    continue

                yield WlanEventRecord(
                    ts=self.ts.to_localtime(event.get("TimeCreated_SystemTime").value),
                    task=task,
                    event_id=event_id,
                    event_record_id=event.get("EventRecordID"),
                    interface_guid=event.get("InterfaceGuid"),
                    interface_description=event.get("InterfaceDescription"),
                    connection_mode=event.get("ConnectionMode"),
                    profile_name=event.get("ProfileName"),
                    failure_reason=event.get("FailureReason"),
                    reason_code=event.get("ReasonCode"),
                    ssid=event.get("SSID"),
                    bsstype=event.get("BSSType"),
                    phytype=event.get("PHYType"),
                    authentication_algorithm=event.get("AuthenticationAlgorithm"),
                    cipher_algorithm=event.get("CipherAlgorithm"),
                    connection_id=event.get("ConnectionId"),
                    channel=event.get("Channel"),
                    provider=event.get("Provider_Name"),
                    _target=self._target,
                )
