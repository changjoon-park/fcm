import logging
from typing import Generator, Optional
from datetime import datetime

from dissect.eventlog.evtx import Evtx

from forensic_artifact import Source, ArtifactRecord, ForensicArtifact, Record
from settings.config import Artifact

logger = logging.getLogger(__name__)


class EventLogonRecord(ArtifactRecord):
    """Event logon record."""

    ts: datetime
    task: str
    event_id: int
    event_record_id: int
    subject_user_sid: str
    subject_user_name: str
    subject_domain_name: str
    subject_logon_id: str
    target_user_sid: str
    target_user_name: str
    target_domain_name: str
    target_server_name: str
    target_info: str
    target_logon_id: str
    logon_type: str
    workstation_name: str
    ip_address: str
    ip_port: str
    channel: str
    provider: str
    evidence_id: str

    class Config:
        record_name: str = "evt_logon"


class EventUSBRecord(ArtifactRecord):
    """Event USB record."""

    ts: datetime
    task: str
    event_id: int
    event_record_id: int
    capacity_gb: float
    manufacturer: str
    model: str
    revision: str
    serialnumber: str
    mbr: str
    parent_id: str
    channel: str
    provider: str

    class Config:
        record_name: str = "evt_usb"


class EventWLANRecord(ArtifactRecord):
    """Event WLAN record."""

    ts: datetime
    task: str
    event_id: int
    event_record_id: int
    interface_guid: str
    interface_description: str
    connection_mode: str
    profile_name: str
    failure_reason: str
    reason_code: str
    ssid: str
    bsstype: str
    phytype: str
    authentication_algorithm: str
    cipher_algorithm: str
    connection_id: str
    channel: str
    provider: str

    class Config:
        record_name: str = "evt_wlan"


class ForensicEvent(ForensicArtifact):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self, descending: bool = False):
        if self.artifact == Artifact.EVT_LOGON.value:
            event_logon = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.event_logon())
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
            self.records.append(
                Record(
                    schema=EventLogonRecord,
                    record=event_logon,  # record is a generator
                )
            )
        elif self.artifact == Artifact.EVT_USB.value:
            event_usb = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.event_usb())
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
            self.records.append(
                Record(
                    schema=EventUSBRecord,
                    record=event_usb,  # record is a generator
                )
            )
        elif self.artifact == Artifact.EVT_WLAN.value:
            event_wlan = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.event_wlan())
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
            self.records.append(
                Record(
                    schema=EventWLANRecord,
                    record=event_wlan,  # record is a generator
                )
            )

    def event_logon(self) -> Generator[dict, None, None]:
        event_logon = {
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

        for entry in self.check_empty_entry(self.iter_entry(name="Security.evtx")):
            try:
                evtx = Evtx(fh=entry.open("rb"))
            except:
                pass

            for event in evtx:
                event_id = event.get("EventID")

                if task := event_logon.get(event_id, None):
                    if (
                        target_domain_name := event.get("TargetDomainName")
                    ) in exclude_list:
                        continue

                    logon_type = event.get("LogonType")
                    logon_type = logon_type_dsecription.get(logon_type)

                    yield EventLogonRecord(
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
                        provider=str(event.get("Provider_Name")),
                        evidence_id=self.evidence_id,
                    )
                else:
                    logger.debug(f"Unable to parse event: {event_id}")

    def event_usb(self) -> Generator[dict, None, None]:
        SIZE_GB = 1024 * 1024 * 1024

        for entry in self.check_empty_entry(
            self.iter_entry(name="Microsoft-Windows-Partition%4Diagnostic.evtx")
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

                    yield EventUSBRecord(
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
                        provider=str(event.get("Provider_Name")),
                    )
                else:
                    logger.debug(f"Unable to parse event: {event_id}")

    def event_wlan(self) -> Generator[dict, None, None]:
        for entry in self.check_empty_entry(
            self.iter_entry(name="Microsoft-Windows-WLAN-AutoConfig%4Operational.evtx")
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

                yield EventWLANRecord(
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
                    provider=str(event.get("Provider_Name")),
                )
