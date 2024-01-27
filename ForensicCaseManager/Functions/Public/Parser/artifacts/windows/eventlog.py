import logging
from typing import Generator, Optional
from datetime import datetime

from pydantic import ValidationError
from dissect.eventlog.evtx import Evtx

from core.forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings.tables import Tables
from settings.artifact_schema import ArtifactSchema

logger = logging.getLogger(__name__)


class LogonEventRecord(ArtifactRecord):
    """Event logon record."""

    ts: datetime
    task: str
    event_id: int
    event_record_id: int
    subject_user_sid: Optional[str]
    subject_user_name: Optional[str]
    subject_domain_name: Optional[str]
    subject_logon_id: Optional[str]
    target_user_sid: Optional[str]
    target_user_name: Optional[str]
    target_domain_name: Optional[str]
    target_server_name: Optional[str]
    target_info: Optional[str]
    target_logon_id: Optional[str]
    logon_type: Optional[str]
    workstation_name: Optional[str]
    ip_address: Optional[str]
    ip_port: Optional[str]
    channel: str
    provider: str
    evidence_id: str

    class Config:
        table_name: str = Tables.EVENT_LOGON.value


class UsbEventRecord(ArtifactRecord):
    """Event USB record."""

    ts: datetime
    task: str
    event_id: int
    event_record_id: int
    capacity_gb: float
    manufacturer: Optional[str]
    model: Optional[str]
    revision: Optional[str]
    serialnumber: Optional[str]
    mbr: Optional[str]
    parent_id: Optional[str]
    channel: str
    provider: str

    class Config:
        table_name: str = Tables.EVENT_USB.value


class WlanEventRecord(ArtifactRecord):
    """Event WLAN record."""

    ts: datetime
    task: str
    event_id: int
    event_record_id: int
    interface_guid: Optional[str]
    interface_description: Optional[str]
    connection_mode: Optional[str]
    profile_name: Optional[str]
    failure_reason: Optional[str]
    reason_code: Optional[int]
    ssid: Optional[str]
    bsstype: Optional[str]
    phytype: Optional[str]
    authentication_algorithm: Optional[str]
    cipher_algorithm: Optional[str]
    connection_id: Optional[str]
    channel: str
    provider: str

    class Config:
        table_name: str = Tables.EVENT_WLAN.value


class LogonEvent(ForensicArtifact):
    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    def parse(self, descending: bool = False):
        try:
            logon_event = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.logon_event())
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
            self.records.append(logon_event)
        except Exception as e:
            self.log_error(e)
            logon_event = []
        finally:
            return logon_event

    def logon_event(self) -> Generator[dict, None, None]:
        logon_event_id = {
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

        for entry in self.check_empty_entry(self.iter_entry()):
            try:
                evtx = Evtx(fh=entry.open("rb"))
            except:
                pass

            for event in evtx:
                event_id = event.get("EventID")

                if task := logon_event_id.get(event_id, None):
                    if (
                        target_domain_name := event.get("TargetDomainName")
                    ) in exclude_list:
                        continue

                    logon_type = event.get("LogonType")
                    logon_type = logon_type_dsecription.get(logon_type)

                    parsed_data = {
                        "ts": self.ts.to_localtime(
                            event.get("TimeCreated_SystemTime").value
                        ),
                        "task": task,
                        "event_id": event_id,
                        "event_record_id": event.get("EventRecordID"),
                        "subject_user_sid": event.get("SubjectUserSid"),
                        "subject_user_name": event.get("SubjectUserName"),
                        "subject_domain_name": event.get("SubjectDomainName"),
                        "subject_logon_id": event.get("SubjectLogonId"),
                        "target_user_sid": event.get("TargetUserSid"),
                        "target_user_name": event.get("TargetUserName"),
                        "target_domain_name": target_domain_name,
                        "target_server_name": event.get("TargetServerName"),
                        "target_info": event.get("TargetInfo"),
                        "target_logon_id": event.get("TargetLogonId"),
                        "logon_type": logon_type,
                        "workstation_name": event.get("WorkstationName"),
                        "ip_address": event.get("IpAddress"),
                        "ip_port": event.get("IpPort"),
                        "channel": event.get("Channel"),
                        "provider": str(event.get("Provider_Name")),
                        "evidence_id": self.evidence_id,
                    }

                    try:
                        yield LogonEventRecord(**parsed_data)
                    except ValidationError as e:
                        self.log_error(e)
                        continue
                else:
                    logger.debug(f"Unable to parse event: {event_id}")


class UsbEvent(ForensicArtifact):
    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    def parse(self, descending: bool = False):
        try:
            usb_event = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.usb_event())
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
            self.records.append(usb_event)
        except Exception as e:
            self.log_error(e)
            usb_event = []
        finally:
            return usb_event

    def usb_event(self) -> Generator[dict, None, None]:
        SIZE_GB = 1024 * 1024 * 1024

        for entry in self.check_empty_entry(self.iter_entry()):
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

                    parsed_data = {
                        "ts": self.ts.to_localtime(
                            event.get("TimeCreated_SystemTime").value
                        ),
                        "task": task,
                        "event_id": event_id,
                        "event_record_id": event.get("EventRecordID"),
                        "capacity_gb": capacity_gb,
                        "manufacturer": event.get("Manufacturer"),
                        "model": event.get("Model"),
                        "revision": event.get("Revision"),
                        "serialnumber": event.get("SerialNumber"),
                        "mbr": event.get("Mbr"),
                        "parent_id": event.get("ParentId"),
                        "channel": event.get("Channel"),
                        "provider": str(event.get("Provider_Name")),
                        "evidence_id": self.evidence_id,
                    }

                    try:
                        yield UsbEventRecord(**parsed_data)
                    except ValidationError as e:
                        self.log_error(e)
                        continue
                else:
                    logger.debug(f"Unable to parse event: {event_id}")


class WlanEvent(ForensicArtifact):
    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    def parse(self, descending: bool = False):
        try:
            wlan_event = sorted(
                (
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.wlan_event())
                ),
                key=lambda record: record.ts,
                reverse=descending,
            )
            self.records.append(wlan_event)
        except Exception as e:
            self.log_error(e)
            wlan_event = []
        finally:
            return wlan_event

    def wlan_event(self) -> Generator[dict, None, None]:
        for entry in self.check_empty_entry(self.iter_entry()):
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

                parsed_data = {
                    "ts": self.ts.to_localtime(
                        event.get("TimeCreated_SystemTime").value
                    ),
                    "task": task,
                    "event_id": event_id,
                    "event_record_id": event.get("EventRecordID"),
                    "interface_guid": event.get("InterfaceGuid"),
                    "interface_description": event.get("InterfaceDescription"),
                    "connection_mode": event.get("ConnectionMode"),
                    "profile_name": event.get("ProfileName"),
                    "failure_reason": event.get("FailureReason"),
                    "reason_code": event.get("ReasonCode"),
                    "ssid": event.get("SSID"),
                    "bsstype": event.get("BSSType"),
                    "phytype": event.get("PHYType"),
                    "authentication_algorithm": event.get("AuthenticationAlgorithm"),
                    "cipher_algorithm": event.get("CipherAlgorithm"),
                    "connection_id": event.get("ConnectionId"),
                    "channel": event.get("Channel"),
                    "provider": str(event.get("Provider_Name")),
                    "evidence_id": self.evidence_id,
                }

                try:
                    yield WlanEventRecord(**parsed_data)
                except ValidationError as e:
                    self.log_error(e)
                    continue
