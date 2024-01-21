import logging
from typing import Generator, Optional
from datetime import datetime
from icecream import ic

from pydantic import ValidationError
from dissect.esedb.tools.sru import SRU as SRUParser
from dissect.target.plugins.os.windows.sru import FIELD_MAPPINGS, TRANSFORMS

from forensic_artifact import Source, ArtifactRecord, ForensicArtifact
from settings.artifact_paths import ArtifactSchema
from settings.artifacts import Artifacts, Tables

logger = logging.getLogger(__name__)


class SruNetworkRecord(ArtifactRecord):
    """SRU Network record."""

    ts: datetime
    app: Optional[str]
    user: Optional[str]
    interface_luid: int
    l2_profile_id: int
    l2_profile_flags: int
    bytes_sent: Optional[int]
    bytes_recvd: Optional[int]
    connected_time: Optional[int]
    connect_start_time: Optional[datetime]
    sru_table: str

    class Config:
        table_name: str = Tables.WIN_SRU_NETWORK.value


class SruApplicationRecord(ArtifactRecord):
    """SRU Application record."""

    ts: datetime
    app: str
    user: str
    foreground_cycle_time: int
    background_cycle_time: int
    face_time: int
    foreground_context_switches: int
    background_context_switches: int
    foreground_bytes_read: int
    foreground_bytes_written: int
    foreground_num_read_operations: int
    foreground_num_write_operations: int
    foreground_number_of_flushes: int
    background_bytes_read: int
    background_bytes_written: int
    background_num_read_operations: int
    background_num_write_operations: int
    background_number_of_flushes: int
    sru_table: str

    class Config:
        table_name: str = Tables.WIN_SRU_APPLICATION.value


class SRU(ForensicArtifact):
    def __init__(self, src: Source, schema: ArtifactSchema):
        super().__init__(src=src, schema=schema)

    def parse(self, descending: bool = False):
        if self.name == Artifacts.WIN_SRU_NETWORK.value:
            try:
                # network_data = sorted(
                #     (
                #         self.validate_record(index=index, record=record)
                #         for index, record in enumerate(self.network_data())
                #     ),
                #     key=lambda record: record.ts,
                #     reverse=descending,
                # )
                # network_connectivity = sorted(
                #     (
                #         self.validate_record(index=index, record=record)
                #         for index, record in enumerate(self.network_connectivity())
                #     ),
                #     key=lambda record: record.ts,
                #     reverse=descending,
                # )
                network = sorted(
                    (
                        self.validate_record(index=index, record=record)
                        for index, record in enumerate(self.network())
                    ),
                    key=lambda record: record.ts,
                    reverse=descending,
                )
            except Exception as e:
                self.log_error(e)
                # network_data = []
                # network_connectivity = []
                network = []
            finally:
                # self.records.append(network_data)
                # self.records.append(network_connectivity)
                self.records.append(network)

        elif self.name == Artifacts.WIN_SRU_APPLICATION.value:
            try:
                application = sorted(
                    (
                        self.validate_record(index=index, record=record)
                        for index, record in enumerate(self.application())
                    ),
                    key=lambda record: record.ts,  # Sorting based on the 'ts' field
                    reverse=descending,
                )
            except Exception as e:
                self.log_error(e)
                application = []
            finally:
                self.records.append(application)

        # application_timeline = [
        #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
        #     for record in self.application_timeline()
        # ]

        # energy_estimator = [
        #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
        #     for record in self.energy_estimator()
        # ]
        # energy_usage = [
        #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
        #     for record in self.energy_usage()
        # ]
        # energy_usage_lt = [
        #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
        #     for record in self.energy_usage_lt()
        # ]
        # push_notification = [
        #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
        #     for record in self.push_notification()
        # ]
        # vfu = [
        #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
        #     for record in self.vfu()
        # ]
        # sdp_volume_provider = [
        #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
        #     for record in self.sdp_volume_provider()
        # ]
        # sdp_physical_disk_provider = [
        #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
        #     for record in self.sdp_physical_disk_provider()
        # ]
        # sdp_cpu_provider = [
        #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
        #     for record in self.sdp_cpu_provider()
        # ]
        # sdp_network_provider = [
        #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
        #     for record in self.sdp_network_provider()
        # ]

        # self.result = {
        #     "application_timeline": application_timeline,
        #     "energy_estimator": energy_estimator,
        #     "energy_usage": energy_usage,
        #     "energy_usage_lt": energy_usage_lt,
        #     "push_notification": push_notification,
        #     "vfu": vfu,
        #     "sdp_volume_provider": sdp_volume_provider,
        #     "sdp_physical_disk_provider": sdp_physical_disk_provider,
        #     "sdp_cpu_provider": sdp_cpu_provider,
        #     "sdp_network_provider": sdp_network_provider,
        # }

    def _process_records(
        self, record_generator: Generator, record_class: ArtifactRecord
    ) -> Generator:
        """
        Process records based on the specified type and record class.

        Args:
        record_generator (Generator): The generator of the record.
        record_class (ArtifactRecord): The class of the record.

        Yields:
        Generator: Yields instances of the specified record class.
        """
        for record in record_generator:
            processed_record = {
                key: record.get(key) for key in record_class.__annotations__.keys()
            }
            processed_record[
                "evidence_id"
            ] = self.evidence_id  # Set evidence_id for each record

            try:
                yield record_class(**processed_record)
            except ValidationError as e:
                self.log_error(e)
                continue

    def _combined_network(self):
        """
        Combined generator for raw network data and network connectivity.

        network data: the contents of Windows Network Usage Monitor table from the SRUDB.dat file.
        network connectivity: the contents of Windows Network Connectivity Usage Monitor table from the SRUDB.dat file.

        Yields:
        Generator: Yields raw network data and network connectivity records.
        """
        yield from self.read_records("network_data")
        yield from self.read_records("network_connectivity")

    def network(self):
        """
        Return the contents of Windows Network Usage Monitor table from the SRUDB.dat file.
        """
        yield from self._process_records(self._combined_network(), SruNetworkRecord)

    def application(self):
        """
        Return the contents of Application Resource Usage table from the SRUDB.dat file.
        """
        return self._process_records(
            self.read_records("application"), SruApplicationRecord
        )

    # def energy_estimator(self):
    #     """Return the contents of Energy Estimator table from the SRUDB.dat file."""
    #     yield from self.read_records("energy_estimator")

    # def energy_usage(self):
    #     """
    #     Return the contents of Energy Usage Provider table from the SRUDB.dat file.

    #     Gives insight into the energy usage of the system.
    #     """
    #     yield from self.read_records("energy_usage")

    # def energy_usage_lt(self):
    #     """
    #     Return the contents of Energy Usage Provider Long Term table from the SRUDB.dat file.

    #     Gives insight into the energy usage of the system looking over the long term.
    #     """
    #     yield from self.read_records("energy_usage_lt")

    # def push_notification(self):
    #     """
    #     Return the contents of Windows Push Notification Data table from the SRUDB.dat file.

    #     Gives insight into the notification usage of the system.
    #     """
    #     yield from self.read_records("push_notifications")

    # def application_timeline(self):
    #     """Return the contents of App Timeline Provider table from the SRUDB.dat file."""
    #     yield from self.read_records("application_timeline")

    # def vfu(self):
    #     """Return the contents of vfuprov table from the SRUDB.dat file."""
    #     yield from self.read_records("vfu")

    # def sdp_volume_provider(self):
    #     """Return the contents of SDP Volume Provider table from the SRUDB.dat file."""
    #     yield from self.read_records("sdp_volume_provider")

    # def sdp_physical_disk_provider(self):
    #     """Return the contents of SDP Physical Disk Provider table from the SRUDB.dat file."""
    #     yield from self.read_records("sdp_physical_disk_provider")

    # def sdp_cpu_provider(self):
    #     """Return the contents of SDP CPU Provider table from the SRUDB.dat file."""
    #     yield from self.read_records("sdp_cpu_provider")

    # def sdp_network_provider(self):
    #     """Return the contents of SDP Network Provider table from the SRUDB.dat file."""
    #     yield from self.read_records("sdp_network_provider")

    def read_records(self, table_name: str) -> Generator[dict, None, None]:
        for db_file in self.check_empty_entry(self.iter_entry()):
            try:
                db = SRUParser(db_file.open("rb"))

                table = db.get_table(table_name=table_name)
                if not table:
                    raise ValueError(f"Table not found: {table_name}")

                columns = [c.name for c in table.columns]
                if columns[:4] != ["AutoIncId", "TimeStamp", "AppId", "UserId"]:
                    raise ValueError(
                        f"Unexpected table layout in SRU iteration: {table} ({columns[:4]})"
                    )
                columns = columns[1:]

                for entry in db.get_table_entries(table=table):
                    values = (entry[name] for name in columns)
                    column_values = zip(columns, values)

                    record_values = {}
                    for column, value in column_values:
                        new_value = (
                            TRANSFORMS[column](value) if column in TRANSFORMS else value
                        )
                        new_column = FIELD_MAPPINGS.get(column, column)
                        record_values[new_column] = new_value
                        record_values["sru_table"] = table_name

                    yield record_values
            except Exception as e:
                self.log_error(e)
                continue
