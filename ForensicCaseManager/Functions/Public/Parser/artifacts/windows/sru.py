import logging
from typing import Generator

from dissect.esedb.tools.sru import SRU as SRUParser
from dissect.target.plugins.os.windows.sru import FIELD_MAPPINGS, TRANSFORMS

from forensic_artifact import Source, ForensicArtifact
from settings.config import (
    ART_SRU_NETWORK,
    ART_SRU_APPLICATION,
)

logger = logging.getLogger(__name__)


class SRU(ForensicArtifact):
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(src=src, artifact=artifact, category=category)

    def parse(self, descending: bool = False):
        if self.artifact == ART_SRU_NETWORK:
            network_data = sorted(
                [
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.network_data())
                ],
                key=lambda record: record["ts"],  # Sorting based on the 'ts' field
                reverse=descending,
            )
            network_connectivity = sorted(
                [
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.network_connectivity())
                ],
                key=lambda record: record["ts"],  # Sorting based on the 'ts' field
                reverse=descending,
            )
        elif self.artifact == ART_SRU_APPLICATION:
            application = sorted(
                [
                    self.validate_record(index=index, record=record)
                    for index, record in enumerate(self.application())
                ],
                key=lambda record: record["ts"],  # Sorting based on the 'ts' field
                reverse=descending,
            )
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

    def network_data(self):
        """
        Return the contents of Windows Network Data Usage Monitor table from the SRUDB.dat file.

        Gives insight into the network usage of the system.

        output data type mapping:
        ("datetime", "ts"),
        ("path", "app"),
        ("string", "user"),
        ("varint", "interface_luid"),
        ("varint", "l2_profile_id"),
        ("varint", "l2_profile_flags"),
        ("varint", "bytes_sent"),
        ("varint", "bytes_recvd"),

        """
        yield from self.read_records("network_data")

    def network_connectivity(self):
        """
        Return the contents of Windows Network Connectivity Usage Monitor table from the SRUDB.dat file.

        Gives insight into the network connectivity usage of the system.

        output data type mapping:
        ("datetime", "ts"),
        ("path", "app"),
        ("string", "user"),
        ("varint", "interface_luid"),
        ("varint", "l2_profile_id"),
        ("varint", "connected_time"),
        ("datetime", "connect_start_time"),
        ("varint", "l2_profile_flags"),
        """
        yield from self.read_records("network_connectivity")

    def energy_estimator(self):
        """Return the contents of Energy Estimator table from the SRUDB.dat file."""
        yield from self.read_records("energy_estimator")

    def energy_usage(self):
        """
        Return the contents of Energy Usage Provider table from the SRUDB.dat file.

        Gives insight into the energy usage of the system.
        """
        yield from self.read_records("energy_usage")

    def energy_usage_lt(self):
        """
        Return the contents of Energy Usage Provider Long Term table from the SRUDB.dat file.

        Gives insight into the energy usage of the system looking over the long term.
        """
        yield from self.read_records("energy_usage_lt")

    def application(self):
        """
        Return the contents of Application Resource Usage table from the SRUDB.dat file.

        Gives insights into the resource usage of applications on the system.

        output data type mapping:
        ("datetime", "ts"),
        ("path", "app"),
        ("string", "user"),
        ("varint", "foreground_cycle_time"),
        ("varint", "background_cycle_time"),
        ("varint", "face_time"),
        ("varint", "foreground_context_switches"),
        ("varint", "background_context_switches"),
        ("varint", "foreground_bytes_read"),
        ("varint", "foreground_bytes_written"),
        ("varint", "foreground_num_read_operations"),
        ("varint", "foreground_num_write_operations"),
        ("varint", "foreground_number_of_flushes"),
        ("varint", "background_bytes_read"),
        ("varint", "background_bytes_written"),
        ("varint", "background_num_read_operations"),
        ("varint", "background_num_write_operations"),
        ("varint", "background_number_of_flushes"),
        """
        yield from self.read_records("application")

    def push_notification(self):
        """
        Return the contents of Windows Push Notification Data table from the SRUDB.dat file.

        Gives insight into the notification usage of the system.
        """
        yield from self.read_records("push_notifications")

    def application_timeline(self):
        """Return the contents of App Timeline Provider table from the SRUDB.dat file."""
        yield from self.read_records("application_timeline")

    def vfu(self):
        """Return the contents of vfuprov table from the SRUDB.dat file."""
        yield from self.read_records("vfu")

    def sdp_volume_provider(self):
        """Return the contents of SDP Volume Provider table from the SRUDB.dat file."""
        yield from self.read_records("sdp_volume_provider")

    def sdp_physical_disk_provider(self):
        """Return the contents of SDP Physical Disk Provider table from the SRUDB.dat file."""
        yield from self.read_records("sdp_physical_disk_provider")

    def sdp_cpu_provider(self):
        """Return the contents of SDP CPU Provider table from the SRUDB.dat file."""
        yield from self.read_records("sdp_cpu_provider")

    def sdp_network_provider(self):
        """Return the contents of SDP Network Provider table from the SRUDB.dat file."""
        yield from self.read_records("sdp_network_provider")

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
                        record_values["evidence_id"] = self.evidence_id

                    yield record_values
            except:
                logger.exception(f"Error: Unable to parse {table_name} from {db_file}")
