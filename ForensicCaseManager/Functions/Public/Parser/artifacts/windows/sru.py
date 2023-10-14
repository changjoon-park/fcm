import json

from dissect.esedb.tools.sru import SRU as SRUParser
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugins.os.windows.sru import (
    FIELD_MAPPINGS,
    TRANSFORMS,
    NetworkDataRecord,
    NetworkConnectivityRecord,
    EnergyEstimatorRecord,
    EnergyUsageRecord,
    EnergyUsageLTRecord,
    ApplicationRecord,
    ApplicationTimelineRecord,
    PushNotificationRecord,
    VfuRecord,
    SdpVolumeProviderRecord,
    SdpPhysicalDiskProviderRecord,
    SdpCpuProviderRecord,
    SdpNetworkProviderRecord,
)

from forensic_artifact import Source, ForensicArtifact


class SRU(ForensicArtifact):
    
    def __init__(self, src: Source, artifact: str, category: str):
        super().__init__(
            src=src,
            artifact=artifact,
            category=category
        )
        
    def parse(self):
        if self.artifact == "SRU(Network)":
            network_data = [
                json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
                for record in self.network_data()
            ]
            network_connectivity = [
                json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
                for record in self.network_connectivity()
            ]
            self.result = {
                "sru_network_connectivity": network_connectivity,
                "sru_network_data": network_data,
            }
        elif self.artifact == "SRU(App)":
            application = [
                json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
                for record in self.application()
            ]
            # application_timeline = [
            #     json.dumps(record._packdict(), indent=2, default=str, ensure_ascii=False)
            #     for record in self.application_timeline()
            # ]
            self.result = {
                "sru_application": application,
                # "application_timeline": application_timeline,
            }        
            
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
        """
        yield from self.read_records("network_data", NetworkDataRecord)

    def network_connectivity(self):
        """
        Return the contents of Windows Network Connectivity Usage Monitor table from the SRUDB.dat file.

        Gives insight into the network connectivity usage of the system.
        """
        yield from self.read_records("network_connectivity", NetworkConnectivityRecord)

    def energy_estimator(self):
        """Return the contents of Energy Estimator table from the SRUDB.dat file."""
        yield from self.read_records("energy_estimator", EnergyEstimatorRecord)

    def energy_usage(self):
        """
        Return the contents of Energy Usage Provider table from the SRUDB.dat file.

        Gives insight into the energy usage of the system.
        """
        yield from self.read_records("energy_usage", EnergyUsageRecord)

    def energy_usage_lt(self):
        """
        Return the contents of Energy Usage Provider Long Term table from the SRUDB.dat file.

        Gives insight into the energy usage of the system looking over the long term.
        """
        yield from self.read_records("energy_usage_lt", EnergyUsageLTRecord)

    def application(self):
        """
        Return the contents of Application Resource Usage table from the SRUDB.dat file.

        Gives insights into the resource usage of applications on the system.
        """
        yield from self.read_records("application", ApplicationRecord)

    def push_notification(self):
        """
        Return the contents of Windows Push Notification Data table from the SRUDB.dat file.

        Gives insight into the notification usage of the system.
        """
        yield from self.read_records("push_notifications", PushNotificationRecord)

    def application_timeline(self):
        """Return the contents of App Timeline Provider table from the SRUDB.dat file."""
        yield from self.read_records("application_timeline", ApplicationTimelineRecord)

    def vfu(self):
        """Return the contents of vfuprov table from the SRUDB.dat file."""
        yield from self.read_records("vfu", VfuRecord)

    def sdp_volume_provider(self):
        """Return the contents of SDP Volume Provider table from the SRUDB.dat file."""
        yield from self.read_records("sdp_volume_provider", SdpVolumeProviderRecord)

    def sdp_physical_disk_provider(self):
        """Return the contents of SDP Physical Disk Provider table from the SRUDB.dat file."""
        yield from self.read_records("sdp_physical_disk_provider", SdpPhysicalDiskProviderRecord)

    def sdp_cpu_provider(self):
        """Return the contents of SDP CPU Provider table from the SRUDB.dat file."""
        yield from self.read_records("sdp_cpu_provider", SdpCpuProviderRecord)

    def sdp_network_provider(self):
        """Return the contents of SDP Network Provider table from the SRUDB.dat file."""
        yield from self.read_records("sdp_network_provider", SdpNetworkProviderRecord)


    def read_records(self, table_name:str, record_type:TargetRecordDescriptor):
        for db_file in self._iter_entry():
            try:
                db = SRUParser(db_file.open("rb"))

                table = db.get_table(table_name=table_name)
                if not table:
                    raise ValueError(f"Table not found: {table_name}")

                columns = [c.name for c in table.columns]
                if columns[:4] != ["AutoIncId", "TimeStamp", "AppId", "UserId"]:
                    raise ValueError(f"Unexpected table layout in SRU iteration: {table} ({columns[:4]})")
                columns = columns[1:]

                for entry in db.get_table_entries(table=table):
                    values = (entry[name] for name in columns)
                    column_values = zip(columns, values)

                    record_values = {}
                    for column, value in column_values:
                        new_value = TRANSFORMS[column](value) if column in TRANSFORMS else value
                        new_column = FIELD_MAPPINGS.get(column, column)
                        record_values[new_column] = new_value

                    yield record_type(
                        **record_values,
                    )
            except:
                pass