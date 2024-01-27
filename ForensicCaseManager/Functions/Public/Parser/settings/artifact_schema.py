import logging
import yaml
from pathlib import Path
from dataclasses import dataclass, field


logger = logging.getLogger(__name__)

current_directory = Path(__file__).parent.absolute()
schemas = {
    "apps": current_directory / "schemas" / "apps.yaml",
    "filesystem": current_directory / "schemas" / "filesystem.yaml",
    "windows": current_directory / "schemas" / "windows.yaml",
    "eventlog": current_directory / "schemas" / "eventlog.yaml",
    "registry": current_directory / "schemas" / "registry.yaml",
}


# Function to load schema data from multiple files
def load_schemas(schema_paths):
    schema_data = {}
    for name, path in schema_paths.items():
        with open(path, "r") as file:
            schema_data[name] = yaml.safe_load(file).get("Artifacts", {})
    return schema_data


schema_data = load_schemas(schemas)


@dataclass
class ArtifactSchema:
    name: str
    category: str
    root: str = field(default_factory=str)
    owner: str = field(default_factory=str)
    entries: dict[str] = field(default_factory=dict)
    _schema: dict = field(init=False, default_factory=dict)

    def __post_init__(self):
        self._load_schema()

    def _load_schema(self):
        for schema_type, schema in schema_data.items():
            if self.name in schema:
                self._schema = schema[self.name]
                self.root = self._schema.get("root", self.root)
                self.owner = self._schema.get("owner", self.owner)
                self.entries = self._schema.get("entries", self.entries)
                return
        logger.error(f"ArtifactSchema not found for {self.name} in any schema type")
