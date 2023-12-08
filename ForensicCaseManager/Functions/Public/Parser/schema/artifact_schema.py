from pathlib import Path

current_directory = Path(__file__).parent.absolute()

ARTIFACT_SCHEMA = {
    "Edge": current_directory / "application" / "browsers" / "edge.yaml",
    "RecycleBin": current_directory / "windows" / "recyclebin.yaml",
    "Prefetch": current_directory / "windows" / "prefetch.yaml",
    "WindowsTimeline": current_directory / "windows" / "windows_timeline.yaml",
}
