from pathlib import Path

current_directory = Path(__file__).parent.absolute()

WINDOWS_PATH = current_directory / "windows"
BROWSER_PATH = current_directory / "application" / "browsers"


ARTIFACT_SCHEMA = {
    "Edge": BROWSER_PATH / "edge.yaml",
    "RecycleBin": WINDOWS_PATH / "recyclebin.yaml",
    "Prefetch": WINDOWS_PATH / "prefetch.yaml",
    "WindowsTimeline": WINDOWS_PATH / "windows_timeline.yaml",
    "JumpList": WINDOWS_PATH / "jumplist.yaml",
    "FileHistory": WINDOWS_PATH / "file_history.yaml",
}
