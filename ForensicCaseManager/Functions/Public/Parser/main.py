import argparse
from pathlib import Path

from case_manager import CaseManager, ROOT_DIRECTORY_NAME

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--path", default=None, help="path to parse", dest="path")
    parser.add_argument(
        "-l", "--local", action="store_true", help="local to parse", dest="local"
    )
    parser.add_argument(
        "-c", "--container", default=None, help="container to parse", dest="container"
    )
    parser.add_argument(
        "-a", "--artifact", default=None, help="artifact to parse", dest="artifact"
    )
    parser.add_argument(
        "-y", "--category", default=None, help="category to parse", dest="category"
    )
    parser.add_argument(
        "-o", "--out", default=None, help="output directory", dest="out"
    )

    args = parser.parse_args()
    path = args.path
    local = args.local
    container = args.container
    if args.out:
        root_directory = Path(args.out) / ROOT_DIRECTORY_NAME
    else:
        temp_dir = Path.home() / "AppData" / "Local" / "Temp"
        root_directory = temp_dir / ROOT_DIRECTORY_NAME

    if args.artifact:
        artifacts = args.artifact.split(",")
    else:
        artifacts = None

    if args.category:
        categories = args.category.split(",")
    else:
        categories = None

    case = CaseManager(
        _path=path,
        _local=local,
        _container=container,
        _artifacts=artifacts,
        _categories=categories,
        root_directory=root_directory,
    )

    case.parse_all()
    session, case_information = case.export_all()

    if session and case_information:
        print(True)
