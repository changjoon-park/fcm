import argparse
import logging
from pathlib import Path

from case_manager import CaseManager
from forensic_base import ForensicBase
from forensic_evidence import ForensicEvidence
from database_manager import DatabaseManager

ROOT_DIRECTORY_NAME = "_fcm"


def get_container_files(container_input):
    container_files = []
    for path_str in container_input.split(","):
        path = Path(path_str)
        if path.is_dir():
            container_files.extend(
                [str(file) for file in path.glob("*.E01")]
            )  # Assuming .E01 as container file extension
        elif path.is_file():
            container_files.append(str(path))
        else:
            print(f"Warning: Path {path} is neither a valid file nor a directory")
    return container_files


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-n", "--case_name", default=None, help="case name", dest="case_name"
    )
    parser.add_argument(
        "-l", "--local", action="store_true", help="local to parse", dest="local"
    )
    parser.add_argument(
        "-c", "--container", default=None, help="container to parse", dest="container"
    )
    parser.add_argument(
        "-o", "--out", default=None, help="output directory", dest="out"
    )

    # Creating a mutually exclusive group
    group = parser.add_mutually_exclusive_group()

    # 'artifact' and 'category' are mutually exclusive
    group.add_argument(
        "-a", "--artifact", default=None, help="artifact to parse", dest="artifact"
    )
    group.add_argument(
        "-y", "--category", default=None, help="category to parse", dest="category"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s|%(name)s|%(levelname)s|%(message)s",
        filename="test.log",
        encoding="utf-8",
    )

    # Assigning values to case_name
    case_name = args.case_name

    # Assigning values to local
    local = args.local

    # Get container files from 'container' input
    containers = get_container_files(args.container) if args.container else []

    # Assigning values to artifact
    artifacts = args.artifact.split(",") if args.artifact else None

    # Assigning values to category
    categories = args.category.split(",") if args.category else None

    # Assigning values to root_directory
    if args.out:
        root_directory = Path(args.out) / ROOT_DIRECTORY_NAME
    else:
        root_directory = Path.home() / ROOT_DIRECTORY_NAME

    # Set ForensicEvidence
    forensic_evidences = [
        ForensicEvidence(
            root_directory=root_directory,
            case_name=case_name,
            evidence_number=index,
            _local=local,
            _container=container,
            _artifacts=artifacts,
            _categories=categories,
        )
        for index, container in enumerate(containers)
    ]

    # Set CaseManager
    case = CaseManager(
        root_directory=root_directory,
        case_name=case_name,
        forensic_evidences=forensic_evidences,
    )
    case.investigate_case()
