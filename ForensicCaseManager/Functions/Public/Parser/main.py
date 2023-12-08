import argparse
import uuid
from pathlib import Path

from case_manager import CaseManager
from forensic_evidence import ForensicEvidence
from config import ROOT_DIRECTORY_NAME

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
        "-a", "--artifact", default=None, help="artifact to parse", dest="artifact"
    )
    parser.add_argument(
        "-y", "--category", default=None, help="category to parse", dest="category"
    )
    parser.add_argument(
        "-o", "--out", default=None, help="output directory", dest="out"
    )

    args = parser.parse_args()
    case_name = args.case_name
    local = args.local
    if args.container:
        containers = args.container.split(",")

    if args.artifact:
        artifacts = args.artifact.split(",")
    else:
        artifacts = None

    if args.category:
        categories = args.category.split(",")
    else:
        categories = None

    if args.out:
        root_directory = Path(args.out) / ROOT_DIRECTORY_NAME
    else:
        root_directory = Path.home() / ROOT_DIRECTORY_NAME

    case = CaseManager(
        case_name=case_name,
        root_directory=root_directory,
        forensic_evidences=[
            ForensicEvidence(
                evidence_number=index,
                _local=local,
                _container=container,
                _artifacts=artifacts,
                _categories=categories,
            )
            for index, container in enumerate(containers)
        ],
    )
    case.investigate_case()
