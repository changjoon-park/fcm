import argparse
import logging
from pathlib import Path

from forensic_case import ForensicCase
from forensic_evidence import ForensicEvidence
from settings import ROOT_DIRECTORY_NAME


def get_evidence_files(evidence_input):
    evidence_files = []
    for path_str in evidence_input.split(","):
        path = Path(path_str)
        if path.is_dir():
            evidence_files.extend(
                [str(file) for file in path.glob("*.E01")]
            )  # Assuming .E01 as evidence file extension
        elif path.is_file():
            evidence_files.append(str(path))
        else:
            print(f"Warning: Path {path} is neither a valid file nor a directory")
    return evidence_files


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s|%(name)s|%(levelname)s|%(message)s",
        filename="test.log",
        encoding="utf-8",
    )
    logger = logging.getLogger(__name__)
    logger.info("Starting Forensic Case Manager...")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-n", "--case_name", default=None, help="case name", dest="case_name"
    )
    parser.add_argument(
        "-c", "--evidence", default=None, help="evidence to parse", dest="evidence"
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

    # Assigning values to case_name
    case_name = args.case_name

    # Get evidence files from 'evidence' input
    evidences = get_evidence_files(args.evidence) if args.evidence else []

    # Assigning values to artifact
    artifacts = args.artifact.split(",") if args.artifact else None

    # Assigning values to category
    categories = args.category.split(",") if args.category else None

    # Assigning values to root_directory
    if args.out:
        root_directory = Path(args.out) / ROOT_DIRECTORY_NAME
    else:
        root_directory = Path.home() / ROOT_DIRECTORY_NAME

    # Set ForensicEvidence list
    forensic_evidences = [
        ForensicEvidence(
            root_directory=root_directory,
            case_name=case_name,
            _evidence_number=index,
            _evidence=evidence,
            _artifacts=artifacts,
            _categories=categories,
        )
        for index, evidence in enumerate(evidences)
    ]

    # Set ForensicCase instance
    case = ForensicCase(
        root_directory=root_directory,
        case_name=case_name,
        forensic_evidences=forensic_evidences,
    )

    # Investigate case
    case.investigate_case()
