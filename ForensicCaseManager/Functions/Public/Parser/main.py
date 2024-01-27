import os
import argparse
import logging
import uuid
from pathlib import Path

from core.forensic_case import ForensicCase
from core.forensic_evidence import ForensicEvidence
from settings.config import LOGFILE_NAME


def handle_case(
    case_directory: Path,
    evidences: list[str],
    artifacts: list[str],
    categories: list[int],
):
    log_file = Path(case_directory) / LOGFILE_NAME

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s|%(name)s|%(levelname)s|%(message)s",
        filename=log_file,
        encoding="utf-8",
    )

    logger = logging.getLogger(__name__)
    logger.info("Starting Forensic Case Manager...")

    session_id = str(uuid.uuid4())

    # Set ForensicEvidence list
    forensic_evidences = [
        ForensicEvidence(
            session_id=session_id,
            case_directory=case_directory,
            _evidence_number=index,
            _evidence=evidence,
            _artifacts=artifacts,
            _categories=categories,
        )
        for index, evidence in enumerate(evidences)
    ]

    # Set ForensicCase instance
    case = ForensicCase(
        session_id=session_id,
        case_directory=case_directory,
        forensic_evidences=forensic_evidences,
    )

    # Investigate case
    case.investigate_case()


def is_directory(string):
    if os.path.isdir(string):
        return string
    else:
        raise argparse.ArgumentTypeError(f"{string} is not a valid directory")


def get_evidence_files(case_directory: Path) -> list[str]:
    evidence_files = []
    path = case_directory / "evidences"  # Look in 'evidences' subdirectory
    if path.is_dir():
        evidence_files.extend(
            [str(file) for file in path.glob("*.E01")]
        )  # Assuming .E01 as evidence file extension
    else:
        print(f"Warning: Path {path} is not a valid directory")
    return evidence_files


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # forensic case directory
    parser.add_argument(
        "-c",
        "--case_directory",
        default=None,
        help="forensic case directory",
        dest="case_directory",
        type=is_directory,  # Use the custom function to validate the input
    )

    # Creating a mutually exclusive group: 'artifact' and 'category'
    artifact_group = parser.add_mutually_exclusive_group()

    # 'artifact' and 'category' are mutually exclusive
    artifact_group.add_argument(
        "-a",
        "--artifact",
        default=None,
        help="forensic artifact to parse",
        dest="artifact",
    )
    artifact_group.add_argument(
        "-t",
        "--category",
        default=None,
        help="forensic category to parse",
        dest="category",
    )

    args = parser.parse_args()

    # Assigning values to case_name
    case_directory = Path(args.case_directory)

    # Get evidence files from 'case_directory' input
    evidences = get_evidence_files(case_directory=case_directory)

    # Listing values to artifact
    artifacts = args.artifact.split(",") if args.artifact else None

    # Listing values to category
    categories = args.category.split(",") if args.category else None

    handle_case(case_directory, evidences, artifacts, categories)
