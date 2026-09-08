import os
import stat
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Union, List
from persisthunt.findings import FindingCollection

MAX_SAFE_FILE_SIZE = 10 * 1024 * 1024  # 10 MB maximum configuration file size


def safe_read_lines(
    file_path: Union[str, Path],
    max_size: int = MAX_SAFE_FILE_SIZE,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> List[str]:
    """Safely read lines from a regular file.

    Guarantees:
    - Protects against hanging on FIFOs, named pipes, and character devices.
    - Prevents memory exhaustion by enforcing max_size.
    - Handles unusual Unicode or binary bytes safely via errors='replace'.
    """
    path = Path(file_path)
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise OSError(f"Non-regular or special file encountered: {file_path}")
    if st.st_size > max_size:
        raise OSError(f"File size ({st.st_size} bytes) exceeds safety limit of {max_size} bytes")

    with open(path, "r", encoding=encoding, errors=errors) as f:
        return f.readlines()


def safe_read_text(
    file_path: Union[str, Path],
    max_size: int = MAX_SAFE_FILE_SIZE,
    encoding: str = "utf-8",
    errors: str = "replace",
) -> str:
    """Safely read text content from a regular file.

    Guarantees:
    - Protects against hanging on FIFOs, named pipes, and character devices.
    - Prevents memory exhaustion by enforcing max_size.
    - Handles unusual Unicode or binary bytes safely via errors='replace'.
    """
    path = Path(file_path)
    st = path.stat()
    if not stat.S_ISREG(st.st_mode):
        raise OSError(f"Non-regular or special file encountered: {file_path}")
    if st.st_size > max_size:
        raise OSError(f"File size ({st.st_size} bytes) exceeds safety limit of {max_size} bytes")

    with open(path, "r", encoding=encoding, errors=errors) as f:
        return f.read()


class BaseDetector(ABC):
    """Abstract base class for all PersistHunt persistence detectors.

    All detectors must implement this interface, exposing their human-readable
    name, unique detector identifier, and a `scan()` method returning a
    FindingCollection.
    """

    name: str = "Base Detector"
    detector_id: str = "base"

    def __init__(self, name: Optional[str] = None, detector_id: Optional[str] = None):
        if name is not None:
            self.name = name
        if detector_id is not None:
            self.detector_id = detector_id

    @abstractmethod
    def scan(self) -> FindingCollection:
        """Perform persistence scan and return a FindingCollection.

        Must perform read-only inspection only. Must never execute inspected
        commands, modify files, or make network connections.
        """
        pass
