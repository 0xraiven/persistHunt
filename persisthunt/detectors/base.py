from abc import ABC, abstractmethod
from typing import Optional
from persisthunt.findings import FindingCollection

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
