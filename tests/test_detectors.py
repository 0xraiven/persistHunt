import unittest
from persisthunt.detectors.base import BaseDetector
from persisthunt.findings import FindingCollection, Finding, Severity

class TestDetectorArchitecture(unittest.TestCase):
    def test_cannot_instantiate_abstract_base_detector(self):
        with self.assertRaises(TypeError):
            BaseDetector()

    def test_custom_detector_subclass(self):
        class DummyDetector(BaseDetector):
            name = "Dummy Persistence Detector"
            detector_id = "dummy"

            def scan(self) -> FindingCollection:
                col = FindingCollection()
                col.add(Finding(
                    id="PH-DUMMY-001",
                    category="dummy",
                    severity=Severity.INFO,
                    title="Dummy finding",
                    description="Dummy description"
                ))
                return col

        detector = DummyDetector()
        self.assertEqual(detector.name, "Dummy Persistence Detector")
        self.assertEqual(detector.detector_id, "dummy")

        findings = detector.scan()
        self.assertIsInstance(findings, FindingCollection)
        self.assertEqual(findings.count(), 1)
        self.assertEqual(list(findings)[0].id, "PH-DUMMY-001")

if __name__ == "__main__":
    unittest.main()
