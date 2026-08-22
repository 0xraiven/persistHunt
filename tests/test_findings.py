import unittest
import json
from persisthunt.findings import Finding, FindingCollection, Severity

class TestFinding(unittest.TestCase):
    def test_valid_finding_creation(self):
        finding = Finding(
            id="PH-TEST-001",
            category="test",
            severity=Severity.HIGH,
            title="Test Title",
            description="Test Description",
            evidence="Test Evidence",
            location="/tmp/test",
            recommendation="Test Recommendation"
        )
        self.assertEqual(finding.id, "PH-TEST-001")
        self.assertEqual(finding.category, "test")
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.title, "Test Title")
        
    def test_optional_fields(self):
        finding = Finding(
            id="PH-TEST-002",
            category="test",
            severity=Severity.LOW,
            title="Test Title",
            description="Test Description"
        )
        self.assertIsNone(finding.evidence)
        self.assertIsNone(finding.location)
        self.assertIsNone(finding.recommendation)
        
    def test_validation_empty_id(self):
        with self.assertRaises(ValueError):
            Finding(
                id="",
                category="test",
                severity=Severity.HIGH,
                title="Title",
                description="Desc"
            )
            
    def test_validation_empty_title(self):
        with self.assertRaises(ValueError):
            Finding(
                id="PH-TEST-003",
                category="test",
                severity=Severity.HIGH,
                title="",
                description="Desc"
            )

    def test_validation_invalid_severity(self):
        with self.assertRaises(ValueError):
            Finding(
                id="PH-TEST-004",
                category="test",
                severity="HIGH_BUT_INVALID",  # Not a Severity enum instance
                title="Title",
                description="Desc"
            )

    def test_serialization_to_dict(self):
        finding = Finding(
            id="PH-TEST-005",
            category="test",
            severity=Severity.CRITICAL,
            title="Test Title",
            description="Test Description",
            evidence={"key": "value"}
        )
        d = finding.to_dict()
        self.assertEqual(d["id"], "PH-TEST-005")
        self.assertEqual(d["severity"], "CRITICAL")
        self.assertEqual(d["evidence"], {"key": "value"})

    def test_json_serialization(self):
        finding = Finding(
            id="PH-TEST-006",
            category="test",
            severity=Severity.MEDIUM,
            title="Test Title",
            description="Test Description",
            evidence="evidence"
        )
        d = finding.to_dict()
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        self.assertEqual(parsed["severity"], "MEDIUM")
        self.assertEqual(parsed["id"], "PH-TEST-006")


class TestFindingCollection(unittest.TestCase):
    def setUp(self):
        self.collection = FindingCollection()
        self.finding1 = Finding("1", "cat1", Severity.INFO, "t1", "d1")
        self.finding2 = Finding("2", "cat2", Severity.LOW, "t2", "d2")
        self.finding3 = Finding("3", "cat1", Severity.LOW, "t3", "d3")
        
    def test_add_and_count(self):
        self.assertEqual(self.collection.count(), 0)
        self.collection.add(self.finding1)
        self.assertEqual(self.collection.count(), 1)
        self.collection.add(self.finding2)
        self.assertEqual(self.collection.count(), 2)
        
    def test_iterate(self):
        self.collection.add(self.finding1)
        self.collection.add(self.finding2)
        findings = list(self.collection)
        self.assertEqual(len(findings), 2)
        self.assertIn(self.finding1, findings)
        
    def test_clear(self):
        self.collection.add(self.finding1)
        self.collection.clear()
        self.assertEqual(self.collection.count(), 0)
        
    def test_filter_by_severity(self):
        self.collection.add(self.finding1)
        self.collection.add(self.finding2)
        self.collection.add(self.finding3)
        lows = self.collection.by_severity(Severity.LOW)
        self.assertEqual(len(lows), 2)
        self.assertIn(self.finding2, lows)
        self.assertIn(self.finding3, lows)
        
    def test_filter_by_category(self):
        self.collection.add(self.finding1)
        self.collection.add(self.finding2)
        self.collection.add(self.finding3)
        cat1s = self.collection.by_category("cat1")
        self.assertEqual(len(cat1s), 2)
        self.assertIn(self.finding1, cat1s)
        self.assertIn(self.finding3, cat1s)
        
    def test_to_dict(self):
        self.collection.add(self.finding1)
        dicts = self.collection.to_dict()
        self.assertEqual(len(dicts), 1)
        self.assertEqual(dicts[0]["id"], "1")
        self.assertEqual(dicts[0]["severity"], "INFO")
        
    def test_severity_counts(self):
        self.collection.add(self.finding1)
        self.collection.add(self.finding2)
        self.collection.add(self.finding3)
        counts = self.collection.severity_counts()
        self.assertEqual(counts["INFO"], 1)
        self.assertEqual(counts["LOW"], 2)
        self.assertEqual(counts["MEDIUM"], 0)
        self.assertEqual(counts["HIGH"], 0)
        self.assertEqual(counts["CRITICAL"], 0)

if __name__ == '__main__':
    unittest.main()
