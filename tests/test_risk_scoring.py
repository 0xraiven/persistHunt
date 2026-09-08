import json
import unittest
from persisthunt.findings import Finding, FindingCollection, Severity
from persisthunt.risk import RiskScorer, RiskReport, calculate_risk

class TestRiskScoring(unittest.TestCase):
    def _create_finding(self, severity: Severity, finding_id: str = "PH-TEST-001") -> Finding:
        return Finding(
            id=finding_id,
            category="test",
            severity=severity,
            title=f"Test {severity.value} finding",
            description="Testing risk scoring engine",
        )

    def test_empty_collection(self):
        collection = FindingCollection()
        scorer = RiskScorer()
        report = scorer.calculate(collection)

        self.assertEqual(report.score, 0.0)
        self.assertEqual(report.max_score, 10.0)
        self.assertEqual(report.finding_count, 0)
        self.assertEqual(report.raw_score, 0.0)
        self.assertIsNone(report.highest_severity)
        self.assertEqual(report.severity_counts["CRITICAL"], 0)
        self.assertEqual(report.severity_counts["HIGH"], 0)
        self.assertEqual(report.severity_counts["MEDIUM"], 0)
        self.assertEqual(report.severity_counts["LOW"], 0)
        self.assertEqual(report.severity_counts["INFO"], 0)

    def test_all_informational_findings(self):
        collection = FindingCollection()
        for i in range(5):
            collection.add(self._create_finding(Severity.INFO, f"PH-INFO-00{i}"))

        report = calculate_risk(collection)
        self.assertEqual(report.score, 0.0)
        self.assertEqual(report.finding_count, 5)
        self.assertEqual(report.raw_score, 0.0)
        self.assertEqual(report.highest_severity, Severity.INFO)
        self.assertEqual(report.severity_counts["INFO"], 5)

    def test_single_finding_each_severity(self):
        scorer = RiskScorer()

        # 1. Single LOW finding (weight 1 -> 1 / 5 = 0.2)
        rep_low = scorer.calculate([self._create_finding(Severity.LOW)])
        self.assertEqual(rep_low.score, 0.2)
        self.assertEqual(rep_low.highest_severity, Severity.LOW)

        # 2. Single MEDIUM finding (weight 3 -> 3 / 5 = 0.6)
        rep_med = scorer.calculate([self._create_finding(Severity.MEDIUM)])
        self.assertEqual(rep_med.score, 0.6)
        self.assertEqual(rep_med.highest_severity, Severity.MEDIUM)

        # 3. Single HIGH finding (weight 6 -> 6 / 5 = 1.2)
        rep_high = scorer.calculate([self._create_finding(Severity.HIGH)])
        self.assertEqual(rep_high.score, 1.2)
        self.assertEqual(rep_high.highest_severity, Severity.HIGH)

        # 4. Single CRITICAL finding (weight 10 -> 10 / 5 = 2.0)
        rep_crit = scorer.calculate([self._create_finding(Severity.CRITICAL)])
        self.assertEqual(rep_crit.score, 2.0)
        self.assertEqual(rep_crit.highest_severity, Severity.CRITICAL)

    def test_multiple_findings_same_severity(self):
        # 3 High findings: 3 * 6 = 18 -> 18 / 5 = 3.6
        findings = [self._create_finding(Severity.HIGH, f"PH-HIGH-{i}") for i in range(3)]
        report = calculate_risk(findings)
        self.assertEqual(report.score, 3.6)
        self.assertEqual(report.raw_score, 18.0)
        self.assertEqual(report.finding_count, 3)

    def test_mixed_severity_matches_prompt_example(self):
        """Validates the exact scenario from user specification:

        Critical: 1
        High: 2
        Medium: 4
        Low: 3
        Info: 1
        -> Risk Score: 7.4/10
        """
        collection = FindingCollection()
        # 1 Critical (10)
        collection.add(self._create_finding(Severity.CRITICAL, "PH-CRIT-001"))
        # 2 High (2 * 6 = 12)
        for i in range(2):
            collection.add(self._create_finding(Severity.HIGH, f"PH-HIGH-{i}"))
        # 4 Medium (4 * 3 = 12)
        for i in range(4):
            collection.add(self._create_finding(Severity.MEDIUM, f"PH-MED-{i}"))
        # 3 Low (3 * 1 = 3)
        for i in range(3):
            collection.add(self._create_finding(Severity.LOW, f"PH-LOW-{i}"))
        # 1 Info (1 * 0 = 0)
        collection.add(self._create_finding(Severity.INFO, "PH-INFO-001"))

        report = calculate_risk(collection)

        # Total raw score = 10 + 12 + 12 + 3 + 0 = 37.0
        self.assertEqual(report.raw_score, 37.0)
        # Normalized score = 37 / 5.0 = 7.4
        self.assertEqual(report.score, 7.4)
        self.assertEqual(report.finding_count, 11)
        self.assertEqual(report.highest_severity, Severity.CRITICAL)
        self.assertEqual(report.severity_counts["CRITICAL"], 1)
        self.assertEqual(report.severity_counts["HIGH"], 2)
        self.assertEqual(report.severity_counts["MEDIUM"], 4)
        self.assertEqual(report.severity_counts["LOW"], 3)
        self.assertEqual(report.severity_counts["INFO"], 1)

        # Check summary() text format exactly matches specification
        expected_summary = (
            "Risk Score: 7.4/10\n\n"
            "Critical: 1\n"
            "High: 2\n"
            "Medium: 4\n"
            "Low: 3\n"
            "Info: 1"
        )
        self.assertEqual(report.summary(), expected_summary)

    def test_all_critical_reaches_score_ceiling(self):
        # 5 Criticals = 50.0 points -> 50 / 5 = 10.0
        findings_5 = [self._create_finding(Severity.CRITICAL, f"PH-C-{i}") for i in range(5)]
        report_5 = calculate_risk(findings_5)
        self.assertEqual(report_5.score, 10.0)

        # 10 Criticals = 100.0 points -> capped at 10.0
        findings_10 = [self._create_finding(Severity.CRITICAL, f"PH-C-{i}") for i in range(10)]
        report_10 = calculate_risk(findings_10)
        self.assertEqual(report_10.score, 10.0)
        self.assertEqual(report_10.raw_score, 100.0)

    def test_deterministic_scoring(self):
        findings = [
            self._create_finding(Severity.CRITICAL, "C1"),
            self._create_finding(Severity.HIGH, "H1"),
            self._create_finding(Severity.MEDIUM, "M1"),
            self._create_finding(Severity.LOW, "L1"),
        ]
        scorer = RiskScorer()
        baseline_score = scorer.calculate(findings).score

        for _ in range(200):
            self.assertEqual(scorer.calculate(findings).score, baseline_score)

    def test_explainability_output(self):
        findings = [
            self._create_finding(Severity.HIGH, "H1"),
            self._create_finding(Severity.MEDIUM, "M1"),
        ]
        report = calculate_risk(findings)
        explanation = report.explain()

        self.assertIn("=== Risk Score Explanation ===", explanation)
        self.assertIn("Overall Risk Score:", explanation)
        self.assertIn("HIGH", explanation)
        self.assertIn("MEDIUM", explanation)
        self.assertIn("Top Contributing Findings:", explanation)
        self.assertIn("H1", explanation)
        self.assertIn("M1", explanation)

    def test_json_serialization(self):
        findings = [self._create_finding(Severity.CRITICAL, "PH-C-1")]
        report = calculate_risk(findings)
        d = report.to_dict()

        self.assertEqual(d["score"], 2.0)
        self.assertEqual(d["highest_severity"], "CRITICAL")
        self.assertIn("breakdown", d)
        self.assertIn("contributing_findings", d)

        # Verify it serializes cleanly to valid JSON string
        json_str = json.dumps(d)
        self.assertIn('"score": 2.0', json_str)

    def test_custom_weights_and_limits(self):
        custom_weights = {
            Severity.INFO: 0.0,
            Severity.LOW: 2.0,
            Severity.MEDIUM: 5.0,
            Severity.HIGH: 10.0,
            Severity.CRITICAL: 20.0,
        }
        scorer = RiskScorer(weights=custom_weights, max_raw_score=100.0, max_score=100.0)
        findings = [self._create_finding(Severity.CRITICAL)]
        report = scorer.calculate(findings)

        # 1 Critical = 20.0, divisor = 100 / 100 = 1.0 -> 20.0 / 100
        self.assertEqual(report.score, 20.0)
        self.assertEqual(report.max_score, 100.0)

    def test_invalid_parameters_raise_value_error(self):
        with self.assertRaises(ValueError):
            RiskScorer(max_raw_score=-1)
        with self.assertRaises(ValueError):
            RiskScorer(max_score=0)

if __name__ == "__main__":
    unittest.main()
