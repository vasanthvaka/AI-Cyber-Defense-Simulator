import unittest

from agents.analysis_schema import IncidentAnalysis


class TestIncidentAnalysis(unittest.TestCase):

    def create_valid_analysis(self):

        return IncidentAnalysis(
            incident_id="incident-123",
            incident_type="PORT_SCAN",
            risk_score=78,
            confidence=0.9,
            severity="HIGH",
            evidence_count=2,
            detection_methods=[
                "RULE_BASED",
                "ISOLATION_FOREST"
            ],
            key_findings=[
                "Multiple destination ports contacted",
                "AI model detected anomalous behaviour"
            ],
            requires_human_review=False,
            recommended_escalation="RESPOND"
        )

    def test_create_valid_analysis(self):

        analysis = self.create_valid_analysis()

        self.assertEqual(
            analysis.incident_id,
            "incident-123"
        )

        self.assertEqual(
            analysis.risk_score,
            78
        )

        self.assertEqual(
            analysis.analysis_method,
            "DETERMINISTIC"
        )

        self.assertIsNone(
            analysis.llm_enrichment
        )

        self.assertTrue(
            analysis.analysis_id.startswith(
                "analysis-"
            )
        )

    def test_analysis_ids_are_unique(self):

        first_analysis = (
            self.create_valid_analysis()
        )

        second_analysis = (
            self.create_valid_analysis()
        )

        self.assertNotEqual(
            first_analysis.analysis_id,
            second_analysis.analysis_id
        )

    def test_analysis_converts_to_dictionary(self):

        analysis = self.create_valid_analysis()

        analysis_dictionary = (
            analysis.to_dict()
        )

        self.assertEqual(
            analysis_dictionary[
                "incident_type"
            ],
            "PORT_SCAN"
        )

        self.assertEqual(
            analysis_dictionary[
                "detection_methods"
            ],
            [
                "RULE_BASED",
                "ISOLATION_FOREST"
            ]
        )

        self.assertEqual(
            analysis_dictionary[
                "recommended_escalation"
            ],
            "RESPOND"
        )

    def test_invalid_risk_score_is_rejected(self):

        with self.assertRaises(TypeError):
            IncidentAnalysis(
                incident_id="incident-123",
                incident_type="PORT_SCAN",
                risk_score="high",
                confidence=0.9,
                severity="HIGH",
                evidence_count=1,
                detection_methods=[],
                key_findings=[],
                requires_human_review=False,
                recommended_escalation="RESPOND"
            )

        with self.assertRaises(ValueError):
            IncidentAnalysis(
                incident_id="incident-123",
                incident_type="PORT_SCAN",
                risk_score=101,
                confidence=0.9,
                severity="HIGH",
                evidence_count=1,
                detection_methods=[],
                key_findings=[],
                requires_human_review=False,
                recommended_escalation="RESPOND"
            )

    def test_invalid_confidence_is_rejected(self):

        with self.assertRaises(ValueError):
            IncidentAnalysis(
                incident_id="incident-123",
                incident_type="PORT_SCAN",
                risk_score=70,
                confidence=1.5,
                severity="HIGH",
                evidence_count=1,
                detection_methods=[],
                key_findings=[],
                requires_human_review=False,
                recommended_escalation="RESPOND"
            )

    def test_invalid_severity_is_rejected(self):

        with self.assertRaises(ValueError):
            IncidentAnalysis(
                incident_id="incident-123",
                incident_type="PORT_SCAN",
                risk_score=70,
                confidence=0.9,
                severity="EXTREME",
                evidence_count=1,
                detection_methods=[],
                key_findings=[],
                requires_human_review=False,
                recommended_escalation="RESPOND"
            )

    def test_invalid_evidence_count_is_rejected(self):

        with self.assertRaises(ValueError):
            IncidentAnalysis(
                incident_id="incident-123",
                incident_type="PORT_SCAN",
                risk_score=70,
                confidence=0.9,
                severity="HIGH",
                evidence_count=-1,
                detection_methods=[],
                key_findings=[],
                requires_human_review=False,
                recommended_escalation="RESPOND"
            )

    def test_invalid_detection_methods_are_rejected(self):

        with self.assertRaises(TypeError):
            IncidentAnalysis(
                incident_id="incident-123",
                incident_type="PORT_SCAN",
                risk_score=70,
                confidence=0.9,
                severity="HIGH",
                evidence_count=1,
                detection_methods=[
                    123
                ],
                key_findings=[],
                requires_human_review=False,
                recommended_escalation="RESPOND"
            )

    def test_invalid_key_findings_are_rejected(self):

        with self.assertRaises(TypeError):
            IncidentAnalysis(
                incident_id="incident-123",
                incident_type="PORT_SCAN",
                risk_score=70,
                confidence=0.9,
                severity="HIGH",
                evidence_count=1,
                detection_methods=[],
                key_findings=[
                    {
                        "finding": "Port scan"
                    }
                ],
                requires_human_review=False,
                recommended_escalation="RESPOND"
            )

    def test_invalid_human_review_flag_is_rejected(self):

        with self.assertRaises(TypeError):
            IncidentAnalysis(
                incident_id="incident-123",
                incident_type="PORT_SCAN",
                risk_score=70,
                confidence=0.9,
                severity="HIGH",
                evidence_count=1,
                detection_methods=[],
                key_findings=[],
                requires_human_review="no",
                recommended_escalation="RESPOND"
            )

    def test_invalid_escalation_is_rejected(self):

        with self.assertRaises(ValueError):
            IncidentAnalysis(
                incident_id="incident-123",
                incident_type="PORT_SCAN",
                risk_score=70,
                confidence=0.9,
                severity="HIGH",
                evidence_count=1,
                detection_methods=[],
                key_findings=[],
                requires_human_review=False,
                recommended_escalation="DELETE_SYSTEM"
            )

    def test_analysis_method_and_llm_validation(self):

        with self.assertRaises(ValueError):
            IncidentAnalysis(
                incident_id="incident-123",
                incident_type="PORT_SCAN",
                risk_score=70,
                confidence=0.9,
                severity="HIGH",
                evidence_count=1,
                detection_methods=[],
                key_findings=[],
                requires_human_review=False,
                recommended_escalation="RESPOND",
                analysis_method="UNKNOWN"
            )

        with self.assertRaises(TypeError):
            IncidentAnalysis(
                incident_id="incident-123",
                incident_type="PORT_SCAN",
                risk_score=70,
                confidence=0.9,
                severity="HIGH",
                evidence_count=1,
                detection_methods=[],
                key_findings=[],
                requires_human_review=False,
                recommended_escalation="RESPOND",
                llm_enrichment="summary"
            )


if __name__ == "__main__":
    unittest.main()