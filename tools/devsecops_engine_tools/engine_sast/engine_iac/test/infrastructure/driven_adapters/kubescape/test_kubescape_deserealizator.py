import unittest
from devsecops_engine_tools.engine_core.src.domain.model.finding import (
    Category,
    Finding,
)
from devsecops_engine_tools.engine_sast.engine_iac.src.infrastructure.driven_adapters.kubescape.kubescape_deserealizator import (
    KubescapeDeserealizator
)
from datetime import datetime


class TestKubescapeDeserealizator(unittest.TestCase):

    def setUp(self):
        self.deserealizator = KubescapeDeserealizator()

    def test_get_list_finding_empty_list(self):
        results_scan_list = []
        expected_list = []

        actual_list = self.deserealizator.get_list_finding(results_scan_list)

        self.assertEqual(actual_list, expected_list)

    def test_get_list_finding_single_finding(self):
        results_scan_list = [
            {
                "id": "1",
                "where": "/some/path",
                "description": "Test finding",
                "severity": "High"
            }
        ]
        expected_list = [
            Finding(
                id="1",
                cvss=None,
                where="/some/path",
                description="Test finding",
                severity="high",
                identification_date=datetime.now().strftime("%d%m%Y"),
                published_date_cve=None,
                module="engine_iac",
                category=Category.VULNERABILITY,
                requirements=None,
                tool="kubescape"
            )
        ]

        actual_list = self.deserealizator.get_list_finding(results_scan_list)

        self.assertEqual(len(actual_list), 1)
        self.assertEqual(actual_list[0], expected_list[0])
