import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from src.evaluation import run_evaluation, write_results


class EvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_evaluation()
        cls.scenarios = {r['scenario']: r for r in cls.report['scenarios']}

    def observed(self, name):
        return self.scenarios[name]['observed']

    def test_all_scenarios_meet_actual_checks(self):
        self.assertEqual(self.report['scenarios_passed'], 7)
        self.assertEqual(self.report['scenarios_total'], 7)
        self.assertTrue(self.report['overall_passed'])
        for scenario in self.report['scenarios']:
            self.assertEqual(scenario['passed'], all(scenario['checks'].values()))

    def test_normal_is_unreachable_with_no_response(self):
        result = self.observed('Normal activity')
        self.assertFalse(result['protected_asset_reachable'])
        self.assertEqual(result['viable_paths_before'], 0)
        self.assertFalse(result['disruptive_containment_recommended'])
        self.assertEqual(result['recommended_action_ids'], [])
        self.assertEqual(result['actions_applied'], [])

    def test_positive_path_and_evidence(self):
        result = self.observed('Active compromise')
        self.assertEqual(result['viable_paths_before'], 2)
        self.assertTrue(result['protected_asset_reachable'])
        self.assertGreater(result['evidence_count'], 0)
        self.assertEqual(result['operational_cost'], 3)
        self.assertEqual(result['viable_paths_after'], 0)

    def test_suspicion_alone_does_not_trigger_containment(self):
        result = self.observed('Suspicious but non-reachable')
        self.assertGreater(result['evidence_count'], 0)
        self.assertFalse(result['protected_asset_reachable'])
        self.assertFalse(result['disruptive_containment_recommended'])
        self.assertEqual(result['actions_applied'], [])

    def test_missing_telemetry_is_handled_and_lowers_confidence(self):
        result = self.observed('Missing telemetry')
        self.assertNotIn('error', result)
        self.assertTrue(result['telemetry_incomplete'])
        self.assertLess(result['confidence'], result['full_confidence'])
        self.assertLess(result['evidence_coverage'], result['full_evidence_coverage'])
        self.assertEqual(result['viable_paths_before'], 2)
        self.assertEqual(result['viable_paths_after'], 2)

    def test_partial_containment_retains_backup_route(self):
        result = self.observed('Partial containment')
        self.assertEqual(result['viable_paths_after'], 1)
        self.assertEqual(result['containment_status'], 'INCOMPLETE')
        self.assertEqual(result['actions_applied'], ['revoke-deploy'])
        self.assertIn('backup-service', result['remaining_paths'][0])

    def test_success_requires_approval_and_leaves_no_paths(self):
        result = self.observed('Recommended containment')
        checks = self.scenarios['Recommended containment']['checks']
        self.assertTrue(result['analyst_approval_required'])
        self.assertTrue(checks['approval_enforced'])
        self.assertTrue(checks['explicit_matching_approval'])
        self.assertEqual(result['viable_paths_after'], 0)
        self.assertEqual(result['containment_status'], 'VERIFIED')
        self.assertEqual(set(result['actions_applied']), {'revoke-backup', 'revoke-deploy'})

    def test_all_graphs_and_assets_preserved(self):
        for scenario in self.report['scenarios']:
            self.assertTrue(scenario['observed']['protected_asset_preserved'])
            self.assertTrue(scenario['observed']['original_graph_unchanged'])

    def test_complete_alternatives_cost_more(self):
        result = self.observed('High-impact alternatives')
        self.assertEqual([a['operational_cost'] for a in result['alternatives']], [5, 8, 20])
        for alternative in result['alternatives']:
            self.assertTrue(alternative['containment_complete'])
            self.assertLess(result['operational_cost'], alternative['operational_cost'])
            self.assertEqual(alternative['cost_reduction'], alternative['operational_cost'] - result['operational_cost'])

    def test_evaluation_is_deterministic(self):
        self.assertEqual(self.report, run_evaluation())

    def test_json_matches_actual_results(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / 'evaluation_results.json'
            write_results(self.report, path)
            self.assertEqual(json.loads(path.read_text()), self.report)
            self.assertEqual(json.loads(path.read_text())['scenarios'][4]['observed']['viable_paths_after'], 1)

    def test_execution_failure_is_reported_not_hidden(self):
        with patch('src.evaluation.ContainmentWorkflow.execute', side_effect=RuntimeError('injected failure')):
            result = run_evaluation()
        self.assertFalse(result['overall_passed'])
        self.assertLess(result['scenarios_passed'], result['scenarios_total'])
        self.assertIn('injected failure', result['scenarios'][0]['observed']['error'])


if __name__ == '__main__':
    unittest.main()
