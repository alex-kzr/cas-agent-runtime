"""Static package/resource regressions; no Hatch import or build backend execution."""
import copy
import importlib.util
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cas_static_packaging_check', ROOT / 'tools/check_packaging_resources.py')
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class PackagingResources(unittest.TestCase):
    def setUp(self):
        self.config = tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))

    def test_current_resource_coverage_without_duplicate_destinations(self):
        self.assertFalse(checker.check(ROOT, self.config)['duplicate_destinations'])
        self.assertIn('force-include', self.config['tool']['hatch']['build']['targets']['sdist'])

    def test_historical_failed_configuration_rejected(self):
        old = copy.deepcopy(self.config)
        old['tool']['hatch']['build']['targets']['wheel']['force-include'] = {
            'src/agent_runtime/providers/claude/working_cells/metadata':
            'agent_runtime/providers/claude/working_cells/metadata'
        }
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_WHEEL_DESTINATION:.*metadata/backend.json'):
            checker.check(ROOT, old)

    def test_missing_package_does_not_pass(self):
        broken = copy.deepcopy(self.config)
        broken['tool']['hatch']['build']['targets']['wheel']['packages'] = ['missing-package']
        with self.assertRaisesRegex(ValueError, 'PACKAGE_MISSING'):
            checker.check(ROOT, broken)

    def test_wrong_package_prefix_loses_metadata_and_is_rejected(self):
        broken = copy.deepcopy(self.config)
        broken['tool']['hatch']['build']['targets']['wheel']['packages'] = ['src/agent_runtime/providers/claude']
        with self.assertRaisesRegex(ValueError, 'METADATA_COVERAGE_CHANGED'):
            checker.check(ROOT, broken)

    def test_different_forced_source_same_destination_rejected(self):
        broken = copy.deepcopy(self.config)
        broken['tool']['hatch']['build']['targets']['wheel']['force-include'] = {'README.md': 'agent_runtime/__init__.py'}
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_WHEEL_DESTINATION'):
            checker.check(ROOT, broken)

    def test_escaping_destination_rejected(self):
        broken = copy.deepcopy(self.config)
        broken['tool']['hatch']['build']['targets']['wheel']['force-include'] = {'README.md': '../outside'}
        with self.assertRaisesRegex(ValueError, 'UNSAFE_DESTINATION'):
            checker.check(ROOT, broken)


if __name__ == '__main__':
    unittest.main()
