import contextlib
import io
import sys
import types
import unittest

from src.remediation.runner import FLOW_MODULES, run_flow


class TestRemediationRunner(unittest.TestCase):
    def test_flow_map_contains_expected_modules(self):
        self.assertIn("openstack-runtime", FLOW_MODULES)
        self.assertIn("aws-runtime", FLOW_MODULES)
        self.assertIn("iac-pr", FLOW_MODULES)
        self.assertIn("drift-reconcile", FLOW_MODULES)

    def test_run_flow_with_dummy_module(self):
        module_name = "tests.dummy_remediation_module"
        dummy_module = types.ModuleType(module_name)

        def main():
            print("dummy remediation executed")
            return 0

        dummy_module.main = main
        sys.modules[module_name] = dummy_module
        try:
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                exit_code = run_flow(module_name, ["--help"])
            self.assertEqual(exit_code, 0)
            self.assertIn("dummy remediation executed", output.getvalue())
        finally:
            del sys.modules[module_name]
