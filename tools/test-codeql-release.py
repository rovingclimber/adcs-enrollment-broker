#!/usr/bin/env python3
"""Mock GitHub responses to exercise the public CodeQL release gate."""

from copy import deepcopy
from importlib.util import module_from_spec, spec_from_file_location
from io import StringIO
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, call, patch
from uuid import UUID


# Tests also run against the immutable export before it is archived.
sys.dont_write_bytecode = True
spec = spec_from_file_location("codeql_release", Path(__file__).with_name("check-codeql-release.py"))
gate = module_from_spec(spec)
spec.loader.exec_module(gate)

SHA = "a" * 40
OLD_SHA = "b" * 40
SARIF_ID = str(UUID(int=1))
BRANCH = {"name": "main", "protected": True, "commit": {"sha": SHA}}
RUN = {
    "id": 123,
    "run_attempt": 1,
    "run_started_at": "1970-01-01T10:00:00Z",
    "head_sha": SHA,
    "head_branch": "main",
    "path": ".github/workflows/codeql.yml",
    "event": "push",
    "status": "completed",
    "conclusion": "success",
}
ANALYSIS = {
    "id": 456,
    "sarif_id": SARIF_ID,
    "created_at": "1970-01-01T10:02:00Z",
    "commit_sha": SHA,
    "ref": "refs/heads/main",
    "analysis_key": ".github/workflows/codeql.yml:analyze",
    "category": "/language:csharp",
    "tool": {"name": "CodeQL"},
    "error": "",
    "warning": "",
    "rules_count": 100,
}
UPLOAD = {"processing_status": "complete"}
RUN_RESPONSE = {"total_count": 1, "workflow_runs": [RUN]}
SNAPSHOT = [BRANCH, RUN_RESPONSE, [ANALYSIS], UPLOAD, [], [ANALYSIS], UPLOAD, RUN_RESPONSE, BRANCH]


class GateTests(unittest.TestCase):
    def test_clean_exact_commit_passes(self):
        get = Mock(side_effect=SNAPSHOT)
        self.assertEqual(gate.verify(get, SHA), (123, 456))
        branch_call = call("branches/main")
        run_call = call("actions/workflows/codeql.yml/runs", branch="main", head_sha=SHA, per_page=1)
        analysis_call = call("code-scanning/analyses", ref="refs/heads/main", tool_name="CodeQL",
                             sort="created", direction="desc", per_page=1)
        upload_call = call(f"code-scanning/sarifs/{SARIF_ID}")
        self.assertEqual(get.call_args_list, [
            branch_call, run_call, analysis_call, upload_call,
            call("code-scanning/alerts", ref="refs/heads/main", state="open", per_page=1),
            analysis_call, upload_call, run_call, branch_call,
        ])

    def test_successful_scheduled_run_passes(self):
        snapshot = deepcopy(SNAPSHOT)
        snapshot[1]["workflow_runs"][0]["event"] = "schedule"
        self.assertEqual(gate.verify(Mock(side_effect=snapshot), SHA), (123, 456))

    def test_missing_stale_or_unsuccessful_evidence_blocks(self):
        cases = [
            (0, {**BRANCH, "protected": False}, "protected branch"),
            (0, {**BRANCH, "commit": {"sha": OLD_SHA}}, "exact protected main tip"),
            (1, {"workflow_runs": []}, "did not return a latest CodeQL workflow run"),
            (1, {"workflow_runs": [{**RUN, "head_sha": OLD_SHA}]}, "expected main workflow and commit"),
            (1, {"workflow_runs": [{**RUN, "event": "pull_request"}]}, "expected main workflow and commit"),
            (1, {"workflow_runs": [{**RUN, "status": "in_progress", "conclusion": None}]}, "finish successfully"),
            (1, {"workflow_runs": [{**RUN, "conclusion": "failure"}]}, "finish successfully"),
            (1, {"workflow_runs": [{**RUN, "run_attempt": True}]}, "expected main workflow and commit"),
            (2, [], "did not return a latest CodeQL analysis"),
            (2, [{**ANALYSIS, "commit_sha": OLD_SHA}], "release commit and C# configuration"),
            (2, [{**ANALYSIS, "category": "/language:javascript"}], "release commit and C# configuration"),
            (2, [{**ANALYSIS, "error": "analysis failed"}], "incomplete or reports an error"),
            (2, [{**ANALYSIS, "rules_count": 0}], "incomplete or reports an error"),
            (2, [{**ANALYSIS, "created_at": "1970-01-01T09:58:00Z"}], "predates the latest"),
            (2, [{**ANALYSIS, "sarif_id": "//example.org"}], "malformed SARIF ID"),
            (3, {"processing_status": "pending"}, "has not completed successfully"),
            (3, {"processing_status": "failed"}, "has not completed successfully"),
            (4, [{"number": 18}], "open code-scanning alerts"),
            (4, {}, "malformed code-scanning alerts response"),
        ]
        for index, result, message in cases:
            with self.subTest(message=message, result=result):
                snapshot = list(SNAPSHOT)
                snapshot[index] = result
                get = Mock(side_effect=snapshot)
                with self.assertRaisesRegex(gate.GateError, message):
                    gate.verify(get, SHA)
                self.assertEqual(get.call_count, index + 1)

    def test_concurrent_changes_block(self):
        cases = [
            (5, [{**ANALYSIS, "id": 457}], "analysis changed"),
            (7, {"workflow_runs": [{**RUN, "run_attempt": 2}]}, "workflow attempt changed"),
            (8, {**BRANCH, "commit": {"sha": OLD_SHA}}, "exact protected main tip"),
            (8, {**BRANCH, "protected": False}, "protected branch"),
        ]
        for index, result, message in cases:
            with self.subTest(message=message):
                snapshot = list(SNAPSHOT)
                snapshot[index] = result
                with self.assertRaisesRegex(gate.GateError, message):
                    gate.verify(Mock(side_effect=snapshot), SHA)

    def test_missing_environment_fails_before_any_api_call(self):
        with patch.dict(gate.os.environ, {"GITHUB_REPOSITORY": "owner/repo", "GITHUB_SHA": SHA}, clear=True), \
                patch.object(gate, "HTTPSConnection") as https, patch.object(gate.sys, "stderr", StringIO()) as stderr:
            self.assertEqual(gate.main(), 1)
            self.assertIn("GH_TOKEN is missing", stderr.getvalue())
            https.assert_not_called()


class ApiTests(unittest.TestCase):
    def test_http_errors_and_redirects_fail_without_reading_the_body(self):
        client = gate.GitHub("owner/repo", "fixture-token")
        for status in (302, 401, 403, 404, 429, 503):
            with self.subTest(status=status), patch.object(gate, "HTTPSConnection") as https:
                connection = https.return_value
                response = connection.getresponse.return_value
                response.status = status
                response.getheader.return_value = "https://unexpected.example/"
                with self.assertRaisesRegex(gate.GateError, f"HTTP {status}") as failure:
                    client.get("code-scanning/alerts", ref="refs/heads/main", state="open", per_page=1)
                self.assertNotIn("fixture-token", str(failure.exception))
                https.assert_called_once_with("api.github.com", timeout=15)
                connection.request.assert_called_once()
                response.read.assert_not_called()

    def test_invalid_json_and_pagination_are_rejected(self):
        with patch.object(gate, "HTTPSConnection") as https:
            response = https.return_value.getresponse.return_value
            response.status = 200
            response.read.return_value = b"malformed raw body"
            client = gate.GitHub("owner/repo", "fixture-token")
            with self.assertRaisesRegex(gate.GateError, "request or response failed") as failure:
                client.get("code-scanning/alerts")
            self.assertNotIn("malformed raw body", str(failure.exception))
            response.read.return_value = b"[]"
            response.getheader.return_value = '<https://api.github.com/example>; rel="next"'
            with self.assertRaisesRegex(gate.GateError, "empty page with pagination links"):
                client.get("code-scanning/alerts")


if __name__ == "__main__":
    unittest.main()
