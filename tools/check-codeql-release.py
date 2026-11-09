#!/usr/bin/env python3
"""Require completed CodeQL evidence for the exact public release commit."""

from contextlib import closing
from datetime import datetime
from http.client import HTTPException, HTTPSConnection
import json
import os
import re
import sys
from urllib.parse import urlencode


MAIN_REF = "refs/heads/main"
WORKFLOW_PATH = ".github/workflows/codeql.yml"
MAX_RESPONSE_BYTES = 1024 * 1024


class GateError(Exception):
    """Release evidence is missing, invalid, or no longer current."""


class GitHub:
    def __init__(self, repository, token):
        self.repository = repository
        self.token = token

    def get(self, endpoint, **query):
        path = f"/repos/{self.repository}/{endpoint}"
        if query:
            path += "?" + urlencode(query)
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "Cache-Control": "no-cache",
            "User-Agent": "codeql-release-gate",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        try:
            # A direct TLS connection never follows redirects or API-supplied URLs.
            with closing(HTTPSConnection("api.github.com", timeout=15)) as connection:
                connection.request("GET", path, headers=headers)
                response = connection.getresponse()
                if response.status != 200:
                    raise GateError(f"GitHub API returned HTTP {response.status} for {endpoint}.")
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise GateError("GitHub API response exceeded the size limit.")
                result = json.loads(body)
                if result == [] and response.getheader("Link"):
                    raise GateError("GitHub API returned an empty page with pagination links.")
                return result
        except (OSError, HTTPException, ValueError, RecursionError):
            raise GateError(f"GitHub API request or response failed for {endpoint}.") from None


def positive_int(value):
    return type(value) is int and value > 0


def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise GateError("GitHub API returned a missing or malformed evidence timestamp.")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise GateError("GitHub API returned an invalid evidence timestamp.") from None


def check_main(get, sha):
    branch = get("branches/main")
    if not isinstance(branch, dict) or branch.get("name") != "main" or branch.get("protected") is not True:
        raise GateError("GitHub did not report main as a protected branch.")
    commit = branch.get("commit")
    if not isinstance(commit, dict) or commit.get("sha") != sha:
        raise GateError("Release commit is no longer the exact protected main tip.")


def latest_run(get, sha):
    response = get("actions/workflows/codeql.yml/runs", branch="main", head_sha=sha, per_page=1)
    runs = response.get("workflow_runs") if isinstance(response, dict) else None
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
        raise GateError("GitHub did not return a latest CodeQL workflow run for the release commit.")
    run = runs[0]
    if (run.get("head_branch") != "main" or run.get("head_sha") != sha
            or run.get("path") != WORKFLOW_PATH or run.get("event") not in ("push", "schedule")
            or not positive_int(run.get("id")) or not positive_int(run.get("run_attempt"))):
        raise GateError("Latest CodeQL workflow run does not match the expected main workflow and commit.")
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        raise GateError("Latest CodeQL workflow run must finish successfully before publication.")
    return run["id"], run["run_attempt"], timestamp(run.get("run_started_at"))


def latest_analysis(get, sha, run_started_at):
    analyses = get("code-scanning/analyses", ref=MAIN_REF, tool_name="CodeQL",
                   sort="created", direction="desc", per_page=1)
    if not isinstance(analyses, list) or len(analyses) != 1 or not isinstance(analyses[0], dict):
        raise GateError("GitHub did not return a latest CodeQL analysis for main.")
    analysis = analyses[0]
    tool = analysis.get("tool")
    if (analysis.get("ref") != MAIN_REF or analysis.get("commit_sha") != sha
            or analysis.get("analysis_key") != f"{WORKFLOW_PATH}:analyze"
            or analysis.get("category") != "/language:csharp"
            or not isinstance(tool, dict) or tool.get("name") != "CodeQL"):
        raise GateError("Latest main CodeQL analysis does not match the release commit and C# configuration.")
    if (analysis.get("error") != "" or analysis.get("warning") != ""
            or not positive_int(analysis.get("id")) or not positive_int(analysis.get("rules_count"))):
        raise GateError("Latest main CodeQL analysis is incomplete or reports an error or warning.")
    if timestamp(analysis.get("created_at")) < run_started_at:
        raise GateError("Latest main CodeQL analysis predates the latest successful workflow attempt.")
    sarif_id = analysis.get("sarif_id")
    if not isinstance(sarif_id, str) or not re.fullmatch(r"[0-9a-fA-F-]{36}", sarif_id):
        raise GateError("Latest main CodeQL analysis has a missing or malformed SARIF ID.")
    upload = get(f"code-scanning/sarifs/{sarif_id}")
    if not isinstance(upload, dict) or upload.get("processing_status") != "complete":
        raise GateError("Latest main CodeQL SARIF upload has not completed successfully.")
    return analysis["id"], sarif_id


def verify(get, sha):
    check_main(get, sha)
    run = latest_run(get, sha)
    analysis = latest_analysis(get, sha, run[2])

    # One result is enough to block, regardless of scanner or severity.
    alerts = get("code-scanning/alerts", ref=MAIN_REF, state="open", per_page=1)
    if not isinstance(alerts, list):
        raise GateError("GitHub returned a malformed code-scanning alerts response.")
    if alerts:
        raise GateError("Main has open code-scanning alerts.")

    # Reject evidence that changed while the branch-wide alert count was read.
    if latest_analysis(get, sha, run[2]) != analysis:
        raise GateError("Main CodeQL analysis changed during the release check.")
    if latest_run(get, sha) != run:
        raise GateError("Main CodeQL workflow attempt changed during the release check.")
    check_main(get, sha)
    return run[0], analysis[0]


def main():
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    sha = os.environ.get("GITHUB_SHA", "")
    token = os.environ.get("GH_TOKEN", "")
    try:
        if not re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9_.-]+", repository) or repository.endswith(("/.", "/..")):
            raise GateError("GITHUB_REPOSITORY must identify the release repository.")
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise GateError("GITHUB_SHA must be the full release commit SHA.")
        if not re.fullmatch(r"[\x21-\x7e]+", token):
            raise GateError("GH_TOKEN is missing or malformed.")
        run_id, analysis_id = verify(GitHub(repository, token).get, sha)
    except GateError as error:
        print(f"CodeQL release gate blocked publication. {error}", file=sys.stderr)
        return 1
    print(f"CodeQL release gate passed for {sha} with workflow run {run_id}, analysis {analysis_id}, and zero open alerts.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
