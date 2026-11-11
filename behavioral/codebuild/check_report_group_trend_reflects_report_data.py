"""report-group-trend-reflects-report-data."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "report-group-trend-reflects-report-data"
GROUP = "data-plane"
SERVICES = ["codebuild"]

_SCENARIO = "report-group-trend-reflects-report-data"

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_ROLE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "codebuild:CreateReport",
                    "codebuild:UpdateReport",
                    "codebuild:BatchPutTestCases",
                    "codebuild:BatchPutCodeCoverages",
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "*",
            }
        ],
    }
)

_BUILDSPEC_TMPL = """version: 0.2
phases:
  build:
    commands:
      - mkdir -p reports
      - printf '<testsuite tests="1" failures="0"><testcase classname="t" name="pass1" time="0.01"/></testsuite>' > reports/results.xml
reports:
  {report_group_arn}:
    files:
      - reports/results.xml
    file-format: JUNITXML
"""


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetReportGroupTrend's PASS_RATE trend for a report group is derived from the
    reports actually listed for that group (a build that generates one all-passing
    JUnit report yields a 100% pass-rate trend covering exactly that report)."""
    codebuild = ctx.client("codebuild")

    role_arn = _create_codebuild_role(ctx)
    report_group_name = ctx.unique_name("sim2real-behav-rg-")
    report_group = codebuild.create_report_group(
        name=report_group_name,
        type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
        tags=[{"key": "sim2real", "value": _SCENARIO}],
    )["reportGroup"]
    report_group_arn = report_group["arn"]
    ctx.on_cleanup(lambda: codebuild.delete_report_group(arn=report_group_arn, deleteReports=True))

    project_name = ctx.unique_name("sim2real-behav-proj-")
    _create_minimal_project(ctx, project_name, role_arn)

    buildspec = _BUILDSPEC_TMPL.format(report_group_arn=report_group_arn)
    build_id = _start_build_with_retry(ctx, project_name, buildspec)
    build = _wait_for_build_terminal(ctx, build_id, timeout_s=900)
    assert build["buildStatus"] == "SUCCEEDED", f"build did not succeed: {build}"

    reports = _poll_until(
        lambda: codebuild.list_reports_for_report_group(reportGroupArn=report_group_arn)["reports"],
        lambda reports: len(reports) >= 1,
        timeout_s=120,
        interval_s=3,
    )
    assert len(reports) == 1, f"expected exactly 1 report, got {reports}"
    report_arn = reports[0]

    trend = codebuild.get_report_group_trend(reportGroupArn=report_group_arn, trendField="PASS_RATE")
    raw_data = trend["rawData"]
    assert len(raw_data) == 1, f"expected trend rawData for exactly 1 report, got {raw_data}"
    assert raw_data[0]["reportArn"] == report_arn, (
        f"trend rawData references {raw_data[0]['reportArn']!r}, "
        f"but ListReportsForReportGroup returned {report_arn!r}"
    )
    assert float(raw_data[0]["data"]) == 100.0, f"expected 100% pass rate, got {raw_data[0]['data']!r}"
    assert float(trend["stats"]["average"]) == 100.0, (
        f"expected trend stats.average of 100.0, got {trend['stats']['average']!r}"
    )


def _create_codebuild_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cb-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline-report-perms", PolicyDocument=_ROLE_POLICY
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline-report-perms"))
    return role["Arn"]


def _retry_role_propagation(call, *, timeout_s: float = 120.0):
    """Retry `call` through IAM role-trust propagation: CodeBuild rejects both CreateProject
    and StartBuild against a just-created service role with InvalidInputException naming the
    role as not assumable, until the role/policy become visible to its AssumeRole check. Any
    other error is not that condition and is raised immediately rather than masked."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return call()
        except ClientError as err:
            error = err.response.get("Error", {})
            msg = (error.get("Message") or "").lower()
            transient_role = error.get("Code") == "InvalidInputException" and (
                "not authorized to perform" in msg or "assume" in msg
            )
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _create_minimal_project(ctx: Any, project_name: str, role_arn: str) -> None:
    codebuild = ctx.client("codebuild")
    _retry_role_propagation(lambda: codebuild.create_project(
        name=project_name,
        source={"type": "NO_SOURCE", "buildspec": "version: 0.2\nphases:\n  build:\n    commands: []\n"},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        logsConfig={"cloudWatchLogs": {"status": "ENABLED"}, "s3Logs": {"status": "DISABLED"}},
        tags=[{"key": "sim2real", "value": _SCENARIO}],
    ))
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))


def _start_build_with_retry(ctx: Any, project_name: str, buildspec: str, timeout_s: float = 120.0) -> str:
    codebuild = ctx.client("codebuild")
    resp = _retry_role_propagation(
        lambda: codebuild.start_build(projectName=project_name, buildspecOverride=buildspec),
        timeout_s=timeout_s,
    )
    return resp["build"]["id"]


def _wait_for_build_terminal(ctx: Any, build_id: str, timeout_s: float = 900.0) -> dict:
    codebuild = ctx.client("codebuild")
    deadline = time.monotonic() + timeout_s
    build = None
    while time.monotonic() < deadline:
        build = codebuild.batch_get_builds(ids=[build_id])["builds"][0]
        if build["buildComplete"]:
            return build
        time.sleep(5)
    raise AssertionError(f"build {build_id} did not reach a terminal state in {timeout_s}s: {build}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s; last result={result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
