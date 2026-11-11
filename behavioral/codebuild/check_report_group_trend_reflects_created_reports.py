"""report-group-trend-reflects-created-reports."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "report-group-trend-reflects-created-reports"
GROUP = "data-plane"
SERVICES = ["codebuild"]

_BUILD_TIMEOUT_S = 900.0
_BUILD_POLL_S = 15.0
_REPORT_TIMEOUT_S = 180.0
_REPORT_POLL_S = 5.0
_ROLE_RETRY_TIMEOUT_S = 90.0
_ROLE_RETRY_INTERVAL_S = 5.0


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After one build emits a single passing JUnit report into a fresh report group,
    GetReportGroupTrend PASS_RATE raw data and stats reflect exactly that one report."""
    codebuild = ctx.client("codebuild")
    iam = ctx.client("iam")

    report_group_name = ctx.unique_name("sim2real-behav-trend-rg-")
    report_group = codebuild.create_report_group(
        name=report_group_name,
        type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
        tags=[{"key": "sim2real", "value": CHECK}],
    )["reportGroup"]
    rg_arn = report_group["arn"]
    ctx.on_cleanup(lambda: codebuild.delete_report_group(arn=rg_arn, deleteReports=True))

    role_arn = _create_build_role(ctx, iam)

    project_name = ctx.unique_name("sim2real-behav-trend-proj-")
    buildspec = _junit_buildspec(rg_arn)
    project = _create_project_with_role_retry(
        ctx,
        codebuild,
        name=project_name,
        role_arn=role_arn,
        buildspec=buildspec,
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project["name"]))

    build = codebuild.start_build(projectName=project_name)["build"]
    build_id = build["id"]

    final_build = _poll_until(
        lambda: codebuild.batch_get_builds(ids=[build_id])["builds"][0],
        lambda b: b["buildStatus"] != "IN_PROGRESS",
        timeout_s=_BUILD_TIMEOUT_S,
        interval_s=_BUILD_POLL_S,
    )
    assert final_build["buildStatus"] == "SUCCEEDED", (
        f"build did not succeed: {final_build['buildStatus']}"
    )

    report_arns = _poll_until(
        lambda: codebuild.list_reports_for_report_group(reportGroupArn=rg_arn).get(
            "reports", []
        ),
        lambda reports: len(reports) >= 1,
        timeout_s=_REPORT_TIMEOUT_S,
        interval_s=_REPORT_POLL_S,
    )
    assert len(report_arns) == 1, f"expected exactly 1 report, got {report_arns}"

    report = codebuild.batch_get_reports(reportArns=report_arns)["reports"][0]
    assert report["status"] == "SUCCEEDED", f"expected report status SUCCEEDED, got {report['status']!r}"
    test_summary = report["testSummary"]
    assert test_summary["total"] == 1, f"expected 1 test case in report, got {test_summary['total']}"
    assert test_summary["statusCounts"].get("SUCCEEDED", 0) == 1, (
        f"expected 1 SUCCEEDED test case, got statusCounts={test_summary['statusCounts']!r}"
    )
    expected_pass_rate = (
        test_summary["statusCounts"].get("SUCCEEDED", 0) / test_summary["total"] * 100.0
    )

    trend = codebuild.get_report_group_trend(reportGroupArn=rg_arn, trendField="PASS_RATE")
    assert len(trend["rawData"]) == 1, f"expected 1 trend data point, got {trend['rawData']}"
    raw_point = trend["rawData"][0]
    assert raw_point["reportArn"] == report_arns[0], (
        f"trend rawData references {raw_point['reportArn']!r}, expected {report_arns[0]!r}"
    )
    assert abs(float(raw_point["data"]) - expected_pass_rate) < 0.01, (
        f"trend rawData point {raw_point['data']!r}, expected {expected_pass_rate!r}"
    )
    assert abs(float(trend["stats"]["average"]) - expected_pass_rate) < 0.01, (
        f"trend stats.average {trend['stats']['average']!r}, expected {expected_pass_rate!r}"
    )
    assert abs(float(trend["stats"]["max"]) - expected_pass_rate) < 0.01, (
        f"trend stats.max {trend['stats']['max']!r}, expected {expected_pass_rate!r}"
    )
    assert abs(float(trend["stats"]["min"]) - expected_pass_rate) < 0.01, (
        f"trend stats.min {trend['stats']['min']!r}, expected {expected_pass_rate!r}"
    )


def _junit_buildspec(report_group_arn: str) -> str:
    junit_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<testsuites><testsuite name="sim2real" tests="1" failures="0">'
        '<testcase classname="sim2real" name="trend_check" time="0.01"/>'
        "</testsuite></testsuites>"
    )
    buildspec = {
        "version": "0.2",
        "phases": {
            "build": {
                "commands": [
                    "mkdir -p reports",
                    f"printf '%s' '{junit_xml}' > reports/report.xml",
                ]
            }
        },
        "reports": {
            report_group_arn: {
                "files": ["reports/report.xml"],
                "file-format": "JUNITXML",
            }
        },
    }
    return json.dumps(buildspec)


def _create_build_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-cb-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "codebuild:CreateReport",
                    "codebuild:UpdateReport",
                    "codebuild:BatchPutTestCases",
                    "codebuild:BatchPutCodeCoverages",
                ],
                "Resource": "*",
            },
        ],
    }
    policy_name = "sim2real-behav-cb-inline-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(inline_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )
    return role["Arn"]


def _create_project_with_role_retry(
    ctx, codebuild, *, name: str, role_arn: str, buildspec: str
) -> dict[str, Any]:
    deadline = time.monotonic() + _ROLE_RETRY_TIMEOUT_S
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return codebuild.create_project(
                name=name,
                source={"type": "NO_SOURCE", "buildspec": buildspec},
                artifacts={"type": "NO_ARTIFACTS"},
                environment={
                    "type": "LINUX_CONTAINER",
                    "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
                    "computeType": "BUILD_GENERAL1_SMALL",
                },
                serviceRole=role_arn,
                timeoutInMinutes=10,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["project"]
        except Exception as exc:  # noqa: BLE001
            response = getattr(exc, "response", None)
            code = (response or {}).get("Error", {}).get("Code")
            message = (response or {}).get("Error", {}).get("Message", "")
            if code == "InvalidInputException" and "not authorized" in message.lower():
                last_exc = exc
                time.sleep(_ROLE_RETRY_INTERVAL_S)
                continue
            raise
    raise AssertionError(
        f"create_project never succeeded after role propagation retries: {last_exc}"
    )


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    if predicate(value):
        return value
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {value}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
