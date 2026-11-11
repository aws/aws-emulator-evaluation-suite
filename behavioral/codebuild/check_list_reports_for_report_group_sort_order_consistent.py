"""list-reports-for-report-group-sort-order-consistent."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-reports-for-report-group-sort-order-consistent"
GROUP = "ordering"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListReportsForReportGroup returns a stable order across repeated calls, and ASCENDING/DESCENDING reverse each other."""
    cb = ctx.client("codebuild")
    report_group_name = ctx.unique_name("sim2real-cb-rg-")
    rg = cb.create_report_group(
        name=report_group_name,
        type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    report_group_arn = rg["reportGroup"]["arn"]
    ctx.on_cleanup(lambda: cb.delete_report_group(arn=report_group_arn, deleteReports=True))

    role_arn = _create_report_capable_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-proj-")
    junit_xml = (
        '<testsuites><testsuite name="s" tests="1">'
        '<testcase classname="c" name="t"/></testsuite></testsuites>'
    )
    buildspec_lines = [
        "version: 0.2",
        "phases:",
        "  build:",
        "    commands:",
        "      - mkdir -p reports",
        f"      - printf '%s' '{junit_xml}' > reports/report.xml",
        "reports:",
        f"  {report_group_arn}:",
        "    files:",
        "      - reports/report.xml",
        "    file-format: JUNITXML",
    ]
    buildspec = "\n".join(buildspec_lines) + "\n"

    _create_project_with_role_retry(
        cb,
        ctx,
        name=project_name,
        source={"type": "NO_SOURCE", "buildspec": buildspec},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cb.delete_project(name=project_name))

    build_id_1 = cb.start_build(projectName=project_name)["build"]["id"]
    status_1 = _wait_for_build_terminal(ctx, cb, build_id_1)
    build_id_2 = cb.start_build(projectName=project_name)["build"]["id"]
    status_2 = _wait_for_build_terminal(ctx, cb, build_id_2)
    ctx.on_cleanup(lambda: cb.batch_delete_builds(ids=[build_id_1, build_id_2]))

    assert status_1 == "SUCCEEDED", f"build 1 did not succeed: {status_1}"
    assert status_2 == "SUCCEEDED", f"build 2 did not succeed: {status_2}"

    reports = _wait_for_report_count(ctx, cb, report_group_arn, expected_count=2, timeout_s=120)

    call_a = cb.list_reports_for_report_group(reportGroupArn=report_group_arn)["reports"]
    call_b = cb.list_reports_for_report_group(reportGroupArn=report_group_arn)["reports"]
    assert call_a == call_b, "two identical calls (no sortOrder) must return the same sequence"
    assert set(call_a) == set(reports), (
        f"unsorted list must contain exactly the {len(reports)} reports seen while "
        f"polling, got {len(call_a)}: {sorted(set(call_a) ^ set(reports))}"
    )

    asc = cb.list_reports_for_report_group(
        reportGroupArn=report_group_arn, sortOrder="ASCENDING"
    )["reports"]
    desc = cb.list_reports_for_report_group(
        reportGroupArn=report_group_arn, sortOrder="DESCENDING"
    )["reports"]
    assert set(asc) == set(reports), f"ASCENDING must cover all {len(reports)} reports, got {asc}"
    assert set(desc) == set(reports), f"DESCENDING must cover all {len(reports)} reports, got {desc}"
    assert asc == list(reversed(desc)), "ASCENDING must be the exact reverse of DESCENDING"

    asc_again = cb.list_reports_for_report_group(
        reportGroupArn=report_group_arn, sortOrder="ASCENDING"
    )["reports"]
    assert asc == asc_again, "repeated ASCENDING calls must return the same sequence"


def _create_report_capable_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]

    def _cleanup_role():
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    policy_name = "sim2real-cb-report-policy"
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowLogs",
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {
                "Sid": "AllowReports",
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
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_document)
    )

    def _cleanup_policy():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_policy)
    # No sleep here: IAM trust-policy propagation is bounded by the retry loop in
    # _create_project_with_role_retry below, not by a fixed wait.
    return role_arn


def _create_project_with_role_retry(cb, ctx, *, name, timeout_s: float = 120.0, **kwargs):
    """CreateProject, retrying through IAM trust-policy propagation: a role that was
    just minted may not yet be assumable, and CodeBuild reports that as a transient
    InvalidInputException rather than any distinguishable propagation-specific code."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return cb.create_project(name=name, **kwargs)["project"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient_role = err.get("Code") == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg
            )
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _wait_for_build_terminal(ctx, cb, build_id: str, timeout_s: float = 300.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = "IN_PROGRESS"
    while time.monotonic() < deadline:
        build = cb.batch_get_builds(ids=[build_id])["builds"][0]
        status = build["buildStatus"]
        if status != "IN_PROGRESS":
            return status
        time.sleep(2)
    raise AssertionError(f"build {build_id} did not reach a terminal state within {timeout_s}s")


def _wait_for_report_count(ctx, cb, report_group_arn: str, expected_count: int, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    reports: list[str] = []
    while time.monotonic() < deadline:
        reports = cb.list_reports_for_report_group(reportGroupArn=report_group_arn)["reports"]
        if len(reports) >= expected_count:
            return reports
        time.sleep(5)
    raise AssertionError(
        f"expected {expected_count} reports in {report_group_arn}, saw {len(reports)} after {timeout_s}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
