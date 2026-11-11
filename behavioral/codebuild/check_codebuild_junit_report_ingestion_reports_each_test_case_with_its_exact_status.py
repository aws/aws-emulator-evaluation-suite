"""codebuild-junit-report-ingestion-reports-each-test-case-with-its-exact-status."""
from __future__ import annotations

import json
import time


from botocore.exceptions import ClientError

from behavioral_harness import tags

_SCENARIO = "codebuild-junit-report"
_IMAGE = "aws/codebuild/standard:7.0"


def _delete_role(iam, role_name):
    """Delete an IAM role and its inline policies; an already-deleted role is fine."""
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_service_role(ctx, statements):
    """A CodeBuild-assumable service role carrying exactly `statements`."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-codebuild-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="codebuild-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation exposes no condition to poll; _create_project retries the trust error.
    return resp["Role"]["Arn"]


def _create_project(cb, ctx, name, role_arn, buildspec, **over):
    """CreateProject on NO_SOURCE + an inline buildspec, retrying through IAM trust-policy
    propagation; registers teardown on success."""
    args = {
        "name": name,
        "source": {"type": "NO_SOURCE", "buildspec": buildspec},
        "artifacts": {"type": "NO_ARTIFACTS"},
        "cache": {"type": "NO_CACHE"},
        "environment": {"type": "LINUX_CONTAINER", "image": _IMAGE,
                        "computeType": "BUILD_GENERAL1_SMALL"},
        "serviceRole": role_arn,
        "logsConfig": {"cloudWatchLogs": {"status": "DISABLED"},
                       "s3Logs": {"status": "DISABLED"}},
        "timeoutInMinutes": 5,
        "tags": [{"key": "sim2real", "value": _SCENARIO}],
    }
    args.update(over)
    deadline = time.monotonic() + 120
    while True:
        try:
            proj = cb.create_project(**args)["project"]
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            msg = (err.get("Message") or "").lower()
            transient_role = err.get("Code") == "InvalidInputException" and (
                "assume" in msg or "not authorized" in msg)
            if transient_role and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: cb.delete_project(name=proj["name"]))
    return proj


def _stop(cb, build_id):
    try:
        cb.stop_build(id=build_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _start_build_with_stop_registered(cb, ctx, **kwargs):
    """Register the StopBuild cleanup BEFORE issuing StartBuild, so a build that starts and
    then trips an assertion still gets stopped instead of billing its whole timeout."""
    holder = {"id": None}
    ctx.on_cleanup(lambda: holder["id"] and _stop(cb, holder["id"]))
    resp = cb.start_build(**kwargs)
    holder["id"] = resp["build"]["id"]
    return resp["build"]


def _poll_build_terminal(cb, build_id, *, timeout_s, interval_s=3.0):
    """Poll BatchGetBuilds until buildComplete; None if the deadline passes first."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = cb.batch_get_builds(ids=[build_id])
        builds = got.get("builds", [])
        assert builds, f"BatchGetBuilds lost build {build_id!r}: {got!r}"
        last = builds[0]
        if last.get("buildComplete") is True:
            return last
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval_s)


def _phases(build):
    return [(p.get("phaseType"), p.get("phaseStatus")) for p in build.get("phases", [])]

CHECK = "codebuild-junit-report-ingestion-reports-each-test-case-with-its-exact-status"
GROUP = 'reports'
SERVICES = ['codebuild']


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A JUnit XML with two passing and one failing case yields one report listing each case's
    exact status, matching testSummary and the failure message; the report is FAILED while the
    build is SUCCEEDED, because an ingested test failure does not fail the build.
    """
    cb = ctx.client("codebuild")

    rg = cb.create_report_group(
        name=ctx.unique_name("sim2real-behav-rg-"), type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"},
        tags=[{"key": "sim2real", "value": _SCENARIO}])["reportGroup"]
    ctx.on_cleanup(lambda: cb.delete_report_group(arn=rg["arn"], deleteReports=True))

    fail_msg = ctx.unique_name("sim2real-gamma-boom-")
    xml_fmt = (
        "<testsuites><testsuite name=\"sim2real\" tests=\"3\" failures=\"1\">"
        "<testcase name=\"alpha_passes\" classname=\"sim2real.suite\" time=\"0.01\"/>"
        "<testcase name=\"beta_passes\" classname=\"sim2real.suite\" time=\"0.02\"/>"
        "<testcase name=\"gamma_fails\" classname=\"sim2real.suite\" time=\"0.03\">"
        "<failure message=\"%s\">%s</failure>"
        "</testcase></testsuite></testsuites>"
    )
    buildspec = (
        "version: 0.2\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        "      - printf '" + xml_fmt + "' \"$SIM2REAL_FAILMSG\" \"$SIM2REAL_FAILMSG\""
        " > sim2real-results.xml\n"
        "reports:\n"
        '  "' + rg["arn"] + '":\n'
        "    files:\n"
        "      - sim2real-results.xml\n"
        "    file-format: JUNITXML\n"
    )

    name = ctx.unique_name("sim2real-behav-proj-rep-")
    _create_project(cb, ctx, name, _create_service_role(ctx, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"},
        {"Effect": "Allow",
         "Action": ["codebuild:CreateReport", "codebuild:UpdateReport",
                    "codebuild:BatchPutTestCases", "codebuild:BatchPutCodeCoverages"],
         "Resource": rg["arn"]}]), buildspec)

    started = _start_build_with_stop_registered(
        cb, ctx, projectName=name,
        environmentVariablesOverride=[
            {"name": "SIM2REAL_FAILMSG", "value": fail_msg, "type": "PLAINTEXT"}])
    build = _poll_build_terminal(cb, started["id"], timeout_s=240)
    assert build is not None, f"build {started['id']!r} never reported buildComplete"

    assert build["buildStatus"] == "SUCCEEDED", (
        f"every buildspec command exited zero, so the build must be SUCCEEDED even though a "
        f"test case failed; got {build['buildStatus']!r}; phases={_phases(build)!r}"
    )
    arns = build.get("reportArns") or []
    assert len(arns) == 1, f"expected exactly one report arn, got {arns!r}"

    report = cb.batch_get_reports(reportArns=arns)["reports"][0]
    cases = []
    token = None
    while True:
        page = cb.describe_test_cases(
            reportArn=arns[0], **({"nextToken": token} if token else {}))
        cases.extend(page.get("testCases", []))
        token = page.get("nextToken")
        if not token:
            break

    expected_names = {"alpha_passes", "beta_passes", "gamma_fails"}
    got_names = set(c["name"] for c in cases)
    assert got_names == expected_names, (
        f"report listed {sorted(got_names)!r}, expected {sorted(expected_names)!r}"
    )
    expected_pairs = {("alpha_passes", "SUCCEEDED"), ("beta_passes", "SUCCEEDED"),
                      ("gamma_fails", "FAILED")}
    got_pairs = set((c["name"], c["status"]) for c in cases)
    assert got_pairs == expected_pairs, (
        f"per-case status mismatch: {sorted(got_pairs)!r}, expected "
        f"{sorted(expected_pairs)!r}"
    )
    assert report["status"] == "FAILED", (
        f"the report must record the ingested test failure as FAILED even though the build "
        f"SUCCEEDED, report status was {report['status']!r}"
    )
    summary = report.get("testSummary") or {}
    assert (summary.get("total"), summary.get("statusCounts", {}).get("FAILED")) == (3, 1), (
        f"testSummary disagrees with the three ingested cases: {summary!r}"
    )
    failed_case = next(c for c in cases if c["name"] == "gamma_fails")
    assert fail_msg in (failed_case.get("message") or ""), (
        f"the failing case carried message {failed_case.get('message')!r}, expected it to "
        f"contain the emitted {fail_msg!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
