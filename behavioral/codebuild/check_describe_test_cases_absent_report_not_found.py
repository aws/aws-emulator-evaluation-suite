"""describe-test-cases-absent-report-not-found."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


_IMAGE = "aws/codebuild/standard:7.0"


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what AWS refuses is not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_role(iam, role_name):
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
    """Mint a real CodeBuild-assumable service role carrying exactly `statements`."""
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
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="codebuild-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    # IAM propagation exposes no condition to poll; _create_project's bounded retry absorbs it.
    return resp["Role"]["Arn"]


def _create_project(cb, ctx, name, role_arn, buildspec):
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
    }
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
    holder = {"id": None}
    ctx.on_cleanup(lambda: holder["id"] and _stop(cb, holder["id"]))
    resp = cb.start_build(**kwargs)
    holder["id"] = resp["build"]["id"]
    return resp["build"]


def _poll_build_terminal(cb, build_id, *, timeout_s, interval_s=3.0):
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


def _create_real_report(ctx, cb):
    """Run a build that ingests one passing JUnit case; return (report_arn, test_case_name).
    Reports are only created by a build parsing a results file; there is no CreateReport API."""
    rg = cb.create_report_group(
        name=ctx.unique_name("sim2real-behav-rg-"), type="TEST",
        exportConfig={"exportConfigType": "NO_EXPORT"})["reportGroup"]
    ctx.on_cleanup(lambda: cb.delete_report_group(arn=rg["arn"], deleteReports=True))

    case_name = ctx.unique_name("sim2real_case_")
    buildspec = (
        "version: 0.2\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        "      - printf '<testsuites><testsuite name=\"sim2real\" tests=\"1\" "
        "failures=\"0\"><testcase name=\"%s\" classname=\"sim2real.suite\" "
        "time=\"0.01\"/></testsuite></testsuites>' > sim2real-results.xml\n"
        % case_name
        + "reports:\n"
        '  "' + rg["arn"] + '":\n'
        "    files:\n"
        "      - sim2real-results.xml\n"
        "    file-format: JUNITXML\n"
    )

    name = ctx.unique_name("sim2real-behav-proj-rep-")
    role_arn = _create_service_role(ctx, [
        {"Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": "*"},
        {"Effect": "Allow",
         "Action": ["codebuild:CreateReport", "codebuild:UpdateReport",
                    "codebuild:BatchPutTestCases"],
         "Resource": rg["arn"]}])
    _create_project(cb, ctx, name, role_arn, buildspec)

    started = _start_build_with_stop_registered(cb, ctx, projectName=name)
    build = _poll_build_terminal(cb, started["id"], timeout_s=240)
    assert build is not None, f"build {started['id']!r} never reported buildComplete"
    assert build["buildStatus"] == "SUCCEEDED", (
        f"prerequisite build must succeed to mint a real report, got "
        f"{build['buildStatus']!r}; phases={[(p.get('phaseType'), p.get('phaseStatus')) for p in build.get('phases', [])]!r}"
    )
    arns = build.get("reportArns") or []
    assert len(arns) == 1, f"expected exactly one report arn from the build, got {arns!r}"
    return arns[0], case_name


def _perturbed_report_arn(real_arn: str) -> str:
    """`real_arn` with only the report id swapped for a fresh UUID. It must stay UUID-shaped:
    AWS classifies a malformed report id as InvalidInputException, not ResourceNotFound."""
    prefix, _, report_id = real_arn.rpartition(":")
    fresh = str(uuid.uuid4())
    assert fresh != report_id, "uuid collision with the real report id"
    return f"{prefix}:{fresh}"


CHECK = "describe-test-cases-absent-report-not-found"
GROUP = 'error-semantics'
SERVICES = ['codebuild']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeTestCases on a build-minted report returns its JUnit case, while the same ARN with
    only the report id swapped for an absent UUID raises ResourceNotFoundException."""
    cb = ctx.client("codebuild")

    real_arn, case_name = _create_real_report(ctx, cb)

    control = cb.describe_test_cases(reportArn=real_arn)
    control_names = {c["name"] for c in control.get("testCases", [])}
    assert case_name in control_names, (
        f"positive control: expected {case_name!r} in {sorted(control_names)!r} for "
        f"real report {real_arn!r}"
    )

    bogus_arn = _perturbed_report_arn(real_arn)
    code, message = _client_error(lambda: cb.describe_test_cases(reportArn=bogus_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for perturbed report id, got {code!r}"
    )
    assert message == "Report does not exist or is in DELETING status", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
