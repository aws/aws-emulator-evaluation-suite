"""stop-build-already-stopped-is-an-idempotent-no-op."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-build-already-stopped-is-an-idempotent-no-op"
GROUP = "overly-permissive"
SERVICES = ["codebuild"]

_IMAGE = "aws/codebuild/amazonlinux2-x86_64-standard:5.0"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopBuild on a build already STOPPED returns 200 with status STOPPED and the same endTime, after a
    first StopBuild moved the running build to STOPPED."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_service_role(ctx)

    project_name = ctx.unique_name("sim2real-cb-proj-")
    _create_project_retrying_role_propagation(
        codebuild,
        name=project_name,
        source={
            "type": "NO_SOURCE",
            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo placeholder\n",
        },
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": _IMAGE,
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    long_spec = "version: 0.2\nphases:\n  build:\n    commands:\n      - sleep 120\n"
    build_id = codebuild.start_build(projectName=project_name, buildspecOverride=long_spec)[
        "build"
    ]["id"]
    ctx.on_cleanup(lambda: codebuild.batch_delete_builds(ids=[build_id]))

    # positive control: stopping a running build actually transitions it to STOPPED
    stop_resp = codebuild.stop_build(id=build_id)
    assert stop_resp["build"]["buildStatus"] == "STOPPED", (
        f"positive control: expected STOPPED, got {stop_resp['build']['buildStatus']!r}"
    )
    final_status = _poll_until_terminal(ctx, build_id)
    assert final_status == "STOPPED", f"positive control: expected STOPPED, got {final_status!r}"
    settled = codebuild.batch_get_builds(ids=[build_id])["builds"][0]
    settled_end_time = settled["endTime"]

    # StopBuild against the already-STOPPED build is an idempotent no-op on real AWS:
    # it does not raise, and does not re-trigger a state transition (endTime unchanged).
    noop = codebuild.stop_build(id=build_id)["build"]
    assert noop["buildStatus"] == "STOPPED", (
        f"no-op StopBuild changed buildStatus: expected STOPPED, got {noop['buildStatus']!r}"
    )
    assert noop["endTime"] == settled_end_time, "no-op StopBuild mutated the terminal endTime"

    # effect absent, via an independent read: terminal status and endTime are unchanged
    build_after = codebuild.batch_get_builds(ids=[build_id])["builds"][0]
    assert build_after["buildStatus"] == "STOPPED", (
        f"no-op StopBuild mutated terminal status: expected STOPPED, got {build_after['buildStatus']!r}"
    )
    assert build_after["endTime"] == settled_end_time, (
        "independent read shows endTime changed after the no-op StopBuild"
    )


def _create_project_retrying_role_propagation(codebuild, **kwargs) -> None:
    """CreateProject retrying through IAM trust-policy propagation: a freshly-created
    service role is not yet assumable, and CodeBuild reports that as InvalidInputException
    rather than exposing a condition to poll."""
    deadline = time.monotonic() + 120.0
    while True:
        try:
            codebuild.create_project(**kwargs)
            return
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


def _poll_until_terminal(ctx, build_id: str, timeout_s: float = 60.0) -> str:
    codebuild = ctx.client("codebuild")
    terminal = {"SUCCEEDED", "FAILED", "FAULT", "TIMED_OUT", "STOPPED"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        build = codebuild.batch_get_builds(ids=[build_id])["builds"][0]
        status = build["buildStatus"]
        if status in terminal:
            return status
        time.sleep(3)
    raise AssertionError(f"build {build_id} never reached a terminal state (last={status})")


def _create_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust = {
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
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-cb-inline",
        PolicyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cb-inline")
    )
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
