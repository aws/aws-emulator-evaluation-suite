"""stop-build-on-completed-build-is-an-idempotent-no-op."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-build-on-completed-build-is-an-idempotent-no-op"
GROUP = "overly-permissive"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopBuild on an already-SUCCEEDED build is an idempotent no-op: it returns the existing
    terminal status with an unchanged endTime, while the same call on an in-progress build of
    the same project does stop it (positive control)."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    project = _create_minimal_project(
        ctx, role_arn, "version: 0.2\nphases:\n  build:\n    commands:\n      - echo hi\n"
    )

    completed_id = codebuild.start_build(projectName=project)["build"]["id"]
    final = _poll_until(
        lambda: codebuild.batch_get_builds(ids=[completed_id])["builds"][0],
        lambda b: b["buildComplete"],
        timeout_s=240.0,
        interval_s=5.0,
    )
    assert final["buildStatus"] == "SUCCEEDED", f"expected SUCCEEDED, got {final['buildStatus']!r}"

    # StopBuild on an already-SUCCEEDED build is an idempotent no-op on real AWS: it
    # does not raise, and does not re-trigger a state transition (endTime unchanged).
    noop = codebuild.stop_build(id=completed_id)["build"]
    assert noop["buildStatus"] == "SUCCEEDED", (
        f"no-op StopBuild changed buildStatus: expected SUCCEEDED, got {noop['buildStatus']!r}"
    )
    assert noop["endTime"] == final["endTime"], "no-op StopBuild mutated the terminal endTime"

    after = codebuild.batch_get_builds(ids=[completed_id])["builds"][0]
    assert after["buildStatus"] == "SUCCEEDED", (
        f"no-op StopBuild mutated terminal status: expected SUCCEEDED, got {after['buildStatus']!r}"
    )
    assert after["buildComplete"] is True, "no-op StopBuild left buildComplete false"
    assert after["endTime"] == final["endTime"], (
        "independent read shows endTime changed after the no-op StopBuild"
    )

    # positive control: a genuinely in-progress build on the same project can
    # still be stopped successfully.
    control_id = codebuild.start_build(
        projectName=project,
        buildspecOverride="version: 0.2\nphases:\n  build:\n    commands:\n      - sleep 60\n",
    )["build"]["id"]
    ctx.on_cleanup(lambda: _best_effort_stop(codebuild, control_id))
    _poll_until(
        lambda: codebuild.batch_get_builds(ids=[control_id])["builds"][0]["currentPhase"],
        lambda phase: phase == "BUILD",
        timeout_s=240.0,
        interval_s=5.0,
    )
    stop_resp = codebuild.stop_build(id=control_id)
    assert stop_resp["build"]["buildStatus"] in ("STOPPED", "STOPPING"), (
        f"positive control: expected STOPPED/STOPPING, got {stop_resp['build']['buildStatus']!r}"
    )
    control_final = _poll_until(
        lambda: codebuild.batch_get_builds(ids=[control_id])["builds"][0],
        lambda b: b["buildComplete"],
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert control_final["buildStatus"] == "STOPPED", (
        f"positive control: expected STOPPED, got {control_final['buildStatus']!r}"
    )


# ===== helpers =====
_ROLE_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_codebuild_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ROLE_TRUST_POLICY),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    inline_policy = {
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
        RoleName=role_name, PolicyName="sim2real-cb-inline", PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cb-inline"))
    return role_arn


def _create_minimal_project(ctx, role_arn: str, buildspec: str) -> str:
    codebuild = ctx.client("codebuild")
    name = ctx.unique_name("sim2real-cb-proj-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            codebuild.create_project(
                name=name,
                source={"type": "NO_SOURCE", "buildspec": buildspec},
                artifacts={"type": "NO_ARTIFACTS"},
                environment={
                    "type": "LINUX_CONTAINER",
                    "image": "aws/codebuild/standard:7.0",
                    "computeType": "BUILD_GENERAL1_SMALL",
                },
                serviceRole=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInputException" and time.monotonic() < deadline:
                time.sleep(3.0)
                continue
            raise
    ctx.on_cleanup(lambda: codebuild.delete_project(name=name))
    return name


def _poll_until(probe, predicate, *, timeout_s: float = 180.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed value={last!r}")


def _best_effort_stop(codebuild, build_id: str) -> None:
    try:
        codebuild.stop_build(id=build_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
