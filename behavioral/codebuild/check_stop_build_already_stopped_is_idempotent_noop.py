"""stop-build-already-stopped-is-idempotent-noop."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "stop-build-already-stopped-is-idempotent-noop"
GROUP = "negative-classes"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopBuild on a build already STOPPED is a no-op that returns it STOPPED with an unchanged endTime,
    while the first StopBuild stops the IN_PROGRESS build."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-stop-")
    _create_project(
        ctx,
        project_name,
        role_arn,
        source={
            "type": "NO_SOURCE",
            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - sleep 600\n",
        },
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    build = codebuild.start_build(projectName=project_name)["build"]
    build_id = build["id"]
    ctx.on_cleanup(lambda: _best_effort_stop(codebuild, build_id))
    assert build["buildStatus"] == "IN_PROGRESS", build["buildStatus"]
    # The buildspec sleeps far longer than this check runs, so the build stays running
    # until the check stops it; wait until the read API shows it running.
    _poll_until(
        lambda: codebuild.batch_get_builds(ids=[build_id])["builds"][0],
        lambda b: b["buildStatus"] == "IN_PROGRESS",
        timeout_s=60,
        interval_s=2,
    )

    # Positive control: stopping a running build succeeds and transitions it to STOPPED.
    stopped = codebuild.stop_build(id=build_id)["build"]
    assert stopped["buildStatus"] in ("STOPPED", "STOPPING"), stopped["buildStatus"]
    final = _poll_until(
        lambda: codebuild.batch_get_builds(ids=[build_id])["builds"][0],
        lambda b: b["buildStatus"] == "STOPPED",
        timeout_s=120,
        interval_s=3,
    )

    # Re-stopping an already-terminal build is an idempotent no-op on real AWS: it does
    # NOT raise, and it does NOT re-trigger a new state transition (endTime is stable).
    again = codebuild.stop_build(id=build_id)["build"]
    assert again["buildStatus"] == "STOPPED", f"unexpected status: {again['buildStatus']}"
    assert again["endTime"] == final["endTime"], "re-stopping mutated the terminal endTime"

    # Effect absent: the build is still STOPPED and did not change state again.
    unchanged = codebuild.batch_get_builds(ids=[build_id])["builds"][0]
    assert unchanged["buildStatus"] == "STOPPED", f"unexpected status: {unchanged['buildStatus']}"
    assert unchanged["endTime"] == final["endTime"], "build endTime drifted after the no-op re-stop"


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _create_codebuild_role(ctx) -> str:
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_project(ctx, name: str, role_arn: str, **overrides: Any) -> dict:
    codebuild = ctx.client("codebuild")
    params: dict[str, Any] = {
        "name": name,
        "source": {
            "type": "NO_SOURCE",
            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo default\n",
        },
        "artifacts": {"type": "NO_ARTIFACTS"},
        "environment": {
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        "serviceRole": role_arn,
        "logsConfig": {
            "cloudWatchLogs": {"status": "DISABLED"},
            "s3Logs": {"status": "DISABLED"},
        },
    }
    params.update(overrides)
    last_err = None
    for _ in range(10):
        try:
            return codebuild.create_project(**params)["project"]
        except codebuild.exceptions.InvalidInputException as err:
            last_err = err
            time.sleep(3)
    raise last_err


def _best_effort_stop(codebuild, build_id: str) -> None:
    try:
        codebuild.stop_build(id=build_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
