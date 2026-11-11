"""retry-build-account-limit-exceeded-blocked."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "retry-build-account-limit-exceeded-blocked"
GROUP = "negative-classes"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RetryBuild while the project's concurrent-build limit is already saturated by
    another running build is rejected with AccountLimitExceededException instead of
    queuing a new build, and succeeds once the limit frees up again (positive control)."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-lim-")
    project = _create_project(ctx, project_name, role_arn, concurrentBuildLimit=1)
    assert project["concurrentBuildLimit"] == 1, (
        f"expected concurrentBuildLimit=1, got {project['concurrentBuildLimit']!r}"
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    # Build A: quick build, completes fast and is later used as the RetryBuild target.
    build_a = codebuild.start_build(
        projectName=project_name,
        buildspecOverride="version: 0.2\nphases:\n  build:\n    commands:\n      - echo build-a\n",
    )["build"]
    build_a_id = build_a["id"]
    ctx.on_cleanup(lambda: _best_effort_stop(codebuild, build_a_id))
    build_a = _poll_until(
        lambda: codebuild.batch_get_builds(ids=[build_a_id])["builds"][0],
        lambda b: b["buildStatus"] != "IN_PROGRESS",
        timeout_s=240,
        interval_s=5,
    )
    assert build_a["buildStatus"] == "SUCCEEDED", f"build A did not succeed: {build_a}"

    # Build B: holds the project's single concurrent-build slot. Its buildspec sleeps far
    # longer than this check runs; the check stops it itself to free the slot.
    build_b = codebuild.start_build(
        projectName=project_name,
        buildspecOverride="version: 0.2\nphases:\n  build:\n    commands:\n      - sleep 600\n",
    )["build"]
    build_b_id = build_b["id"]
    ctx.on_cleanup(lambda: _best_effort_stop(codebuild, build_b_id))
    assert build_b["buildStatus"] == "IN_PROGRESS", (
        f"expected build B to be IN_PROGRESS right after StartBuild, got {build_b['buildStatus']!r}"
    )
    _poll_until(
        lambda: codebuild.batch_get_builds(ids=[build_b_id])["builds"][0],
        lambda b: b["buildStatus"] == "IN_PROGRESS",
        timeout_s=60,
        interval_s=2,
    )

    # Negative: while B holds the only concurrency slot, retrying A must be blocked.
    code, message = _error(lambda: _retry_build_tracked(ctx, codebuild, build_a_id))
    assert code == "AccountLimitExceededException", f"unexpected code: {code}"
    expected_message = (
        f"Concurrent build limit exceeded. This build project has a limit of "
        f"{project['concurrentBuildLimit']} concurrent build(s). Start the build again after "
        f"other builds are complete, or edit project configuration."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the blocked RetryBuild did not create any additional build.
    builds_for_project = codebuild.list_builds_for_project(projectName=project_name)["ids"]
    related = [bid for bid in builds_for_project if bid.startswith(f"{project_name}:")]
    assert sorted(related) == sorted([build_a_id, build_b_id]), (
        f"unexpected build set after blocked retry: {related}"
    )

    # Positive control: once B is stopped and frees the slot, RetryBuild on A succeeds.
    codebuild.stop_build(id=build_b_id)
    build_b_final = _poll_until(
        lambda: codebuild.batch_get_builds(ids=[build_b_id])["builds"][0],
        lambda b: b["buildStatus"] != "IN_PROGRESS",
        timeout_s=180,
        interval_s=5,
    )
    assert build_b_final["buildStatus"] == "STOPPED", f"build B did not stop: {build_b_final}"

    retried = _retry_build_tracked(ctx, codebuild, build_a_id)
    retried_id = retried["id"]
    assert retried_id != build_a_id, "RetryBuild should mint a new build id"
    assert retried["buildStatus"] == "IN_PROGRESS", (
        f"expected RetryBuild to return the new build IN_PROGRESS, got {retried['buildStatus']!r}"
    )

    # Independent read right after RetryBuild: provisioning alone outlasts this call, so the
    # retried build still reads back IN_PROGRESS.
    retried_now = codebuild.batch_get_builds(ids=[retried_id])["builds"][0]
    assert retried_now["buildStatus"] == "IN_PROGRESS", (
        f"expected the retried build {retried_id!r} to read back IN_PROGRESS via an "
        f"independent BatchGetBuilds, got {retried_now['buildStatus']!r}"
    )

    # Terminal read: an independent BatchGetBuilds, polled until the retried build finishes.
    retried_seen = _poll_until(
        lambda: codebuild.batch_get_builds(ids=[retried_id])["builds"][0],
        lambda b: b["buildStatus"] != "IN_PROGRESS",
        timeout_s=240,
        interval_s=5,
    )
    assert retried_seen["buildStatus"] == "SUCCEEDED", (
        f"expected the retried build {retried_id!r} to finish SUCCEEDED, got {retried_seen!r}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _retry_build_tracked(ctx, codebuild, build_id: str) -> dict:
    """RetryBuild, registering a stop for any build it mints."""
    build = codebuild.retry_build(id=build_id)["build"]
    ctx.on_cleanup(lambda: _best_effort_stop(codebuild, build["id"]))
    return build


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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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
        "tags": [{"key": "sim2real", "value": CHECK}],
    }
    params.update(overrides)
    last_err = None
    # IAM role trust propagation can lag a few seconds behind create_role.
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
