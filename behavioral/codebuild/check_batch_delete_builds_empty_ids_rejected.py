"""batch-delete-builds-empty-ids-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-delete-builds-empty-ids-rejected"
GROUP = "negative-classes"
SERVICES = ["codebuild"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchDeleteBuilds with an empty ids array is rejected with InvalidInputException
    rather than silently succeeding; the (still-existing) build is untouched, and a
    real deletion of that same build with a non-empty id list succeeds."""
    cb = ctx.client("codebuild")
    # botocore's own client-side ParamValidationError would fire before any request
    # ever reaches the service for an empty list, masking the *service's* semantics.
    # A second ctx client with client-side param validation disabled lets this one call
    # reach CodeBuild so the assertion is on ITS rejection.
    cb_noval = ctx.client(
        "codebuild",
        config=Config(parameter_validation=False, retries={"max_attempts": 8, "mode": "standard"}),
    )
    role_arn = _create_codebuild_service_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-bdb-")

    _create_project_with_retry(
        cb,
        name=project_name,
        source={
            "type": "NO_SOURCE",
            "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo sim2real\n",
        },
        artifacts={"type": "NO_ARTIFACTS"},
        environment=_minimal_environment(),
        serviceRole=role_arn,
        logsConfig={"cloudWatchLogs": {"status": "DISABLED"}, "s3Logs": {"status": "DISABLED"}},
        tags=[{"key": "sim2real", "value": "batch-delete-builds-empty-ids-rejected"}],
    )
    ctx.on_cleanup(lambda: cb.delete_project(name=project_name))

    build_id = cb.start_build(projectName=project_name)["build"]["id"]
    # Stop immediately so the build reaches a terminal (deletable) state quickly rather
    # than waiting out the full echo/provisioning cycle.
    cb.stop_build(id=build_id)
    _wait_build_terminal(cb, build_id, timeout_s=120.0)

    code, message = _error(lambda: cb_noval.batch_delete_builds(ids=[]))
    assert (code, message) == (
        "InvalidInputException",
        "The input build ID list cannot be empty.",
    ), (code, message)

    # Effect absent: the build is still there.
    got = cb.batch_get_builds(ids=[build_id])
    assert build_id not in got["buildsNotFound"], f"{build_id} unexpectedly reported not found: {got}"
    assert got["builds"][0]["id"] == build_id, f"expected {build_id}, got {got['builds']}"

    # Positive control: a real, non-empty id list actually deletes it. CodeBuild's
    # internal build-record store can lag a few seconds behind the build reaching a
    # terminal status, so poll rather than assuming the very first attempt succeeds.
    result = _batch_delete_with_retry(cb, build_id)
    assert len(result["buildsDeleted"]) == 1, f"unexpected batch_delete_builds result: {result}"
    # BatchDeleteBuilds echoes back the build's full ARN, not the bare id we passed in.
    assert result["buildsDeleted"][0].endswith(build_id), f"unexpected batch_delete_builds result: {result}"
    assert result["buildsNotDeleted"] == [], f"expected no buildsNotDeleted, got {result['buildsNotDeleted']}"
    got_after = cb.batch_get_builds(ids=[build_id])
    assert build_id in got_after["buildsNotFound"], f"expected {build_id} to be gone, got {got_after}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected
    SUCCESS raises, so an over-permissive target is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _minimal_environment() -> dict[str, Any]:
    return {
        "type": "LINUX_CONTAINER",
        "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
        "computeType": "BUILD_GENERAL1_SMALL",
        "imagePullCredentialsType": "CODEBUILD",
    }


def _create_codebuild_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust_policy = json.dumps(
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": "batch-delete-builds-empty-ids-rejected"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Arn"]


def _create_project_with_retry(cb, timeout_s: float = 40.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return cb.create_project(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInputException":
                raise
            last_exc = exc
            time.sleep(3)
    assert last_exc is not None, "create_project retry loop exited without ever raising"
    raise last_exc


def _wait_build_terminal(cb, build_id: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> str:
    terminal = {"SUCCEEDED", "FAILED", "FAULT", "TIMED_OUT", "STOPPED"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        builds = cb.batch_get_builds(ids=[build_id])["builds"]
        status = builds[0]["buildStatus"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"build {build_id} never reached a terminal state (last status={status})")


def _batch_delete_with_retry(cb, build_id: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> dict:
    """The build record can lag briefly behind the build's terminal status becoming
    visible; retry a non-empty buildsNotDeleted a few times before giving up."""
    deadline = time.monotonic() + timeout_s
    result: dict = {}
    while time.monotonic() < deadline:
        result = cb.batch_delete_builds(ids=[build_id])
        deleted = result.get("buildsDeleted") or []
        if len(deleted) == 1 and deleted[0].endswith(build_id):
            return result
        time.sleep(interval_s)
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
