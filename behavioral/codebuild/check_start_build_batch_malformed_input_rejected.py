"""start-build-batch-malformed-input-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-build-batch-malformed-input-rejected"
GROUP = "negative-classes"
SERVICES = ["codebuild"]
_SCENARIO = "start-build-batch-malformed-input"

_BATCH_BUILDSPEC = (
    "version: 0.2\n"
    "batch:\n"
    "  build-list:\n"
    "    - identifier: build1\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    "      - echo batch-build\n"
)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartBuildBatch with a malformed buildBatchConfigOverride (a negative
    timeoutInMins) is rejected with InvalidInputException before any batch build
    resource is created, while a well-formed StartBuildBatch call still succeeds."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-batch-")
    _create_project(
        ctx,
        project_name,
        role_arn,
        source={"type": "NO_SOURCE", "buildspec": _BATCH_BUILDSPEC},
        buildBatchConfig={"serviceRole": role_arn, "combineArtifacts": False},
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    def _start_malformed() -> None:
        codebuild.start_build_batch(
            projectName=project_name,
            # The override replaces the project's batch config, so it carries the same
            # serviceRole; the negative timeout is the only thing wrong with the request.
            buildBatchConfigOverride={"serviceRole": role_arn, "timeoutInMins": -100},
        )

    code, message = _error(_start_malformed)
    assert code == "InvalidInputException", f"unexpected code: {code}"
    expected_message = "TimeoutInMins must be between 5 and 2160"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no batch build resource was created by the rejected call.
    ids_before = codebuild.list_build_batches_for_project(projectName=project_name)["ids"]
    assert ids_before == [], f"a batch build was created despite the rejected request: {ids_before}"

    # Positive control: a well-formed StartBuildBatch call succeeds.
    batch = codebuild.start_build_batch(projectName=project_name)["buildBatch"]
    batch_id = batch["id"]
    ctx.on_cleanup(lambda: _best_effort_stop_batch(codebuild, batch_id))
    assert batch["buildBatchStatus"] in ("IN_PROGRESS", "SUBMITTED"), batch["buildBatchStatus"]

    ids_after = codebuild.list_build_batches_for_project(projectName=project_name)["ids"]
    assert batch_id in ids_after, f"well-formed batch {batch_id!r} not in {ids_after!r}"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected rejection, but the call succeeded: {result!r}")


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
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
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
        "tags": [{"key": "sim2real", "value": _SCENARIO}],
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


def _best_effort_stop_batch(codebuild, batch_id: str) -> None:
    try:
        codebuild.stop_build_batch(id=batch_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
