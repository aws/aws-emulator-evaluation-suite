"""build-batch-lifecycle-transitions."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "build-batch-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["codebuild"]

_SCENARIO = "codebuild-build-batch-lifecycle-transitions"

_BATCH_BUILDSPEC = (
    "version: 0.2\n"
    "batch:\n"
    "  build-list:\n"
    "    - identifier: build1\n"
    "    - identifier: build2\n"
    "phases:\n"
    "  build:\n"
    "    commands:\n"
    "      - sleep 600\n"
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartBuildBatch produces an IN_PROGRESS batch visible via BatchGetBuildBatches, and
    StopBuildBatch drives it to a terminal STOPPED status with finalized phases."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-batch-")

    _create_project_with_retry(
        ctx,
        name=project_name,
        source={"type": "NO_SOURCE", "buildspec": _BATCH_BUILDSPEC},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
        buildBatchConfig={
            "serviceRole": role_arn,
            "combineArtifacts": False,
            "timeoutInMins": 30,
        },
        tags=[{"key": "sim2real", "value": _SCENARIO}],
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    start_resp = codebuild.start_build_batch(projectName=project_name)
    batch = start_resp["buildBatch"]
    batch_id = batch["id"]
    assert batch["buildBatchStatus"] == "IN_PROGRESS", f"unexpected start status: {batch}"

    def _cleanup_batch() -> None:
        try:
            codebuild.stop_build_batch(id=batch_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        # A stopped batch refuses deletion ("still in progress") until it is complete.
        deadline = time.monotonic() + 120.0
        while True:
            try:
                codebuild.delete_build_batch(id=batch_id)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidInputException" or time.monotonic() >= deadline:
                    raise
                time.sleep(2)

    ctx.on_cleanup(_cleanup_batch)

    def _probe() -> dict[str, Any]:
        resp = codebuild.batch_get_build_batches(ids=[batch_id])
        found = resp["buildBatches"]
        assert len(found) == 1, f"batch {batch_id} not found via BatchGetBuildBatches: {resp}"
        return found[0]

    # The batch legs sleep far longer than this check runs, so the check holds the batch
    # in progress until StopBuildBatch; wait until the read API shows it before stopping.
    in_progress = _poll_until(
        _probe, lambda b: b["buildBatchStatus"] == "IN_PROGRESS", timeout_s=60.0, interval_s=3.0
    )
    assert in_progress["buildBatchStatus"] == "IN_PROGRESS", (
        f"expected IN_PROGRESS, got {in_progress['buildBatchStatus']}"
    )

    codebuild.stop_build_batch(id=batch_id)

    stopped = _poll_until(
        _probe, lambda b: b["buildBatchStatus"] == "STOPPED", timeout_s=120.0, interval_s=5.0
    )
    assert stopped["buildBatchStatus"] == "STOPPED", (
        f"expected STOPPED, got {stopped['buildBatchStatus']}"
    )
    assert stopped.get("endTime") is not None, "STOPPED batch must have a finalized endTime"
    phases = stopped.get("phases") or []
    assert phases, "STOPPED batch must report finalized phases"
    assert any(p.get("phaseStatus") == "STOPPED" for p in phases), (
        f"expected a phase reflecting the stop, got: {phases}"
    )


# ===== helpers =====

def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 3.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_codebuild_role(ctx) -> str:
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
        Tags=[{"Key": "sim2real", "Value": _SCENARIO}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-cb-inline"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                            "s3:*",
                        ],
                        "Resource": "*",
                    },
                    {
                        # The batch service role starts and stops the batch legs itself.
                        "Effect": "Allow",
                        "Action": ["codebuild:StartBuild", "codebuild:StopBuild", "codebuild:RetryBuild"],
                        "Resource": "*",
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_project_with_retry(ctx, *, timeout_s: float = 90.0, **kwargs) -> dict[str, Any]:
    """CreateProject can transiently fail with InvalidInputException while the freshly
    created IAM service role has not yet propagated; retry within a bounded window."""
    codebuild = ctx.client("codebuild")
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return codebuild.create_project(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "InvalidInputException" and "role" in message.lower():
                last_exc = exc
                time.sleep(5)
                continue
            raise
    assert last_exc is not None, "retry loop exited without ever calling create_project"
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
