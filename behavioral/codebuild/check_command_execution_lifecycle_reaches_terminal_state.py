"""command-execution-lifecycle-reaches-terminal-state."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "command-execution-lifecycle-reaches-terminal-state"
GROUP = "state-machine"
SERVICES = ["codebuild"]

_QUICK_BUILDSPEC = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo build-ok\n"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A command execution started in a sandbox progresses to a terminal SUCCEEDED status."""
    codebuild = ctx.client("codebuild")
    role_arn = _make_codebuild_role(ctx)
    project_name = _create_no_source_project(ctx, role_arn, _QUICK_BUILDSPEC)

    sandbox_id = codebuild.start_sandbox(projectName=project_name)["sandbox"]["id"]
    ctx.on_cleanup(lambda: _stop_sandbox(codebuild, sandbox_id))

    def _running():
        s = codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]
        return s if s["status"] == "RUNNING" else None

    assert _poll_until(_running, timeout_s=300, interval_s=5) is not None, "sandbox never reached RUNNING"

    exec_id = codebuild.start_command_execution(
        sandboxId=sandbox_id, command="echo hello-command-execution", type="SHELL"
    )["commandExecution"]["id"]

    def _terminal():
        ce = codebuild.batch_get_command_executions(
            sandboxId=sandbox_id, commandExecutionIds=[exec_id]
        )["commandExecutions"][0]
        # Measured against real AWS: the in-flight set is bigger than QUEUED/PENDING/
        # PROCESSING -- a real command execution passes through SUBMITTED too, and a poll
        # that only excludes the smaller set stops early, on a still-in-flight status. Poll
        # for the two genuine terminal outcomes directly instead of guessing the transient set.
        return ce if ce["status"] in ("SUCCEEDED", "FAILED") else None

    final = _poll_until(_terminal, timeout_s=180, interval_s=3)
    assert final is not None, "command execution never reached SUCCEEDED or FAILED within 180s"
    assert final.get("submitTime") is not None, "terminal command execution missing submitTime"
    # This check runs a plain `echo`, which has no legitimate way to fail -- so unlike a
    # general terminal-state probe, the happy-path contract under test is specifically
    # SUCCEEDED, not merely "reached some terminal state" (a target that reported FAILED for
    # every command execution would otherwise still satisfy a weaker version of this check).
    assert final["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {final['status']!r}: {final!r}"
    assert final.get("exitCode") == "0", f"expected exitCode '0', got {final.get('exitCode')!r}"
    assert "hello-command-execution" in final.get("standardOutputContent", ""), (
        f"expected the echoed marker in stdout, got {final.get('standardOutputContent')!r}"
    )


# ===== helpers =====
def _try(fn) -> None:
    """Teardown call: an already-absent resource is fine; any other failure raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "NoSuchEntity"):
            raise


def _stop_sandbox(codebuild, sandbox_id: str) -> None:
    """Teardown: stops the sandbox unless already stopped, retrying while it is still starting."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 180.0
    while True:
        sandboxes = codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"]
        if not sandboxes:
            return  # an absent id is already gone
        status = sandboxes[0]["status"]
        if status in ("STOPPING", "STOPPED", "FAILED"):
            return
        try:
            codebuild.stop_sandbox(id=sandbox_id)
            return
        except ClientError as exc:
            # StopSandbox refuses a sandbox that is still starting up.
            if exc.response["Error"]["Code"] != "InvalidInputException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        value = probe()
        if value is not None:
            return value
        time.sleep(interval_s)
    return None


def _make_codebuild_role(ctx) -> str:
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        _try(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="inline"))
        _try(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "s3:*",
                    "ssmmessages:*",
                    "ssm:StartSession",
                    "codebuild:*",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )

    def _policy_readable():
        doc = iam.get_role_policy(RoleName=role_name, PolicyName="inline").get("PolicyDocument")
        return doc if doc else None

    # IAM's own read path is the only observable proxy for the propagation CodeBuild's
    # STS AssumeRole needs; bound the wait on it instead of sleeping blind.
    assert _poll_until(_policy_readable, timeout_s=30, interval_s=2) is not None, (
        "inline role policy never became readable via get_role_policy"
    )
    return role_arn


def _create_no_source_project(
    ctx, role_arn: str, buildspec: str, extra: dict[str, Any] | None = None
) -> str:
    codebuild = ctx.client("codebuild")
    name = ctx.unique_name("sim2real-cb-proj-")
    kwargs: dict[str, Any] = dict(
        name=name,
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
    if extra:
        kwargs.update(extra)

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            codebuild.create_project(**kwargs)
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInputException":
                last_err = e
                time.sleep(5)
                continue
            raise
    else:
        assert last_err is not None, "create_project deadline elapsed with no recorded error"
        raise last_err
    ctx.on_cleanup(lambda: _try(lambda: codebuild.delete_project(name=name)))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
