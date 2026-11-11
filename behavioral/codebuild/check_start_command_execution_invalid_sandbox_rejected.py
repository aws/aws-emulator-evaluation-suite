"""start-command-execution-invalid-sandbox-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "start-command-execution-invalid-sandbox-rejected"
GROUP = "overly-permissive"
SERVICES = ["codebuild"]

_QUICK_BUILDSPEC = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo build-ok\n"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartCommandExecution against a nonexistent sandbox must be rejected, not queued."""
    import uuid

    codebuild = ctx.client("codebuild")
    # Sandbox ids are documented as "<project-name>:<uuid>" (well-formed shape) so that this
    # exercises "doesn't exist" rather than "malformed identifier" (a distinct InvalidInputException
    # boundary already covered elsewhere).
    bogus_sandbox_id = f"{ctx.unique_name('sim2real-cb-nosandbox-')}:{uuid.uuid4()}"

    code, message = _client_error(
        lambda: codebuild.start_command_execution(sandboxId=bogus_sandbox_id, command="echo hi")
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but nonexistent sandboxId, got {code!r}"
    )
    expected = "Sandbox does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: nothing was queued against the phantom sandbox either, checked through an
    # independent read distinct from the rejected mutating call.
    listed = codebuild.list_command_executions_for_sandbox(sandboxId=bogus_sandbox_id)
    assert listed.get("commandExecutions", []) == [], (
        f"expected no command executions listed for a nonexistent sandbox, got {listed.get('commandExecutions')}"
    )

    # Positive control: the identical call against a real, running sandbox is accepted.
    role_arn = _make_codebuild_role(ctx)
    project_name = _create_no_source_project(ctx, role_arn, _QUICK_BUILDSPEC)
    sandbox_id = codebuild.start_sandbox(projectName=project_name)["sandbox"]["id"]
    ctx.on_cleanup(lambda: _stop_sandbox(codebuild, sandbox_id))

    def _running():
        s = codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]
        return s if s["status"] == "RUNNING" else None

    assert _poll_until(_running, timeout_s=300, interval_s=5) is not None, "sandbox never reached RUNNING"

    exec_id = codebuild.start_command_execution(
        sandboxId=sandbox_id, command="echo control-ok"
    )["commandExecution"]["id"]

    # Terminal assertion is an independent read at the destination, through a different
    # operation than the one that mutated -- not the mutating call's own echoed response.
    def _visible():
        ce = codebuild.batch_get_command_executions(
            sandboxId=sandbox_id, commandExecutionIds=[exec_id]
        )["commandExecutions"]
        return ce[0] if ce else None

    seen = _poll_until(_visible, timeout_s=60, interval_s=3)
    assert seen is not None, "control command execution never became visible via an independent read"
    assert seen["sandboxId"] == sandbox_id, (
        f"expected independent read to report sandboxId {sandbox_id!r}, got {seen['sandboxId']!r}"
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


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly here."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust)
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
    # No unconditional sleep for IAM role propagation: _create_no_source_project already
    # retries CreateProject on InvalidInputException (the shape this propagation delay takes)
    # for up to 90s below.
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
        assert last_err is not None
        raise last_err
    ctx.on_cleanup(lambda: _try(lambda: codebuild.delete_project(name=name)))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
