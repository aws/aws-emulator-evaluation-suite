"""sandbox-lifecycle-active-to-terminated."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "sandbox-lifecycle-active-to-terminated"
GROUP = "state-machine"
SERVICES = ["codebuild"]

_QUICK_BUILDSPEC = "version: 0.2\nphases:\n  build:\n    commands:\n      - echo build-ok\n"


@tags("axis:happy-path", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A sandbox moves to RUNNING then STOPPED, and cannot accept work once terminated."""
    codebuild = ctx.client("codebuild")
    role_arn = _make_codebuild_role(ctx)
    project_name = _create_no_source_project(ctx, role_arn, _QUICK_BUILDSPEC)

    sandbox_id = codebuild.start_sandbox(projectName=project_name)["sandbox"]["id"]
    ctx.on_cleanup(lambda: _stop_sandbox(codebuild, sandbox_id))

    def _running():
        s = codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]
        return s if s["status"] == "RUNNING" else None

    running = _poll_until(_running, timeout_s=300, interval_s=5)
    assert running is not None, "sandbox never reached RUNNING"

    # Positive control: a command execution succeeds while the sandbox is RUNNING, so the
    # later rejection cannot be explained by StartCommandExecution being broken outright.
    control_exec_id = codebuild.start_command_execution(
        sandboxId=sandbox_id, command="echo sim2real-sandbox-active", type="SHELL"
    )["commandExecution"]["id"]

    def _control_done():
        ce = codebuild.batch_get_command_executions(
            sandboxId=sandbox_id, commandExecutionIds=[control_exec_id]
        )["commandExecutions"][0]
        return ce if ce["status"] in ("SUCCEEDED", "FAILED") else None

    control_final = _poll_until(_control_done, timeout_s=120, interval_s=5)
    assert control_final is not None, "control command execution never reached a terminal state"
    assert control_final["status"] == "SUCCEEDED", (
        f"positive control command execution failed: {control_final}"
    )

    before_ids = {
        ce["id"]
        for ce in codebuild.list_command_executions_for_sandbox(sandboxId=sandbox_id)["commandExecutions"]
    }
    assert control_exec_id in before_ids

    codebuild.stop_sandbox(id=sandbox_id)

    def _stopped():
        s = codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]
        return s if s["status"] == "STOPPED" else None

    stopped = _poll_until(_stopped, timeout_s=120, interval_s=3)
    assert stopped is not None, "sandbox never reached STOPPED after StopSandbox"
    assert stopped["status"] == "STOPPED"

    # A terminated sandbox cannot be reused: no new command execution may be queued on it.
    # AWS keeps the stopped sandbox id known and refuses on its status.
    code, message = _client_error(
        lambda: codebuild.start_command_execution(sandboxId=sandbox_id, command="echo reuse-attempt")
    )
    assert code == "InvalidInputException", (
        f"expected InvalidInputException rejecting the terminated sandbox, got {code!r}"
    )
    expected = "Command execution cannot be started if sandbox status is STOPPED"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the sandbox must still show as STOPPED, not silently reactivated.
    still_stopped = codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]
    assert still_stopped["status"] == "STOPPED"

    # Effect absent: the rejected reuse attempt left no new command execution recorded.
    after_ids = {
        ce["id"]
        for ce in codebuild.list_command_executions_for_sandbox(sandboxId=sandbox_id)["commandExecutions"]
    }
    assert after_ids == before_ids, (
        f"a command execution leaked after the rejected reuse attempt: {after_ids - before_ids}"
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

    # CodeBuild's control plane can lag the IAM role/policy write it just observed,
    # so retry create_project on InvalidInputException until the role has propagated.
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
