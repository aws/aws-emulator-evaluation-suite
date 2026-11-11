"""sandbox-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sandbox-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["codebuild"]

_BUILDSPEC = """version: 0.2
phases:
  build:
    commands:
      - echo "sim2real sandbox project"
"""

_SSM_STATEMENTS = [
    {
        "Effect": "Allow",
        "Action": [
            "ssmmessages:CreateControlChannel",
            "ssmmessages:CreateDataChannel",
            "ssmmessages:OpenControlChannel",
            "ssmmessages:OpenDataChannel",
        ],
        "Resource": "*",
    },
    {
        "Effect": "Allow",
        "Action": ["ssm:StartSession"],
        "Resource": "*",
    },
]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A sandbox moves PROVISIONING -> RUNNING (visible via ListSandboxes/BatchGetSandboxes),
    accepts command execution while RUNNING, then moves to STOPPED after StopSandbox, at which
    point a further StartCommandExecution against it is rejected (wrong-status transition)."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx, extra_statements=_SSM_STATEMENTS)
    project_name = ctx.unique_name("sim2real-cbsandbox-")
    _create_project_with_retry(
        codebuild,
        name=project_name,
        source={"type": "NO_SOURCE", "buildspec": _BUILDSPEC},
        artifacts={"type": "NO_ARTIFACTS"},
        environment={
            "type": "LINUX_CONTAINER",
            "image": "aws/codebuild/amazonlinux2-x86_64-standard:5.0",
            "computeType": "BUILD_GENERAL1_SMALL",
        },
        serviceRole=role_arn,
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    sandbox = codebuild.start_sandbox(projectName=project_name)["sandbox"]
    sandbox_id = sandbox["id"]
    ctx.on_cleanup(lambda: _safe_stop_sandbox(codebuild, sandbox_id))

    _poll_until(
        lambda: sandbox_id in codebuild.list_sandboxes().get("ids", []),
        lambda present: present,
        timeout_s=60,
        interval_s=3,
    )

    def sandbox_status():
        got = codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"]
        return got[0]["status"] if got else None

    active_status = _poll_until(
        sandbox_status,
        lambda s: s not in (None, "PROVISIONING", "REQUESTED", "QUEUED", "STARTING"),
        timeout_s=300,
        interval_s=10,
    )
    assert active_status == "RUNNING", f"expected sandbox to reach RUNNING, got status={active_status}"

    # --- positive control: a command execution succeeds while the sandbox is ACTIVE ---
    exec_id = codebuild.start_command_execution(
        sandboxId=sandbox_id, command="echo sim2real-sandbox-active", type="SHELL"
    )["commandExecution"]["id"]

    def exec_status():
        got = codebuild.batch_get_command_executions(sandboxId=sandbox_id, commandExecutionIds=[exec_id])[
            "commandExecutions"
        ]
        return got[0]["status"] if got else None

    final_status = _poll_until(exec_status, lambda s: s in ("SUCCEEDED", "FAILED"), timeout_s=120, interval_s=5)
    assert final_status == "SUCCEEDED", f"expected the control command to SUCCEED, got {final_status}"

    before_count = len(
        codebuild.list_command_executions_for_sandbox(sandboxId=sandbox_id).get("commandExecutions", [])
    )

    codebuild.stop_sandbox(id=sandbox_id)
    stopped_status = _poll_until(sandbox_status, lambda s: s == "STOPPED", timeout_s=180, interval_s=5)
    assert stopped_status == "STOPPED", f"expected sandbox to reach STOPPED after StopSandbox, got {stopped_status}"

    # --- break exactly one thing: start a command execution against the now-stopped sandbox ---
    code, message = _client_error(
        lambda: codebuild.start_command_execution(
            sandboxId=sandbox_id, command="echo sim2real-sandbox-after-stop", type="SHELL"
        )
    )
    assert code == "InvalidInputException", f"code={code}"
    expected = "Command execution cannot be started if sandbox status is STOPPED"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no new command execution was recorded against the stopped sandbox
    after_count = len(
        codebuild.list_command_executions_for_sandbox(sandboxId=sandbox_id).get("commandExecutions", [])
    )
    assert after_count == before_count, "a command execution was recorded despite the rejected call"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


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


def _create_codebuild_role(ctx, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    managed_policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy_arn))
    if extra_statements:
        policy_name = f"{role_name}-extra"
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": extra_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_project_with_retry(codebuild, timeout_s=90.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return codebuild.create_project(**kwargs)["project"]
        except codebuild.exceptions.InvalidInputException as exc:
            last_exc = exc
            time.sleep(5)
    raise last_exc


def _safe_stop_sandbox(codebuild, sandbox_id):
    try:
        codebuild.stop_sandbox(id=sandbox_id)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] in ("ResourceNotFoundException",)
            or (exc.response["Error"]["Code"] == "InvalidInputException" and "when the sandbox is STOPPED" in exc.response["Error"].get("Message", ""))
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
