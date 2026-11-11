"""command-execution-lifecycle-in-sandbox."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "command-execution-lifecycle-in-sandbox"
GROUP = "state-machine"
SERVICES = ["codebuild"]

_BUILDSPEC = """version: 0.2
phases:
  build:
    commands:
      - echo "sim2real command execution sandbox project"
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A command execution submitted to an ACTIVE sandbox progresses to a terminal status
    observable via BatchGetCommandExecutions, with the process's real stdout/exit code
    surfaced -- both for a command that succeeds and one that deliberately fails."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_codebuild_role(ctx, extra_statements=_SSM_STATEMENTS)
    project_name = ctx.unique_name("sim2real-cbcmdexec-")
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
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))
    # A sandbox with no explicit logsConfig makes the service create /aws/codebuild/<project>
    # asynchronously; left uncleaned otherwise.
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda: _safe_delete_log_group(logs, f"/aws/codebuild/{project_name}"))

    sandbox_id = codebuild.start_sandbox(projectName=project_name)["sandbox"]["id"]
    ctx.on_cleanup(lambda: _safe_stop_sandbox(codebuild, sandbox_id))

    def sandbox_status():
        got = codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"]
        return got[0]["status"] if got else None

    active_status = _poll_until(
        sandbox_status,
        lambda s: s not in (None, "PROVISIONING", "REQUESTED", "QUEUED", "STARTING"),
        timeout_s=300,
        interval_s=10,
    )
    assert active_status in ("ACTIVE", "RUNNING", "IN_PROGRESS"), f"status={active_status}"

    def command_result(exec_id):
        def probe():
            got = codebuild.batch_get_command_executions(
                sandboxId=sandbox_id, commandExecutionIds=[exec_id]
            )["commandExecutions"]
            return got[0] if got else None

        result = _poll_until(
            probe, lambda ce: ce is not None and ce["status"] in ("SUCCEEDED", "FAILED"), timeout_s=120, interval_s=5
        )
        return result

    marker = ctx.unique_name("sim2real-marker-")
    ok_id = codebuild.start_command_execution(
        sandboxId=sandbox_id, command=f"echo {marker}", type="SHELL"
    )["commandExecution"]["id"]
    ok_result = command_result(ok_id)
    assert ok_result["status"] == "SUCCEEDED", f"expected SUCCEEDED, got {ok_result['status']}"
    assert ok_result["exitCode"] == "0", f"expected exit code 0, got {ok_result['exitCode']}"
    assert marker in ok_result.get("standardOutputContent", ""), "echoed marker missing from stdout"

    fail_id = codebuild.start_command_execution(sandboxId=sandbox_id, command="exit 7", type="SHELL")[
        "commandExecution"
    ]["id"]
    fail_result = command_result(fail_id)
    assert fail_result["status"] == "FAILED", f"expected FAILED, got {fail_result['status']}"
    assert fail_result["exitCode"] == "7", f"expected exit code 7, got {fail_result['exitCode']}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _create_codebuild_role(ctx, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
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


def _safe_delete_log_group(logs, group_name):
    try:
        logs.delete_log_group(logGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
