"""e2e-sandbox-command-execution-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-sandbox-command-execution-flow"
GROUP = "e2e"
SERVICES = ["codebuild"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartSandbox -> StartCommandExecution -> the execution shows up in
    ListCommandExecutionsForSandbox -> StopSandbox blocks further command submission."""
    codebuild = ctx.client("codebuild")
    role_arn = _create_service_role(ctx)
    project_name = ctx.unique_name("sim2real-cb-sandbox-")

    buildspec = (
        "version: 0.2\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        "      - echo project-ready\n"
    )
    _create_project_with_retry(
        ctx,
        codebuild,
        {
            "name": project_name,
            "source": {"type": "NO_SOURCE", "buildspec": buildspec},
            "artifacts": {"type": "NO_ARTIFACTS"},
            "environment": {
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/amazonlinux-x86_64-standard:5.0",
                "computeType": "BUILD_GENERAL1_SMALL",
            },
            "serviceRole": role_arn,
            "tags": [{"key": "sim2real", "value": CHECK}],
        },
    )
    ctx.on_cleanup(lambda: codebuild.delete_project(name=project_name))

    sandbox = codebuild.start_sandbox(projectName=project_name)["sandbox"]
    sandbox_id = sandbox["id"]

    def _safe_stop_sandbox() -> None:
        try:
            codebuild.stop_sandbox(id=sandbox_id)
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] in ("ResourceNotFoundException",)
                or (exc.response["Error"]["Code"] == "InvalidInputException" and "when the sandbox is STOPPED" in exc.response["Error"].get("Message", ""))
            ):
                raise

    ctx.on_cleanup(_safe_stop_sandbox)

    # The sandbox environment takes time to provision; retry submitting the command until
    # the sandbox reports active (ResourceNotFoundException means "not active yet").
    command_execution = _retry_until_ready(
        lambda: codebuild.start_command_execution(
            sandboxId=sandbox_id, command="echo hello-from-sandbox", type="SHELL"
        )["commandExecution"],
        codebuild,
        timeout_s=300.0,
    )
    exec_id = command_execution["id"]
    assert command_execution["sandboxId"] == sandbox_id, (
        f"expected StartCommandExecution to bind to sandbox {sandbox_id!r}, "
        f"got sandboxId={command_execution['sandboxId']!r}"
    )

    def _probe_listed() -> list:
        resp = codebuild.list_command_executions_for_sandbox(sandboxId=sandbox_id)
        return [c["id"] for c in resp.get("commandExecutions", [])]

    listed_ids = _poll_until(
        _probe_listed, lambda ids: exec_id in ids, timeout_s=60.0, interval_s=3.0
    )
    assert exec_id in listed_ids, (
        f"expected {exec_id!r} in ListCommandExecutionsForSandbox, got {listed_ids!r}"
    )

    # StopSandbox is rejected with InvalidInputException while the sandbox is still in a
    # transient starting state (e.g. QUEUED, STARTING); retry until it's accepted.
    _retry_stop_sandbox(codebuild, sandbox_id, timeout_s=240.0)
    stopped_sandbox = _poll_until(
        lambda: codebuild.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0],
        lambda sbx: sbx.get("endTime") is not None,
        timeout_s=180.0,
        interval_s=3.0,
    )
    assert stopped_sandbox.get("endTime") is not None, (
        f"expected sandbox {sandbox_id!r} to report an endTime once stopped, got {stopped_sandbox!r}"
    )

    code, message = _client_error(
        lambda: codebuild.start_command_execution(
            sandboxId=sandbox_id, command="echo should-fail", type="SHELL"
        )
    )
    assert code == "InvalidInputException", (
        f"expected command submission after StopSandbox to be rejected, got code={code!r}"
    )
    assert message == "Command execution cannot be started if sandbox status is STOPPED", message

    # Effect absent: the rejected submission must not have been recorded against the
    # stopped sandbox — only the earlier, accepted execution shows up.
    after_stop_ids = _probe_listed()
    assert after_stop_ids == listed_ids, (
        f"a command execution leaked after StartCommandExecution was rejected post-StopSandbox: "
        f"before={listed_ids!r} after={after_stop_ids!r}"
    )


def _create_service_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-sbx-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "ssmmessages:CreateControlChannel",
                    "ssmmessages:CreateDataChannel",
                    "ssmmessages:OpenControlChannel",
                    "ssmmessages:OpenDataChannel",
                    "ssm:StartSession",
                ],
                "Resource": "*",
            },
        ],
    }
    policy_name = "sim2real-cb-sbx-inline"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _create_project_with_retry(ctx, codebuild, params, timeout_s: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return codebuild.create_project(**params)["project"]
        except codebuild.exceptions.InvalidInputException as exc:
            last_err = exc
            time.sleep(3.0)
    raise AssertionError(f"CreateProject never succeeded (likely IAM propagation): {last_err}")


def _retry_until_ready(fn, codebuild, timeout_s: float = 300.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except codebuild.exceptions.ResourceNotFoundException as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"sandbox never became active for command execution: {last_err}")


def _retry_stop_sandbox(codebuild, sandbox_id: str, timeout_s: float = 240.0, interval_s: float = 5.0) -> None:
    """StopSandbox rejects with InvalidInputException while the sandbox is still starting
    up (e.g. QUEUED/STARTING); retry until the transient window passes."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            codebuild.stop_sandbox(id=sandbox_id)
            return
        except codebuild.exceptions.InvalidInputException as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"StopSandbox never succeeded: {last_err}")



def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true, last value={value!r}")


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
