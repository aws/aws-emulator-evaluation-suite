"""e2e-sandbox-command-execution-after-stop-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-sandbox-command-execution-after-stop-rejected"
GROUP = "e2e"
SERVICES = ["codebuild"]

_SENTINEL = "sim2real-sandbox-control-marker"


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartCommandExecution against a stopped sandbox is rejected; a live sandbox still accepts commands."""
    cb = ctx.client("codebuild")
    sandbox_statements = [
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
        {"Effect": "Allow", "Action": ["ssm:StartSession"], "Resource": "*"},
    ]
    role_arn = _create_codebuild_service_role(ctx, extra_statements=sandbox_statements)
    project_name = ctx.unique_name("sim2real-cb-sandboxneg-")

    def _create_project():
        return cb.create_project(
            name=project_name,
            source={"type": "NO_SOURCE", "buildspec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo noop\n"},
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:7.0",
                "computeType": "BUILD_GENERAL1_SMALL",
            },
            serviceRole=role_arn,
            tags=[{"key": "sim2real", "value": CHECK}],
        )

    _retry_role_propagation(_create_project)
    ctx.on_cleanup(lambda: cb.delete_project(name=project_name))

    sandbox = _retry_role_propagation(lambda: cb.start_sandbox(projectName=project_name))["sandbox"]
    sandbox_id = sandbox["id"]

    _poll_until(
        lambda: cb.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]["status"],
        lambda s: s not in ("PROVISIONING", "QUEUED", "PENDING"),
        timeout_s=300.0,
        interval_s=5.0,
        description=f"sandbox {sandbox_id} to leave PROVISIONING",
    )

    # POSITIVE CONTROL: the live sandbox accepts a real command before we stop it.
    control_exec_id = cb.start_command_execution(
        sandboxId=sandbox_id, command=f"echo {_SENTINEL}", type="SHELL"
    )["commandExecution"]["id"]
    control_final = _poll_until(
        lambda: cb.batch_get_command_executions(
            sandboxId=sandbox_id, commandExecutionIds=[control_exec_id]
        )["commandExecutions"][0],
        lambda ce: ce["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=180.0,
        interval_s=5.0,
        description=f"control command execution {control_exec_id} to finish",
    )
    assert control_final["status"] == "SUCCEEDED", (
        f"positive control command execution against a live sandbox did not succeed: {control_final!r}"
    )

    before_ids = {
        ce["id"]
        for ce in cb.list_command_executions_for_sandbox(sandboxId=sandbox_id)["commandExecutions"]
    }
    assert control_exec_id in before_ids, (
        f"positive control execution {control_exec_id!r} missing from list_command_executions_for_sandbox "
        f"before the negative was attempted: {before_ids!r}"
    )

    # Break exactly one thing: stop the sandbox, then try to run a command against it.
    cb.stop_sandbox(id=sandbox_id)
    _poll_until(
        lambda: cb.batch_get_sandboxes(ids=[sandbox_id])["sandboxes"][0]["status"],
        lambda s: s == "STOPPED",
        timeout_s=120.0,
        interval_s=3.0,
        description=f"sandbox {sandbox_id} to reach STOPPED",
    )

    code, message = _client_error(
        lambda: cb.start_command_execution(
            sandboxId=sandbox_id, command="echo should-not-run", type="SHELL"
        )
    )
    assert code == "InvalidInputException", (
        f"unexpected error code for StartCommandExecution against a stopped sandbox: {code!r}"
    )
    assert message == "Command execution cannot be started if sandbox status is STOPPED", message

    # Effect absent: no new command execution was recorded for the stopped sandbox.
    after_ids = {
        ce["id"]
        for ce in cb.list_command_executions_for_sandbox(sandboxId=sandbox_id)["commandExecutions"]
    }
    assert after_ids == before_ids, f"a command execution leaked after StartCommandExecution was rejected: {after_ids - before_ids}"


def _client_error(fn) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, so a target accepting what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _create_codebuild_service_role(ctx, extra_statements):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cb-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codebuild.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    statements = [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }
    ] + extra_statements
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-cb-policy", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-cb-policy"))
    return role["Role"]["Arn"]


def _retry_role_propagation(fn, timeout_s=90.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "InvalidInputException" and (
                "not authorized" in message or "assume" in message.lower()
            ):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise last_err


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out ({timeout_s}s) waiting for {description}; last observed={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
