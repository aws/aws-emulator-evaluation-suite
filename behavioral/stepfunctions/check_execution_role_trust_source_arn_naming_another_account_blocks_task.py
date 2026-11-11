"""execution-role-trust-source-arn-naming-another-account-blocks-task."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execution-role-trust-source-arn-naming-another-account-blocks-task"
GROUP = "permission-boundary"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An execution role whose trust names another account's aws:SourceArn can never be assumed:
    both the STANDARD execution history and the EXPRESS sync response report States.TaskFailed
    with the exact assume-role-denied cause, while a same-account twin succeeds."""
    fn_arn = _lambda_function(ctx)
    foreign_account = "111122223333"

    foreign_role_name, foreign_role_arn = _execution_role(
        ctx, f"arn:aws:states:{ctx.region}:{foreign_account}:stateMachine:*", fn_arn,
    )
    own_role_arn = _execution_role(
        ctx, f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:*", fn_arn,
    )[1]

    definition = _task_definition(fn_arn)
    expected_cause = (
        "The principal states.amazonaws.com is not authorized to assume the provided role. "
        f"(role: {foreign_role_arn})"
    )

    # --- STANDARD: the async execution history reports the failure ---
    std_bad_arn = _create_state_machine(ctx, definition, foreign_role_arn, "STANDARD")
    std_exec = _start_execution(ctx, std_bad_arn)
    std_final = _wait_terminal(ctx, std_exec)
    assert std_final["status"] == "FAILED", (
        f"an execution whose role trusts a foreign account's SourceArn must FAIL; got "
        f"{std_final['status']!r}"
    )
    assert std_final.get("error") == "States.TaskFailed", (
        f"expected error States.TaskFailed, got {std_final.get('error')!r}"
    )
    assert std_final.get("cause") == expected_cause, (
        f"expected cause {expected_cause!r}, got {std_final.get('cause')!r}"
    )

    # --- EXPRESS: the sync response itself reports the failure, with the identical cause ---
    express_bad_arn = _create_state_machine(ctx, definition, foreign_role_arn, "EXPRESS")
    sync_bad = _start_sync_execution(ctx, express_bad_arn)
    assert sync_bad["status"] == "FAILED", (
        f"an EXPRESS sync execution under the same foreign-SourceArn trust must FAIL; got "
        f"{sync_bad['status']!r}"
    )
    assert sync_bad.get("error") == "States.TaskFailed", (
        f"expected error States.TaskFailed, got {sync_bad.get('error')!r}"
    )
    assert sync_bad.get("cause") == expected_cause, (
        f"expected cause {expected_cause!r}, got {sync_bad.get('cause')!r}"
    )

    # --- Positive control: same Lambda and definition, trust names this account instead ---
    std_ok_arn = _create_state_machine(ctx, definition, own_role_arn, "STANDARD")
    ok_exec = _start_execution(ctx, std_ok_arn)
    ok_final = _wait_terminal(ctx, ok_exec)
    assert ok_final["status"] == "SUCCEEDED", (
        f"the twin trusting this account's own SourceArn must SUCCEED; got "
        f"{ok_final['status']!r} cause={ok_final.get('cause')!r}"
    )


def _task_definition(fn_arn: str) -> str:
    return json.dumps({
        "StartAt": "InvokeLambda",
        "States": {
            "InvokeLambda": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
                # The execution role is freshly created; IAM's eventual consistency can make even
                # a CORRECTLY-trusted role's very first assume bounce with States.TaskFailed
                # before the policy has propagated. The foreign-SourceArn negative hits the same
                # error/cause for a permanent reason, so it keeps failing across every retry too.
                "Retry": [{
                    "ErrorEquals": ["States.TaskFailed"],
                    "IntervalSeconds": 2, "MaxAttempts": 4, "BackoffRate": 2.0,
                }],
                "End": True,
            }
        },
    })


def _lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfn-lamrole-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _lambda_function(ctx) -> str:
    lam = ctx.client("lambda")
    role_arn = _lambda_role(ctx)
    name = ctx.unique_name("sim2real-behav-sfn-fn-")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", "def handler(event, context):\n    return {'ok': True}\n")
    deadline = time.monotonic() + 120.0
    last: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            fn_arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": buf.getvalue()}, Timeout=30, Tags={"sim2real": CHECK[:250]},
            )["FunctionArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last = exc
            time.sleep(2.0)
    else:
        raise AssertionError(f"CreateFunction never became possible: {last}")
    ctx.on_cleanup(lambda: _delete_function_and_log_group(ctx, name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return fn_arn


def _execution_role(ctx, source_arn_pattern: str, fn_arn: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfn-exrole-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {"aws:SourceAccount": ctx.account},
                "ArnLike": {"aws:SourceArn": source_arn_pattern},
            },
        }],
    })
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName="invoke-lambda",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="invoke-lambda"))
    return role_name, role_arn


def _create_state_machine(ctx, definition: str, role_arn: str, sm_type: str, timeout_s: float = 90.0) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name(f"sim2real-behav-sfn-{sm_type.lower()}-")
    deadline = time.monotonic() + timeout_s
    last: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3.0)
    else:
        raise AssertionError(f"CreateStateMachine still AccessDenied after {timeout_s}s: {last}")
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn: str) -> str:
    sfn = ctx.client("stepfunctions")
    return sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]


def _start_sync_execution(ctx, sm_arn: str) -> dict:
    sfn = ctx.client("stepfunctions")
    return sfn.start_sync_execution(stateMachineArn=sm_arn, input="{}")


def _wait_terminal(ctx, exec_arn: str, timeout_s: float = 120.0, poll_s: float = 2.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(poll_s)
    raise AssertionError(f"execution {exec_arn} still RUNNING after {timeout_s}s: {last!r}")


def _delete_function_and_log_group(ctx, name: str) -> None:
    """Delete the function AND the log group delete_function leaves behind, re-deleting over a
    bounded window because a late-flushed stream can recreate the group."""
    lam = ctx.client("lambda")
    try:
        lam.delete_function(FunctionName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    logs = ctx.client("logs")
    group = f"/aws/lambda/{name}"
    absent_rounds = 0
    for _ in range(8):
        try:
            logs.delete_log_group(logGroupName=group)
            absent_rounds = 0
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                absent_rounds += 1
                if absent_rounds >= 2:
                    return
            else:
                raise
        time.sleep(3)
    if _log_group_exists(ctx, group):
        raise AssertionError(f"log group {group} kept reappearing and was not reaped")


def _log_group_exists(ctx, group: str) -> bool:
    logs = ctx.client("logs")
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=group):
        for found in page.get("logGroups") or []:
            if found["logGroupName"] == group:
                return True
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
