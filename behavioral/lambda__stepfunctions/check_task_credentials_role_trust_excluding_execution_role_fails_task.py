"""task-credentials-role-trust-excluding-execution-role-fails-task."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "task-credentials-role-trust-excluding-execution-role-fails-task"
GROUP = "task-credentials"
SERVICES = ["lambda", "stepfunctions"]

_HANDLER_SRC = (
    "def handler(event, context):\n"
    "    return {'ok': True, 'echo': event}\n"
)

_TRUST_MARKERS = (
    "not authorized to assume", "AccessDenied", "is not authorized to perform",
    "UnrecognizedClientException", "security token included in the request is invalid",
)


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Task's `Credentials.RoleArn` whose trust excludes the execution role fails as
    States.TaskFailed with the not-authorized-to-assume cause naming both roles; a twin whose
    trust allows the execution role succeeds.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_arn = _create_function(ctx, lam)
    exec_role_arn, exec_role_name = _create_role(ctx, "states.amazonaws.com", [])

    # Two task roles, same invoke permission, differing only in who may assume them.
    good_role_arn, _ = _create_task_role(ctx, fn_arn, principal_arn=exec_role_arn)
    excluded_role_arn, _ = _create_task_role(ctx, fn_arn, principal_arn=_unrelated_role_arn(ctx))

    _put_policy(ctx, iam, exec_role_name, "assume-task-roles", [
        {"Effect": "Allow", "Action": "sts:AssumeRole",
         "Resource": [good_role_arn, excluded_role_arn]}
    ])

    good_sm = _create_state_machine(ctx, sfn, _definition(fn_arn, good_role_arn), exec_role_arn)
    excluded_sm = _create_state_machine(
        ctx, sfn, _definition(fn_arn, excluded_role_arn), exec_role_arn)

    # --- Positive control: a trust that simply allows the execution role succeeds -------
    marker = ctx.unique_name("sim2real-mark-")
    good = _run_past_propagation(ctx, sfn, good_sm, {"marker": marker})
    assert good["status"] == "SUCCEEDED", (
        f"the correctly-trusted twin must SUCCEED; got {good['status']!r} "
        f"error={good.get('error')!r} cause={good.get('cause')!r}"
    )

    want_cause_excluded = (
        f"The role {exec_role_arn} is not authorized to assume the task state's role, "
        f"{excluded_role_arn}."
    )
    excluded = _run_denied(ctx, sfn, excluded_sm, {"marker": marker})
    assert excluded["status"] == "FAILED", (
        f"a task role whose trust excludes the execution role must FAIL; got "
        f"{excluded['status']!r} error={excluded.get('error')!r} cause={excluded.get('cause')!r}"
    )
    assert excluded.get("error") == "States.TaskFailed", (
        f"a refused task-role assumption surfaces as States.TaskFailed; got "
        f"{excluded.get('error')!r} cause={excluded.get('cause')!r}"
    )
    assert excluded.get("cause") == want_cause_excluded, (
        f"expected cause {want_cause_excluded!r}; got {excluded.get('cause')!r}"
    )
    assert "output" not in excluded, (
        f"a denied execution produces no output; got {excluded.get('output')!r}"
    )


# ===== helpers =====

def _definition(fn_arn: str, task_role_arn: str) -> str:
    return json.dumps({
        "StartAt": "InvokeLambda",
        "States": {
            "InvokeLambda": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Credentials": {"RoleArn": task_role_arn},
                "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
                "End": True,
            }
        },
    })


def _zip_handler(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", src)
    return buf.getvalue()


def _create_function(ctx, lam) -> str:
    iam = ctx.client("iam")
    fn_role_name = ctx.unique_name("sim2real-behav-tc3-fnrole-")
    fn_role_arn = iam.create_role(
        RoleName=fn_role_name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=fn_role_name))
    iam.put_role_policy(
        RoleName=fn_role_name, PolicyName="logs",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow",
             "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
             "Resource": "*"}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=fn_role_name, PolicyName="logs"))

    name = ctx.unique_name("sim2real-behav-tc3-fn-")
    deadline = time.monotonic() + 180.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=fn_role_arn,
                Handler="handler.handler", Code={"ZipFile": _zip_handler(_HANDLER_SRC)},
                MemorySize=128, Timeout=15, Tags={"sim2real": CHECK[:250]},
            )["FunctionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last = exc
            time.sleep(4.0)
            continue
        ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
        ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
        lam.get_waiter("function_active_v2").wait(
            FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
        return arn
    raise AssertionError(f"CreateFunction never stopped denying the fresh role: {last!r}")


def _reap_log_group(ctx, name: str, *, reads: int = 4, interval_s: float = 2.0,
                    budget_s: float = 120.0) -> None:
    logs = ctx.client("logs")
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        exists = any(
            g["logGroupName"] == name
            for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name)
            for g in page.get("logGroups") or []
        )
        if exists:
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name!r} still coming back after {budget_s}s of deletes")
            time.sleep(interval_s)


def _create_role(ctx, trust_principal: str, statements: list[dict]) -> tuple[str, str]:
    """A role trusted by an AWS service, with the given inline policy statements."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-tc3-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_principal},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    if statements:
        iam.put_role_policy(
            RoleName=name, PolicyName="inline",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return arn, name


def _create_task_role(ctx, fn_arn: str, *, principal_arn: str) -> tuple[str, str]:
    """A role that can invoke the function, trusted only by ``principal_arn``.

    A role ARN just minted by a sibling CreateRole can still be unknown to IAM's own policy
    validator for a few seconds, so CreateRole itself is retried on that one error.
    """
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-tc3-taskrole-")
    statement = {"Effect": "Allow", "Principal": {"AWS": principal_arn}, "Action": "sts:AssumeRole"}
    trust_doc = json.dumps({"Version": "2012-10-17", "Statement": [statement]})
    deadline = time.monotonic() + 60.0
    while True:
        try:
            arn = iam.create_role(
                RoleName=name, AssumeRolePolicyDocument=trust_doc,
                Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
            )["Role"]["Arn"]
            break
        except ClientError as exc:
            if (exc.response["Error"]["Code"] != "MalformedPolicyDocument"
                    or "Invalid principal" not in exc.response["Error"]["Message"]
                    or time.monotonic() >= deadline):
                raise
            time.sleep(2.0)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="invoke",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="invoke"))
    return arn, name


def _unrelated_role_arn(ctx) -> str:
    """A real role, trusted by nothing related to this check, used only as the WRONG
    principal a task role's trust can name instead of the execution role."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-tc3-unrelated-")
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


def _put_policy(ctx, iam, role_name: str, policy_name: str, statements: list[dict]) -> None:
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))


def _create_state_machine(ctx, sfn, definition: str, role_arn: str) -> str:
    name = ctx.unique_name("sim2real-behav-tc3-sm-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied after 120s: {last!r}")


def _wait_terminal(ctx, sfn, exec_arn: str, *, timeout_s: float = 90.0, interval_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(interval_s)
    raise AssertionError(f"execution {exec_arn} still RUNNING after {timeout_s}s: {last!r}")


def _run_past_propagation(ctx, sfn, sm_arn: str, payload: dict, *, rounds: int = 20,
                           interval_s: float = 2.0) -> dict:
    """Start fresh executions until one is not a role-propagation artifact (the execution
    role's own trust, or its freshly granted sts:AssumeRole on the task role)."""
    last = None
    for _ in range(rounds):
        arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(payload),
        )["executionArn"]
        last = _wait_terminal(ctx, sfn, arn)
        blob = (last.get("cause") or "") + (last.get("error") or "")
        if last["status"] != "FAILED" or not any(m in blob for m in _TRUST_MARKERS):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"every one of {rounds} executions on {sm_arn!r} failed on role propagation; "
        f"last status {last.get('status')!r} cause {(last.get('cause') or '')[:300]!r}"
    )


def _run_denied(ctx, sfn, sm_arn: str, payload: dict, *, rounds: int = 10,
                interval_s: float = 2.0) -> dict:
    """Start fresh executions until the failure is the permanent denial under test rather
    than the execution role's own trust-propagation artifact, which looks identical in
    status but carries a different cause (naming the execution role's own ARN as the one
    that could not be assumed, not the task role's)."""
    last = None
    for _ in range(rounds):
        arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(payload),
        )["executionArn"]
        last = _wait_terminal(ctx, sfn, arn)
        if last["status"] == "FAILED" and "task state's role" in (last.get("cause") or ""):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"every one of {rounds} executions on {sm_arn!r} never reached the task-role denial "
        f"under test; last status {last.get('status')!r} cause {(last.get('cause') or '')[:300]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
