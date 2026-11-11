"""task-credentials-role-without-invoke-permission-denied."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "task-credentials-role-without-invoke-permission-denied"
GROUP = "authorization"
SERVICES = ["lambda", "stepfunctions"]

_OK_SRC = (
    "def handler(event, context):\n"
    "    return {'ok': True}\n"
)

_NOT_AUTHORIZED_NEEDLE = "is not authorized to perform: lambda:InvokeFunction"
_ASSUME_RACE_NEEDLE = "not authorized to assume the task state's role"
_TOKEN_PROPAGATION_NEEDLE = "UnrecognizedClientException"


def _zip_handler(src: str) -> bytes:
    """One-file deployment package built in memory — no host tooling, no temp files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("handler.py", src)
    return buf.getvalue()


def _make_role(ctx, iam, principal, statements, *, condition=None):
    """One role trusting ``principal`` (a service name or an IAM ARN) with one inline policy.

    Referencing a role just created as another role's trust ``Principal`` races IAM's own
    propagation and answers ``MalformedPolicyDocument`` until it clears.
    """
    name = ctx.unique_name("sim2real-scn-role-")
    key = "Service" if isinstance(principal, str) and principal.endswith(".amazonaws.com") else "AWS"
    stmt = {"Effect": "Allow", "Principal": {key: principal}, "Action": "sts:AssumeRole"}
    if condition:
        stmt["Condition"] = condition
    deadline = time.monotonic() + 60.0
    arn = None
    while True:
        try:
            arn = iam.create_role(
                RoleName=name,
                AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [stmt]}),
                Tags=[{"Key": "sim2real", "Value": "task-credentials-invoke-denied"}],
            )["Role"]["Arn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "MalformedPolicyDocument" or time.monotonic() > deadline:
                raise
            time.sleep(3.0)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    if statements:
        iam.put_role_policy(RoleName=name, PolicyName="inline",
                            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return name, arn


_FN_CREATE_TIMEOUT_S = 240


def _create_function(ctx, lam, src, role_arn):
    """Create an inline-source function, retrying the wait at FIRST USE of a fresh role.

    ``create_function`` right after ``create_role`` fails ``InvalidParameterValueException``
    until the role's trust propagates for Lambda itself to assume it.
    """
    name = ctx.unique_name("sim2real-scn-fn-")
    deadline = time.monotonic() + _FN_CREATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="handler.handler", Code={"ZipFile": _zip_handler(src)},
                Timeout=20, MemorySize=128, Tags={"sim2real": "task-credentials-invoke-denied"},
            )["FunctionArn"]
            ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            lam.get_waiter("function_active_v2").wait(
                FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
            return name, arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last = exc.response["Error"]
            time.sleep(5.0)
    raise AssertionError(f"no Lambda became creatable within {_FN_CREATE_TIMEOUT_S}s; last error {last!r}")


def _reap_log_group(ctx, name: str, *, reads: int = 4, interval_s: float = 2.0,
                    budget_s: float = 120.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it gone."""
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
                    f"log group {name!r} still coming back after {budget_s}s of deletes; "
                    f"{absent} clean read(s) so far"
                )
            time.sleep(interval_s)


def _asl(fn_arn: str, task_role_arn: str) -> str:
    """One Lambda-invoke Task whose Credentials assumes a role distinct from the execution role."""
    return json.dumps({
        "StartAt": "Invoke",
        "States": {"Invoke": {
            "Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
            "Credentials": {"RoleArn": task_role_arn},
            "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
            "End": True,
        }}
    })


def _create_state_machine(ctx, sfn, definition, exec_role_arn):
    name = ctx.unique_name("sim2real-scn-sm-")
    arn = sfn.create_state_machine(
        name=name, definition=definition, roleArn=exec_role_arn, type="EXPRESS",
        tags=[{"key": "sim2real", "value": "task-credentials-invoke-denied"}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return name, arn


def _run_past_assume_race(sfn, sm_arn, *, rounds=20, interval_s=3.0, name_prefix="sim2real-x-"):
    """A fresh same-account role assumption races IAM's own trust-propagation window.

    Retries only while the response is that race, or a freshly-assumed session token not yet
    recognized by Lambda — a second, distinct propagation window — never a bare sleep standing
    in for either; the end is whatever the task's own authorization — under test — decides.
    Raises when the race outlasts the rounds.
    """
    last = None
    for i in range(rounds):
        last = sfn.start_sync_execution(
            stateMachineArn=sm_arn, name=f"{name_prefix}{i}", input="{}")
        cause = last.get("cause") or ""
        if last.get("status") == "FAILED" and (
            _ASSUME_RACE_NEEDLE in cause or _TOKEN_PROPAGATION_NEEDLE in cause
        ):
            time.sleep(interval_s)
            continue
        return last
    raise AssertionError(
        f"executions still failed on IAM propagation after {rounds} rounds: {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Task's ``Credentials.RoleArn`` role lacking ``lambda:InvokeFunction`` fails the task,
    and the cause names that assumed task-role session — never the execution role.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_role_name, fn_role_arn = _make_role(ctx, iam, "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                       "logs:PutLogEvents"], "Resource": "*"}])
    _, fn_arn = _create_function(ctx, lam, _OK_SRC, fn_role_arn)

    exec_role_name, exec_role_arn = _make_role(ctx, iam, "states.amazonaws.com", [])

    granted_task_role_name, granted_task_role_arn = _make_role(
        ctx, iam, exec_role_arn,
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}])
    denied_task_role_name, denied_task_role_arn = _make_role(ctx, iam, exec_role_arn, [])

    iam.put_role_policy(RoleName=exec_role_name, PolicyName="assume-task-roles", PolicyDocument=json.dumps({
        "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole",
        "Resource": [granted_task_role_arn, denied_task_role_arn]}]}))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=exec_role_name, PolicyName="assume-task-roles"))

    _, sm_granted = _create_state_machine(ctx, sfn, _asl(fn_arn, granted_task_role_arn), exec_role_arn)
    _, sm_denied = _create_state_machine(ctx, sfn, _asl(fn_arn, denied_task_role_arn), exec_role_arn)

    # POSITIVE CONTROL: the task role WITH the grant reaches the function and returns its
    # payload, which also clears same-account assume-role propagation for these fresh roles.
    control = _run_past_assume_race(sfn, sm_granted, name_prefix="sim2real-ctl-")
    assert control["status"] == "SUCCEEDED", (
        f"granting lambda:InvokeFunction to the task role must let the task succeed, got "
        f"{control['status']!r} / {control.get('error')!r}: {control.get('cause')!r}"
    )
    assert json.loads(control["output"])["Payload"]["ok"] is True, (
        f"the granted task role must reach the function and return its payload, got "
        f"output {control.get('output')!r}"
    )

    # THE DENIAL.
    got = _run_past_assume_race(sfn, sm_denied, name_prefix="sim2real-den-")
    assert got["status"] == "FAILED", (
        f"a task whose Credentials role cannot invoke the function must fail, got {got['status']!r}"
    )
    assert got["error"] == "Lambda.AWSLambdaException", (
        f"Step Functions surfaces Lambda's 403 as Lambda.AWSLambdaException, got {got['error']!r} "
        f"with cause {(got.get('cause') or '')[:300]!r}"
    )
    cause = got.get("cause") or ""
    partition = exec_role_arn.split(":")[1]
    account = exec_role_arn.split(":")[4]
    # Only the assumed-role session name and the request id are minted per call; both are masked.
    masked = re.sub(rf"(assumed-role/{re.escape(denied_task_role_name)}/)[^ ]+", r"\1<session>", cause)
    masked = re.sub(r"Request ID: [^;)]+", "Request ID: <request-id>", masked)
    assert masked == (
        f"User: arn:{partition}:sts::{account}:assumed-role/{denied_task_role_name}/<session> "
        f"{_NOT_AUTHORIZED_NEEDLE} on resource: {fn_arn} because no identity-based policy allows "
        "the lambda:InvokeFunction action (Service: AWSLambda; Status Code: 403; Error Code: "
        "AccessDeniedException; Request ID: <request-id>; Proxy: null)"
    ), (
        f"the denial must name the ASSUMED TASK-ROLE session (never the execution role "
        f"{exec_role_name}), the missing lambda:InvokeFunction grant and the function; got {cause!r}"
    )
    assert "output" not in got, f"a denied execution produces no output, got {got.get('output')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
