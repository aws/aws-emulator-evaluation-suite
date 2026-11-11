"""task-credentials-dynamic-rolearn-on-legacy-lambda-arn-task-assumes-task-role."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "task-credentials-dynamic-rolearn-on-legacy-lambda-arn-task-assumes-task-role"
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


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A dynamic `Credentials.RoleArn.$` on a legacy Lambda-ARN Task (the function ARN as the
    Resource) assumes the named task role to invoke; without Credentials the same Task runs as
    the execution role, which has no invoke grant, and is denied.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_arn = _create_function(ctx, lam)
    exec_role_arn, exec_role_name = _create_role(ctx, "states.amazonaws.com", [])
    task_role_arn, _ = _create_role(
        ctx, exec_role_arn,
        [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}],
    )
    _put_policy(ctx, iam, exec_role_name, "assume-task-role", [
        {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": task_role_arn}
    ])

    # The legacy integration: Resource IS the function ARN, and the input IS the event
    # (no Payload/FunctionName wrapping); Credentials.RoleArn.$ resolves at runtime.
    definition = json.dumps({
        "StartAt": "InvokeLambda",
        "States": {
            "InvokeLambda": {
                "Type": "Task",
                "Resource": fn_arn,
                "Credentials": {"RoleArn.$": "$.roleArn"},
                "End": True,
            }
        },
    })
    sm_arn = _create_state_machine(ctx, sfn, definition, exec_role_arn, type_="EXPRESS")

    marker = ctx.unique_name("sim2real-mark-")
    final = _run_past_propagation(
        ctx, sfn, sm_arn, {"marker": marker, "roleArn": task_role_arn}
    )
    assert final["status"] == "SUCCEEDED", (
        f"a Task.Credentials.RoleArn.$ invoke must SUCCEED once the task role may be assumed; "
        f"got {final['status']!r} error={final.get('error')!r} cause={final.get('cause')!r}"
    )
    out = json.loads(final["output"])
    assert out == {"ok": True, "echo": {"marker": marker, "roleArn": task_role_arn}}, (
        f"the legacy integration's output IS the function's raw return value, with the "
        f"original event (Credentials.RoleArn.$ included) as the echoed input; got {out!r}"
    )

    # Negative twin: the identical legacy Task without Credentials runs as the execution role,
    # which holds no lambda:InvokeFunction. Its trust already propagated above, so one run decides.
    no_creds_arn = _create_state_machine(ctx, sfn, json.dumps({
        "StartAt": "InvokeLambda",
        "States": {"InvokeLambda": {"Type": "Task", "Resource": fn_arn, "End": True}},
    }), exec_role_arn, type_="EXPRESS")
    denied = sfn.start_sync_execution(
        stateMachineArn=no_creds_arn, name=ctx.unique_name("sim2real-behav-exec-"),
        input=json.dumps({"marker": marker}),
    )
    assert denied["status"] == "FAILED", (
        f"without Credentials the execution role, lacking lambda:InvokeFunction, must be denied; "
        f"got {denied['status']!r} output={denied.get('output')!r}"
    )
    assert denied.get("error") == "Lambda.AWSLambdaException", (
        f"Lambda's 403 surfaces as Lambda.AWSLambdaException; got {denied.get('error')!r} "
        f"cause={denied.get('cause')!r}"
    )
    cause = denied.get("cause") or ""
    partition, account = exec_role_arn.split(":")[1], exec_role_arn.split(":")[4]
    # Only the assumed-role session name and the request id are minted per call; both are masked.
    masked = re.sub(rf"(assumed-role/{re.escape(exec_role_name)}/)[^ ]+", r"\1<session>", cause)
    masked = re.sub(r"Request ID: [^;)]+", "Request ID: <request-id>", masked)
    masked = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", masked)
    assert masked == (
        f"User: arn:{partition}:sts::{account}:assumed-role/{exec_role_name}/<session> is not "
        f"authorized to perform: lambda:InvokeFunction on resource: {fn_arn} because no "
        "identity-based policy allows the lambda:InvokeFunction action (Service: Lambda, "
        "Status Code: 403, Request ID: <request-id>) (SDK Attempt Count: <n>)"
    ), f"the denial must name the execution role's own session and the function; got {cause!r}"
    assert "output" not in denied, f"a denied execution produces no output, got {denied.get('output')!r}"


# ===== helpers =====

def _zip_handler(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", src)
    return buf.getvalue()


def _create_function(ctx, lam) -> str:
    iam = ctx.client("iam")
    fn_role_name = ctx.unique_name("sim2real-behav-tc2-fnrole-")
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

    name = ctx.unique_name("sim2real-behav-tc2-fn-")
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
    """A role trusted either by an AWS service (``"states.amazonaws.com"``) or by another
    role's ARN (any other string), with the given inline policy statements.

    A role ARN just minted by a sibling CreateRole can still be unknown to IAM's own policy
    validator for a few seconds, so CreateRole itself is retried on that one error.
    """
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-tc2-role-")
    principal = {"Service": trust_principal} if "." in trust_principal else {"AWS": trust_principal}
    trust_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": principal, "Action": "sts:AssumeRole"}],
    })
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
    if statements:
        iam.put_role_policy(
            RoleName=name, PolicyName="inline",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"))
    return arn, name


def _put_policy(ctx, iam, role_name: str, policy_name: str, statements: list[dict]) -> None:
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))


def _create_state_machine(ctx, sfn, definition: str, role_arn: str, *, type_: str) -> str:
    name = ctx.unique_name("sim2real-behav-tc2-sm-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type=type_,
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


def _run_past_propagation(ctx, sfn, sm_arn: str, payload: dict, *, rounds: int = 20,
                           interval_s: float = 2.0) -> dict:
    """Run a fresh synchronous EXPRESS execution until one is not a role-propagation artifact."""
    last = None
    for _ in range(rounds):
        last = sfn.start_sync_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-exec-"),
            input=json.dumps(payload),
        )
        blob = (last.get("cause") or "") + (last.get("error") or "")
        if last["status"] != "FAILED" or not any(m in blob for m in _TRUST_MARKERS):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"every one of {rounds} executions on {sm_arn!r} failed on role propagation; "
        f"last status {last.get('status')!r} cause {(last.get('cause') or '')[:300]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
