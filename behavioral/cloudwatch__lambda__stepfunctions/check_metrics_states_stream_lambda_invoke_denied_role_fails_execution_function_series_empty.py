"""metrics-states-stream-lambda-invoke-denied-role-fails-execution-function-series-empty."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-states-stream-lambda-invoke-denied-role-fails-execution-function-series-empty"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda", "stepfunctions"]

_METRIC_BUDGET_S = 600.0
_POLL_S = 2.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """A state machine whose role lacks lambda:InvokeFunction fails with Lambda.AWSLambdaException and
    never moves the function's Succeeded/Invocations series, while a granted control moves them;
    granting the permission then lets the same machine succeed.
    """
    sfn = ctx.client("stepfunctions")
    cw = ctx.client("cloudwatch")
    iam = ctx.client("iam")

    ctrl_arn, ctrl_name = _function(ctx, "ctrl-")
    subj_arn, subj_name = _function(ctx, "deny-")
    ctrl_role = _states_role(ctx, invoke=[ctrl_arn, ctrl_arn + ":*"])
    deny_name, deny_role = _role(ctx, "sim2real-behav-sfnlam-deny-", "states.amazonaws.com")
    _warm(ctx, sfn, ctrl_role, _alias(ctx, ctrl_name))
    ctrl_sm = _state_machine(ctx, sfn, ctrl_role, _definition(ctrl_arn), "ctrl-")
    deny_sm = _state_machine(ctx, sfn, deny_role, _definition(subj_arn), "deny-")

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    ctrl = _wait_terminal(sfn, _start(ctx, sfn, ctrl_sm, {"mode": "ok", "n": 7}))
    assert ctrl["status"] == "SUCCEEDED", f"control execution ended {ctrl['status']!r}: {ctrl!r}"
    denied = _wait_terminal(sfn, _start(ctx, sfn, deny_sm, {"mode": "ok", "n": 7}))
    assert denied["status"] == "FAILED", (
        f"an execution whose role cannot invoke the function must FAIL; got {denied['status']!r}"
    )
    assert denied.get("error") == "Lambda.AWSLambdaException", (
        f"denied execution error is {denied.get('error')!r}; expected 'Lambda.AWSLambdaException'"
    )
    # Measured on real AWS: the cause is Lambda's 403 text, "... is not authorized to perform:
    # lambda:InvokeFunction on resource: <function arn> ...".
    assert "not authorized to perform: lambda:InvokeFunction" in (denied.get("cause") or ""), (
        f"denied execution cause does not name the denial: {denied.get('cause')!r}"
    )

    subj_f = [{"Name": "LambdaFunctionArn", "Value": subj_arn}]
    ctrl_f = [{"Name": "LambdaFunctionArn", "Value": ctrl_arn}]
    deny_s = [{"Name": "StateMachineArn", "Value": deny_sm}]
    reads = {
        "ctrl LambdaFunctionsSucceeded": ("AWS/States", "LambdaFunctionsSucceeded", ctrl_f),
        "ctrl Invocations": ("AWS/Lambda", "Invocations",
                             [{"Name": "FunctionName", "Value": ctrl_name}]),
        "deny ExecutionsFailed": ("AWS/States", "ExecutionsFailed", deny_s),
    }
    # The control function's Invocations also carries its one successful warm-up call (through
    # the alias), which lands inside the same window: 2, not 1.
    # MEASURED on real AWS: for the denied function Step Functions still counts the task as
    # Scheduled, Started and Failed (1 each) — the refusal is attributed to the function's series.
    reads.update({
        "deny LambdaFunctionsScheduled": ("AWS/States", "LambdaFunctionsScheduled", subj_f),
        "deny LambdaFunctionsStarted": ("AWS/States", "LambdaFunctionsStarted", subj_f),
        "deny LambdaFunctionsFailed": ("AWS/States", "LambdaFunctionsFailed", subj_f),
    })
    want = {"ctrl LambdaFunctionsSucceeded": 1.0, "ctrl Invocations": 2.0,
            "deny ExecutionsFailed": 1.0, "deny LambdaFunctionsScheduled": 1.0,
            "deny LambdaFunctionsStarted": 1.0, "deny LambdaFunctionsFailed": 1.0}
    got = _poll(lambda: {k: _sum(cw, ns, m, d, window_start) for k, (ns, m, d) in reads.items()},
                lambda r: r == want, f"control and denied-machine sums to reach {want!r}")

    absent = {
        "deny LambdaFunctionsSucceeded": ("AWS/States", "LambdaFunctionsSucceeded", subj_f),
        "deny ExecutionsSucceeded": ("AWS/States", "ExecutionsSucceeded", deny_s),
        "deny Invocations": ("AWS/Lambda", "Invocations",
                             [{"Name": "FunctionName", "Value": subj_name}]),
    }
    # AWS publishes the untouched counters in the same batch as the moved ones, so one read past
    # the moved-counter barrier is the contrast.
    seen = {k: _stats(cw, ns, m, d, window_start, "Sum") for k, (ns, m, d) in absent.items()}
    moved = {k: v for k, v in seen.items() if any(p["Sum"] > 0 for p in v)}
    assert not moved, f"the denied path moved counters it must not: {moved!r} (control {got!r})"

    # Repair the one broken thing; the SAME machine must now reach the function.
    iam.put_role_policy(RoleName=deny_name, PolicyName="invoke", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction",
                       "Resource": [subj_arn]}],
    }))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=deny_name, PolicyName="invoke"))
    deadline = time.monotonic() + 180.0
    fixed = None
    while time.monotonic() < deadline:
        fixed = _wait_terminal(sfn, _start(ctx, sfn, deny_sm, {"mode": "ok", "n": 9}))
        if fixed["status"] == "SUCCEEDED":
            break
        time.sleep(5.0)  # the repaired grant is propagating; the retry is the wait
    assert fixed and fixed["status"] == "SUCCEEDED", (
        f"after granting lambda:InvokeFunction the same machine still fails: {fixed!r}"
    )
    assert json.loads(fixed["output"]) == {"echo": 9}, f"repaired output {fixed.get('output')!r}"


# ===== helpers =====

_CODE = (
    "def handler(event, context):\n"
    "    if event.get('mode') == 'boom':\n"
    "        raise ValueError('deliberate failure')\n"
    "    return {'echo': event.get('n')}\n"
)


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _CODE)
    return buf.getvalue()


def _trust(service: str) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]})


def _role(ctx, prefix: str, service: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name(prefix)
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_trust(service),
        Description="sim2real sfn lambda metrics", Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, arn


def _states_role(ctx, invoke: list) -> str:
    iam = ctx.client("iam")
    name, arn = _role(ctx, "sim2real-behav-sfnlam-role-", "states.amazonaws.com")
    iam.put_role_policy(RoleName=name, PolicyName="invoke", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": invoke}],
    }))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="invoke"))
    return arn


def _reap_log_group(logs, group: str) -> None:
    """A buffered invocation can recreate the group after delete, so reap in a bounded loop."""
    quiet = 0
    for _ in range(8):
        try:
            logs.delete_log_group(logGroupName=group)
            quiet = 0
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            quiet += 1
            if quiet >= 3:
                return
        time.sleep(5.0)
    raise RuntimeError(f"log group {group} kept reappearing")


def _function(ctx, suffix: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    _, role_arn = _role(ctx, "sim2real-behav-sfnlam-fnrole-", "lambda.amazonaws.com")
    name = ctx.unique_name("sim2real-behav-sfnlam-fn-" + suffix)
    # Registered BEFORE the create so LIFO runs it after delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + 120.0
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": _zip()}, Timeout=30, MemorySize=128,
                Tags={"sim2real": "1"},
            )["FunctionArn"]
            break
        except ClientError as exc:
            if (exc.response["Error"]["Code"] != "InvalidParameterValueException"
                    or time.monotonic() > deadline):
                raise
            time.sleep(5.0)  # the fresh execution role is not yet assumable by Lambda
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return arn, name


def _alias(ctx, fn_name: str) -> str:
    lam = ctx.client("lambda")
    arn = lam.create_alias(FunctionName=fn_name, Name="warm", FunctionVersion="$LATEST")["AliasArn"]
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=fn_name, Name="warm"))
    return arn


def _definition(resource: str) -> str:
    return json.dumps({"StartAt": "Call", "States": {
        "Call": {"Type": "Task", "Resource": resource, "End": True}}})


def _state_machine(ctx, sfn, role_arn: str, definition: str, suffix: str) -> str:
    name = ctx.unique_name("sim2real-behav-sfnlam-" + suffix)
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(5.0)  # IAM propagation of the fresh role: no observable to poll
    raise AssertionError(f"CreateStateMachine AccessDenied for 120s after role create: {last}")


def _warm(ctx, sfn, role_arn: str, alias_arn: str) -> None:
    sm = _state_machine(ctx, sfn, role_arn, _definition(alias_arn), "warm-")
    deadline = time.monotonic() + 180.0
    last = None
    while time.monotonic() < deadline:
        last = _wait_terminal(sfn, _start(ctx, sfn, sm, {"mode": "ok", "n": 0}))
        if last["status"] == "SUCCEEDED":
            return
        time.sleep(5.0)  # the invoke grant is still propagating; the retry is the wait
    raise AssertionError(f"warm-up through {alias_arn} never succeeded in 180s: {last!r}")


def _start(ctx, sfn, sm_arn: str, payload: dict) -> str:
    arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(payload))["executionArn"]
    ctx.on_cleanup(lambda: _stop_quiet(sfn, arn))
    return arn


def _stop_quiet(sfn, arn: str) -> None:
    if sfn.describe_execution(executionArn=arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=arn)


def _wait_terminal(sfn, arn: str, timeout_s: float = 180.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(1.0)
    raise AssertionError(f"execution {arn} still RUNNING after {timeout_s}s: {last!r}")


def _stats(cw, ns: str, metric: str, dims: list, start, stat: str) -> list:
    return cw.get_metric_statistics(
        Namespace=ns, MetricName=metric, Dimensions=dims, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2), Period=60,
        Statistics=[stat],
    )["Datapoints"]


def _sum(cw, ns: str, metric: str, dims: list, start) -> float:
    return float(sum(d["Sum"] for d in _stats(cw, ns, metric, dims, start, "Sum")))


def _poll(read, done, what: str):
    deadline = time.monotonic() + _METRIC_BUDGET_S
    last = None
    while time.monotonic() < deadline:
        last = read()
        if done(last):
            return last
        time.sleep(_POLL_S)
    raise AssertionError(f"timed out after {_METRIC_BUDGET_S}s waiting for {what}; last {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
