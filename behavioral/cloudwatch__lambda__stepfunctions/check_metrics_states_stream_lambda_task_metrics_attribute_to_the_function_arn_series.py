"""metrics-states-stream-lambda-task-metrics-attribute-to-the-function-arn-series."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-states-stream-lambda-task-metrics-attribute-to-the-function-arn-series"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda", "stepfunctions"]

_METRIC_BUDGET_S = 600.0
_POLL_S = 2.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """A Task whose Resource is a function ARN is counted by AWS/States under exactly
    [LambdaFunctionArn] (Scheduled 2, Started 2, Succeeded 1, Failed 1, two RunTime samples), with
    the execution counters under [StateMachineArn] and no family crossing to the other dimension.
    """
    sfn = ctx.client("stepfunctions")
    cw = ctx.client("cloudwatch")

    fn_arn, fn_name = _function(ctx, "subj-")
    role_arn = _states_role(ctx, invoke=[fn_arn, fn_arn + ":*"])
    alias_arn = _alias(ctx, fn_name)
    # Warm the role's lambda:InvokeFunction grant through the ALIAS ARN, which is its own
    # LambdaFunctionArn series, so propagation retries never touch the series under test.
    _warm(ctx, sfn, role_arn, alias_arn)
    sm_arn = _state_machine(ctx, sfn, role_arn, _definition(fn_arn), "sm-")

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    ok = _wait_terminal(sfn, _start(ctx, sfn, sm_arn, {"mode": "ok", "n": 41}))
    assert ok["status"] == "SUCCEEDED", f"ok execution ended {ok['status']!r}: {ok!r}"
    assert json.loads(ok["output"]) == {"echo": 41}, (
        f"execution output {ok.get('output')!r} is not the function's return {{'echo': 41}}"
    )
    bad = _wait_terminal(sfn, _start(ctx, sfn, sm_arn, {"mode": "boom", "n": 0}))
    assert bad["status"] == "FAILED", f"boom execution ended {bad['status']!r}"
    assert bad.get("error") == "ValueError", (
        f"execution error is {bad.get('error')!r}; expected the function's own 'ValueError'"
    )

    fn_d = [{"Name": "LambdaFunctionArn", "Value": fn_arn}]
    sm_d = [{"Name": "StateMachineArn", "Value": sm_arn}]
    lam_d = [{"Name": "FunctionName", "Value": fn_name}]
    reads = {
        "LambdaFunctionsScheduled": ("AWS/States", fn_d, 2.0),
        "LambdaFunctionsStarted": ("AWS/States", fn_d, 2.0),
        "LambdaFunctionsSucceeded": ("AWS/States", fn_d, 1.0),
        "LambdaFunctionsFailed": ("AWS/States", fn_d, 1.0),
        "ExecutionsSucceeded": ("AWS/States", sm_d, 1.0),
        "ExecutionsFailed": ("AWS/States", sm_d, 1.0),
        "Errors": ("AWS/Lambda", lam_d, 1.0),
    }
    want = {k: v[2] for k, v in reads.items()}
    # Invocations also carries the warm-up call (through the alias, same function), so it is
    # bounded below by the two task invocations rather than pinned. It is published on its own
    # schedule, so it is part of the polled barrier rather than read once after it.
    inv_start = window_start - timedelta(minutes=10)

    def _read():
        r = {k: _sum(cw, ns, k, d, window_start) for k, (ns, d, _) in reads.items()}
        r["Invocations"] = _sum(cw, "AWS/Lambda", "Invocations", lam_d, inv_start)
        return r

    got = _poll(_read, lambda r: {k: r[k] for k in want} == want and r["Invocations"] >= 2.0,
                f"sums to reach {want!r} with AWS/Lambda Invocations >= 2")
    assert {k: got[k] for k in want} == want, f"settled {got!r} != {want!r}"
    assert got["Invocations"] >= 2.0, (
        f"AWS/Lambda Invocations for {fn_name} is {got['Invocations']}; the machine invoked it twice")

    rt = _stats(cw, "AWS/States", "LambdaFunctionRunTime", fn_d, window_start, "SampleCount")
    assert sum(p["SampleCount"] for p in rt) == 2.0, (
        f"LambdaFunctionRunTime under [LambdaFunctionArn] must have 2 samples; got {rt!r}"
    )
    for metric in ("LambdaFunctionsSucceeded", "LambdaFunctionsScheduled"):
        leaked = _stats(cw, "AWS/States", metric, sm_d, window_start, "Sum")
        assert leaked == [], (
            f"{metric} is a LambdaFunctionArn-family metric and must not appear under "
            f"[StateMachineArn]; got {leaked!r}"
        )
    leaked = _stats(cw, "AWS/States", "ExecutionsSucceeded", fn_d, window_start, "Sum")
    assert leaked == [], f"ExecutionsSucceeded leaked under [LambdaFunctionArn]: {leaked!r}"


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
