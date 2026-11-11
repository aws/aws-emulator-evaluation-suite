"""obs-sfn-1-optimized-lambda-invoke-denied-and-ok-never-populate-function-arn-series."""
from __future__ import annotations

import io
import json
import math
import time
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-sfn-1-optimized-lambda-invoke-denied-and-ok-never-populate-function-arn-series"
GROUP = "metric-emission"
SERVICES = ["cloudwatch", "lambda", "stepfunctions"]

_SETTLE_BUDGET_S = 420.0
_POLL_S = 2.0
_SLEEP_MS = 1500


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html
@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:e2e",
    "concern:metrics",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c3", "timing:real-time",
)
def run(ctx) -> None:
    """Lambda calls via a direct-ARN Task Resource count in AWS/States LambdaFunctions* by function
    ARN, while allowed and denied lambda:invoke integration calls do not, and the denied ones never
    reach AWS/Lambda Invocations."""
    sfn = ctx.client("stepfunctions")
    cw = ctx.client("cloudwatch")

    lam_role = _role(ctx, "sim2real-behav-obs-sfn-fnrole-", "lambda.amazonaws.com")[1]
    fn_m, name_m = _function(ctx, lam_role, "m-")
    fn_l, name_l = _function(ctx, lam_role, "l-")
    warm_alias = _alias(ctx, name_l)
    grant_name, grant_role = _role(ctx, "sim2real-behav-obs-sfn-role-", "states.amazonaws.com")
    _put_invoke(ctx, grant_name, [fn_m, fn_m + ":*", fn_l, fn_l + ":*"])
    bare_role = _role(ctx, "sim2real-behav-obs-sfn-deny-", "states.amazonaws.com")[1]

    # Warm the grant through L's ALIAS ARN — its own LambdaFunctionArn series — so IAM propagation
    # retries never touch a series under test.
    _warm(ctx, sfn, grant_role, warm_alias)
    opt_sm = _state_machine(ctx, sfn, grant_role, _optimized(fn_m), "opt-")
    deny_sm = _state_machine(ctx, sfn, bare_role, _optimized(fn_m), "deny-")
    leg_sm = _state_machine(ctx, sfn, grant_role, _legacy(fn_l), "leg-")

    window_start = datetime.now(timezone.utc) - timedelta(minutes=2)
    for n in range(3):
        d = _wait_terminal(sfn, _start(ctx, sfn, opt_sm, {"n": n}))
        assert d["status"] == "SUCCEEDED", f"optimized execution {n} ended {d['status']!r}: {d!r}"
        out = json.loads(d["output"])
        assert out.get("Payload") == {"echo": n}, (
            f"optimized lambda:invoke output must wrap the function's return in Payload; got {out!r}")
    for n in range(2):
        d = _wait_terminal(sfn, _start(ctx, sfn, deny_sm, {"n": n}))
        assert d["status"] == "FAILED", f"denied execution {n} must FAIL; got {d['status']!r}"
        assert d.get("error") == "Lambda.AWSLambdaException", (
            f"denied execution error {d.get('error')!r}; expected 'Lambda.AWSLambdaException'")
        assert "lambda:InvokeFunction" in (d.get("cause") or ""), (
            f"denied execution cause does not name the missing permission: {d.get('cause')!r}")
    for n in range(2):
        d = _wait_terminal(sfn, _start(ctx, sfn, leg_sm, {"n": 10 + n}))
        assert d["status"] == "SUCCEEDED", f"legacy execution {n} ended {d['status']!r}: {d!r}"
        assert json.loads(d["output"]) == {"echo": 10 + n}, f"legacy output {d.get('output')!r}"
    t_act = time.monotonic()

    m_d = [{"Name": "LambdaFunctionArn", "Value": fn_m}]
    l_d = [{"Name": "LambdaFunctionArn", "Value": fn_l}]
    want = {
        "L Scheduled": 2.0, "L Started": 2.0, "L Succeeded": 2.0, "L RunTime samples": 2.0,
        "M Scheduled": 0.0, "M Started": 0.0, "M Succeeded": 0.0, "M Failed": 0.0,
        "M Invocations": 3.0, "opt ExecutionsSucceeded": 3.0, "deny ExecutionsFailed": 2.0,
    }

    def _read() -> dict:
        return {
            "L Scheduled": _stat(cw, "AWS/States", "LambdaFunctionsScheduled", l_d, window_start),
            "L Started": _stat(cw, "AWS/States", "LambdaFunctionsStarted", l_d, window_start),
            "L Succeeded": _stat(cw, "AWS/States", "LambdaFunctionsSucceeded", l_d, window_start),
            "L RunTime samples": _stat(cw, "AWS/States", "LambdaFunctionRunTime", l_d,
                                       window_start, "SampleCount"),
            "M Scheduled": _stat(cw, "AWS/States", "LambdaFunctionsScheduled", m_d, window_start),
            "M Started": _stat(cw, "AWS/States", "LambdaFunctionsStarted", m_d, window_start),
            "M Succeeded": _stat(cw, "AWS/States", "LambdaFunctionsSucceeded", m_d, window_start),
            "M Failed": _stat(cw, "AWS/States", "LambdaFunctionsFailed", m_d, window_start),
            "M Invocations": _stat(cw, "AWS/Lambda", "Invocations",
                                   [{"Name": "FunctionName", "Value": name_m}], window_start),
            "opt ExecutionsSucceeded": _stat(cw, "AWS/States", "ExecutionsSucceeded",
                                             [{"Name": "StateMachineArn", "Value": opt_sm}],
                                             window_start),
            "deny ExecutionsFailed": _stat(cw, "AWS/States", "ExecutionsFailed",
                                           [{"Name": "StateMachineArn", "Value": deny_sm}],
                                           window_start),
        }

    _ledger(_read, want, t_act)
    run_min = _stat(cw, "AWS/States", "LambdaFunctionRunTime", l_d, window_start, "Minimum")
    assert run_min >= _SLEEP_MS, (
        f"LambdaFunctionRunTime Minimum for L is {run_min}ms; the function sleeps {_SLEEP_MS}ms")


_CODE = (
    "import time\n"
    "def handler(event, context):\n"
    f"    time.sleep({_SLEEP_MS / 1000.0})\n"
    "    return {'echo': event.get('n')}\n"
)


def _zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", _CODE)
    return buf.getvalue()


def _role(ctx, prefix: str, service: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    name = ctx.unique_name(prefix)
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}]}),
        Description="sim2real obs-sfn metrics ledger", Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return name, arn


def _put_invoke(ctx, role_name: str, resources: list) -> None:
    iam = ctx.client("iam")
    iam.put_role_policy(RoleName=role_name, PolicyName="invoke", PolicyDocument=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "lambda:InvokeFunction",
                       "Resource": resources}],
    }))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="invoke"))


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


def _function(ctx, role_arn: str, suffix: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-obs-sfn-fn-" + suffix)
    # Registered BEFORE the create so LIFO runs it after delete_function.
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/lambda/{name}"))
    deadline = time.monotonic() + 120.0
    while True:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn, Handler="index.handler",
                Code={"ZipFile": _zip()}, Timeout=30, MemorySize=128, Tags={"sim2real": "1"},
            )["FunctionArn"]
            break
        except ClientError as exc:
            if (exc.response["Error"]["Code"] != "InvalidParameterValueException"
                    or time.monotonic() > deadline):
                raise
            time.sleep(5.0)  # the fresh execution role is not yet assumable by Lambda
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    lam.get_waiter("function_active_v2").wait(
        FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    return arn, name


def _alias(ctx, fn_name: str) -> str:
    lam = ctx.client("lambda")
    arn = lam.create_alias(FunctionName=fn_name, Name="warm", FunctionVersion="$LATEST")["AliasArn"]
    ctx.on_cleanup(lambda: lam.delete_alias(FunctionName=fn_name, Name="warm"))
    return arn


def _optimized(fn_arn: str) -> str:
    return json.dumps({"StartAt": "Call", "States": {"Call": {
        "Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
        "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"}, "End": True}}})


def _legacy(resource: str) -> str:
    return json.dumps({"StartAt": "Call", "States": {
        "Call": {"Type": "Task", "Resource": resource, "End": True}}})


def _state_machine(ctx, sfn, role_arn: str, definition: str, suffix: str) -> str:
    name = ctx.unique_name("sim2real-behav-obs-sfn-" + suffix)
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
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
    sm = _state_machine(ctx, sfn, role_arn, _legacy(alias_arn), "warm-")
    deadline = time.monotonic() + 180.0
    last = None
    while time.monotonic() < deadline:
        last = _wait_terminal(sfn, _start(ctx, sfn, sm, {"n": 0}))
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


def _stat(cw, ns: str, metric: str, dims: list, start, stat: str = "Sum") -> float:
    pts = cw.get_metric_statistics(
        Namespace=ns, MetricName=metric, Dimensions=dims, StartTime=start,
        EndTime=datetime.now(timezone.utc) + timedelta(minutes=2), Period=60, Statistics=[stat],
    )["Datapoints"]
    if stat == "Minimum":
        return float(min((p["Minimum"] for p in pts), default=0.0))
    return float(sum(p[stat] for p in pts))


def _ledger(read, want: dict, t_act: float) -> float:
    """Poll to `want` within the settle budget, then hold it for max(3x latency, 60 s)."""
    last = None
    while True:
        last = read()
        if last == want:
            break
        if time.monotonic() - t_act > _SETTLE_BUDGET_S:
            raise AssertionError(
                f"ledger did not reach {want!r} within {_SETTLE_BUDGET_S:.0f}s; last {last!r}")
        time.sleep(_POLL_S)
    latency = time.monotonic() - t_act
    # At least 3x the measured latency rounded up to 10 s, never less than one 60 s period.
    hold_s = max(3.0 * (math.ceil(latency / 10.0) * 10.0), 60.0)
    print(f"[ledger] settled {latency:.0f}s after the last act; holding {hold_s:.0f}s")
    hold_until = time.monotonic() + hold_s
    while time.monotonic() < hold_until:
        time.sleep(_POLL_S)
        now = read()
        assert now == want, (
            f"ledger moved after settling at {latency:.0f}s: {now!r} != {want!r}")
    return latency


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
