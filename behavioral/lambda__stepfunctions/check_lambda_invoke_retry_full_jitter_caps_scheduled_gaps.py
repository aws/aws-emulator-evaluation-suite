"""lambda-invoke-retry-full-jitter-caps-scheduled-gaps."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-invoke-retry-full-jitter-caps-scheduled-gaps"
GROUP = "task_state"
SERVICES = ["lambda", "stepfunctions"]

_INTERVAL_SECONDS = 5
_BACKOFF_RATE = 3.0
_MAX_DELAY_SECONDS = 10
_MAX_ATTEMPTS = 7
# IntervalSeconds * BackoffRate**i, for i in 0..MaxAttempts-1: 5, 15, 45, 135, 405, 1215, 3645.
_UNCAPPED_DELAYS = [_INTERVAL_SECONDS * (_BACKOFF_RATE ** i) for i in range(_MAX_ATTEMPTS)]
# The same delays clamped at MaxDelaySeconds: 5, 10, 10, 10, 10, 10, 10.
_CAPPED_DELAYS = [min(d, _MAX_DELAY_SECONDS) for d in _UNCAPPED_DELAYS]
_SLACK_S = 5.0
# Positions whose uncapped delay lies far above cap+slack, so only a clamp keeps the wait short.
_CLAMPED_POSITIONS = [
    i for i, d in enumerate(_UNCAPPED_DELAYS) if d - _SLACK_S > _MAX_DELAY_SECONDS + _SLACK_S
]

_SCHEDULED_TYPE = "TaskScheduled"
_FAILED_TYPE = "TaskFailed"

_HANDLER_SRC = (
    "def handler(event, context):\n"
    "    raise Exception('sim2real: this handler always raises')\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A lambda:invoke Task's Retry with JitterStrategy FULL and MaxDelaySeconds schedules exactly
    MaxAttempts+1 attempts; every wait lies between 0 and the BackoffRate-grown delay capped at
    MaxDelaySeconds, so the late waits stay far below their uncapped delays.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_role = _create_role(ctx, iam, "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                        "logs:PutLogEvents"], "Resource": "*"}])
    fn_name, fn_arn = _create_function(ctx, lam, _HANDLER_SRC, fn_role)

    sm_role = _create_role(ctx, iam, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}])
    sm_arn = _create_state_machine(ctx, sfn, _definition(fn_arn), sm_role)

    desc = _run_to_terminal(ctx, sfn, sm_arn, timeout_s=300)
    assert desc["status"] == "FAILED", (
        f"a handler that always raises, with no Catch, must leave the execution FAILED once "
        f"retries are exhausted; got {desc['status']!r} error={desc.get('error')!r}"
    )
    assert desc.get("error") == "Exception", (
        f"the surviving error after retry exhaustion must be the handler's own unhandled "
        f"exception class name 'Exception'; got {desc.get('error')!r}"
    )
    cause = json.loads(desc["cause"])
    assert cause["errorMessage"] == "sim2real: this handler always raises", (
        f"the handler's own message must reach the execution verbatim; got {cause!r}"
    )

    events = _history(sfn, desc["executionArn"])
    scheduled = [e for e in events if e["type"] == _SCHEDULED_TYPE]
    failed = [e for e in events if e["type"] == _FAILED_TYPE]
    assert len(scheduled) == _MAX_ATTEMPTS + 1, (
        f"MaxAttempts={_MAX_ATTEMPTS} must produce {_MAX_ATTEMPTS + 1} {_SCHEDULED_TYPE} events "
        f"(1 initial + {_MAX_ATTEMPTS} retries); got {len(scheduled)} out of "
        f"{[e['type'] for e in events]}"
    )
    assert len(failed) == _MAX_ATTEMPTS + 1, (
        f"every one of the {_MAX_ATTEMPTS + 1} attempts must fail (the handler always raises); "
        f"got {len(failed)} {_FAILED_TYPE} events out of {[e['type'] for e in events]}"
    )

    waits = _attempt_gaps(events)
    assert len(waits) == _MAX_ATTEMPTS, (
        f"there must be exactly {_MAX_ATTEMPTS} retry waits between the "
        f"{_MAX_ATTEMPTS + 1} attempts; measured {len(waits)}: {waits}"
    )
    for i, (observed, cap) in enumerate(zip(waits, _CAPPED_DELAYS)):
        assert 0.0 <= observed <= cap + _SLACK_S, (
            f"retry wait #{i + 1} must lie in [0, {cap}s] (the BackoffRate-grown delay clamped "
            f"at MaxDelaySeconds={_MAX_DELAY_SECONDS}) plus {_SLACK_S}s of scheduling slop: "
            f"JitterStrategy FULL only ever shortens the wait, never lengthens it; observed "
            f"{observed:.2f}s. All measured waits: {[round(w, 2) for w in waits]}"
        )
    for i in _CLAMPED_POSITIONS:
        assert waits[i] < _UNCAPPED_DELAYS[i] - _SLACK_S, (
            f"retry wait #{i + 1} must be clamped by MaxDelaySeconds={_MAX_DELAY_SECONDS}s, far "
            f"below the unclamped IntervalSeconds*BackoffRate^{i} = {_UNCAPPED_DELAYS[i]}s; "
            f"observed {waits[i]:.2f}s. All measured waits: {[round(w, 2) for w in waits]}"
        )

def _definition(fn_arn: str) -> str:
    """One Task invoking the always-raising function, retried under FULL jitter with no Catch."""
    return json.dumps({
        "StartAt": "InvokeAlwaysRaises",
        "States": {
            "InvokeAlwaysRaises": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
                "Retry": [{
                    "ErrorEquals": ["States.ALL"],
                    "IntervalSeconds": _INTERVAL_SECONDS,
                    "MaxAttempts": _MAX_ATTEMPTS,
                    "BackoffRate": _BACKOFF_RATE,
                    "MaxDelaySeconds": _MAX_DELAY_SECONDS,
                    "JitterStrategy": "FULL",
                }],
                "End": True,
            }
        },
    })


def _attempt_gaps(events: list[dict]) -> list[float]:
    """Seconds between each attempt's failure and the next attempt's scheduling: the retrier's
    own wait, with the Lambda invocation's own duration excluded by construction."""
    ordered = sorted(events, key=lambda e: e["id"])
    gaps: list[float] = []
    pending_fail = None
    for event in ordered:
        if event["type"] == _FAILED_TYPE:
            pending_fail = event
        elif event["type"] == _SCHEDULED_TYPE and pending_fail is not None:
            gaps.append((event["timestamp"] - pending_fail["timestamp"]).total_seconds())
            pending_fail = None
    return gaps


def _zip_handler(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("handler.py", src)
    return buf.getvalue()


def _create_role(ctx, iam, principal, statements):
    name = ctx.unique_name("sim2real-behav-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": principal},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                                   "Statement": statements}))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity"))
    return arn


_FN_CREATE_TIMEOUT_S = 240


def _create_function(ctx, lam, src, role_arn):
    """Create a 128MB python3.12 inline-zip function, retrying while a fresh role is not yet
    assumable by Lambda."""
    name = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + _FN_CREATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="handler.handler", Code={"ZipFile": _zip_handler(src)},
                Timeout=10, MemorySize=128, Tags={"sim2real": CHECK},
            )["FunctionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last = exc.response["Error"]
            time.sleep(5.0)
            continue
        # LIFO: the log-group reap is registered first so it runs after the function's delete.
        ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
        ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                                 "ResourceNotFoundException"))
        lam.get_waiter("function_active_v2").wait(
            FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
        return name, arn
    raise AssertionError(
        f"no Lambda became creatable within {_FN_CREATE_TIMEOUT_S}s; last error {last!r}"
    )


def _reap_log_group(ctx, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
    logs = ctx.client("logs")
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
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
                    f"log group still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


_SM_CREATE_TIMEOUT_S = 120


def _create_state_machine(ctx, sfn, definition, role_arn):
    """CreateStateMachine, retrying only the AccessDeniedException a fresh role's trust has not
    yet propagated past."""
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + _SM_CREATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=definition, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc.response["Error"]
            time.sleep(3.0)
            continue
        ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn),
                                 "StateMachineDoesNotExist"))
        return arn
    raise AssertionError(
        f"CreateStateMachine still AccessDenied {_SM_CREATE_TIMEOUT_S}s after role creation; "
        f"last error {last!r}"
    )


_RUN_TIMEOUT_S = 120.0
_IAM_RACE_MARKERS = (
    "not authorized to assume",
    "UnrecognizedClientException",
    "security token included in the request is invalid",
)


def _run_to_terminal(ctx, sfn, sm_arn, *, timeout_s: float):
    """Start one execution and poll DescribeExecution every 2s to a terminal status, retrying the
    start itself while the state machine's role is not yet assumable by Step Functions."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-x-"),
            input=json.dumps({"probe": CHECK}),
        )["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: sfn.stop_execution(executionArn=a))
        # 8 attempts plus at most 2+6*4 = 26 s of capped waits, with Lambda cold starts.
        inner_deadline = time.monotonic() + _RUN_TIMEOUT_S
        while True:
            last = sfn.describe_execution(executionArn=exec_arn)
            if last["status"] != "RUNNING":
                break
            if time.monotonic() >= inner_deadline:
                raise AssertionError(
                    f"execution {exec_arn} still RUNNING after {_RUN_TIMEOUT_S}s: {last!r}")
            time.sleep(2.0)
        blob = last.get("cause") or ""
        if last["status"] != "FAILED" or not any(m in blob for m in _IAM_RACE_MARKERS):
            return last
        time.sleep(5.0)
    raise AssertionError(f"execution never left the role-trust race within {timeout_s}s: {last!r}")


def _history(sfn, exec_arn: str) -> list[dict]:
    events: list[dict] = []
    kwargs = {"executionArn": exec_arn}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            return events
        kwargs["nextToken"] = token


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
