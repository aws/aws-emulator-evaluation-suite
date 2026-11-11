"""parameters-injected-payload-over-the-state-quota-rejected-before-the-task-runs."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameters-injected-payload-over-the-state-quota-rejected-before-the-task-runs"
GROUP = "quota"
SERVICES = ["lambda", "stepfunctions"]

_LIMIT = 262144
# Parameters.$ expansion adds the fixed JSON scaffolding below; pad sizes are chosen so the
# POST-Parameters input lands just under and just over _LIMIT once that scaffolding is counted.
_UNDER_PAD = _LIMIT - 2048 - 40
_OVER_PAD = _LIMIT + 1024

_HANDLER_SRC = (
    "def handler(event, context):\n"
    "    return {'got_len': len(event.get('pad', ''))}\n"
)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Task's Parameters injecting a literal payload that pushes the POST-Parameters input
    over the 256 KiB state payload quota fails with States.DataLimitExceeded before the task
    ever runs, while an injected payload just under the quota reaches the task intact.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_role = _create_role(ctx, iam, "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                        "logs:PutLogEvents"], "Resource": "*"}])
    fn_name, fn_arn = _create_function(ctx, lam, fn_role)
    sm_role = _create_role(ctx, iam, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}])

    under_sm = _create_state_machine(ctx, sfn, _definition(fn_arn, _UNDER_PAD), sm_role)
    ok = _run_to_terminal(ctx, sfn, under_sm, timeout_s=150)
    assert ok["status"] == "SUCCEEDED", (
        f"positive control: an injected payload under the quota must reach the task and "
        f"succeed, got {ok['status']!r} error={ok.get('error')!r} cause={ok.get('cause')!r}"
    )
    assert json.loads(ok["output"])["got_len"] == _UNDER_PAD, (
        f"the task's own view of the injected payload was {json.loads(ok['output'])!r}"
    )
    ok_events = [e["type"] for e in _history(sfn, ok["executionArn"])]
    assert "TaskScheduled" in ok_events, (
        f"the positive control must actually schedule the task; got {ok_events!r}"
    )

    over_sm = _create_state_machine(ctx, sfn, _definition(fn_arn, _OVER_PAD), sm_role)
    bad = _run_to_terminal(ctx, sfn, over_sm, timeout_s=90)
    assert bad["status"] == "FAILED", (
        f"an injected payload over the quota must FAIL the execution, got {bad['status']!r}"
    )
    assert bad.get("error") == "States.DataLimitExceeded", (
        f"expected States.DataLimitExceeded, got {bad.get('error')!r} ({bad.get('cause')!r})"
    )
    expected_cause = (
        "The state/task 'Invoke' provided parameters with a size exceeding the maximum number "
        "of bytes service limit."
    )
    assert bad.get("cause") == expected_cause, (
        f"expected cause {expected_cause!r}, got {bad.get('cause')!r}"
    )
    bad_events = [e["type"] for e in _history(sfn, bad["executionArn"])]
    assert "TaskScheduled" not in bad_events, (
        f"Parameters processing must fail BEFORE the task is ever scheduled, so no "
        f"TaskScheduled may appear; got {bad_events!r}"
    )


def _definition(fn_arn: str, pad_size: int) -> str:
    """One Task whose Parameters injects a literal 'pad' string of ``pad_size`` bytes,
    independent of whatever the execution's own (tiny) input holds."""
    return json.dumps({
        "StartAt": "Invoke",
        "States": {"Invoke": {
            "Type": "Task",
            "Resource": "arn:aws:states:::lambda:invoke",
            "Parameters": {"FunctionName": fn_arn, "Payload": {"pad": "x" * pad_size}},
            "ResultSelector": {"got_len.$": "$.Payload.got_len"},
            "End": True,
        }},
    })


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


def _create_function(ctx, lam, role_arn):
    """Create a 128MB python3.12 inline-zip function, retrying while a fresh role is not yet
    assumable by Lambda."""
    name = ctx.unique_name("sim2real-behav-fn-")
    deadline = time.monotonic() + _FN_CREATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="handler.handler", Code={"ZipFile": _zip_handler(_HANDLER_SRC)},
                Timeout=20, MemorySize=128, Tags={"sim2real": CHECK},
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
        inner_deadline = time.monotonic() + 60.0
        while True:
            last = sfn.describe_execution(executionArn=exec_arn)
            if last["status"] != "RUNNING":
                break
            if time.monotonic() >= inner_deadline:
                raise AssertionError(f"execution {exec_arn} still RUNNING after 60s: {last!r}")
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
