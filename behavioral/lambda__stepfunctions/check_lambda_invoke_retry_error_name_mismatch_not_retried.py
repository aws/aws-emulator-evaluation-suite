"""lambda-invoke-retry-error-name-mismatch-not-retried."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-invoke-retry-error-name-mismatch-not-retried"
GROUP = "error_handling"
SERVICES = ["lambda", "stepfunctions"]

_SCHEDULED_TYPE = "TaskScheduled"

_HANDLER_SRC = (
    "def handler(event, context):\n"
    "    raise Exception('sim2real: this handler always raises')\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A Retry naming only a Lambda service-fault code does not match the handler's own
    unhandled-exception error, so the Task retries zero times and fails immediately with it —
    while the identical machine retries to exhaustion once ErrorEquals widens to States.ALL."""
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_role = _create_role(ctx, iam, "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                        "logs:PutLogEvents"], "Resource": "*"}])
    fn_name, fn_arn = _create_function(ctx, lam, _HANDLER_SRC, fn_role)
    sm_role = _create_role(ctx, iam, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}])

    # Negative: the retrier names only a Lambda-service-fault code the handler never raises.
    mismatch_sm = _create_state_machine(
        ctx, sfn, _definition(fn_arn, ["Lambda.TooManyRequestsException"]), sm_role)
    mismatch = _run_to_terminal(ctx, sfn, mismatch_sm, timeout_s=90)
    assert mismatch["status"] == "FAILED", (
        f"an unretried, uncaught Task failure must FAIL the execution; got {mismatch['status']!r}"
    )
    mismatch_error = mismatch.get("error")
    assert mismatch_error == "Exception", (
        f"an unhandled Python exception must surface as the exception class name 'Exception', "
        f"unchanged by a Retry that did not match it; got {mismatch_error!r}"
    )
    mismatch_cause = json.loads(mismatch["cause"])
    assert mismatch_cause["errorMessage"] == "sim2real: this handler always raises", (
        f"the handler's own message must reach the execution verbatim; got {mismatch_cause!r}"
    )
    assert mismatch_cause["errorType"] == "Exception", (
        f"the cause's errorType must be the exception class name; got {mismatch_cause!r}"
    )
    mismatch_scheduled = [
        e for e in _history(sfn, mismatch["executionArn"]) if e["type"] == _SCHEDULED_TYPE
    ]
    assert len(mismatch_scheduled) == 1, (
        f"a Retry naming 'Lambda.TooManyRequestsException' must not match the handler's own "
        f"unhandled-exception error {mismatch_error!r}, so exactly 1 {_SCHEDULED_TYPE} event may "
        f"appear; got {len(mismatch_scheduled)}"
    )

    # Positive control: the identically-shaped machine with States.ALL retries to exhaustion.
    control_sm = _create_state_machine(ctx, sfn, _definition(fn_arn, ["States.ALL"]), sm_role)
    control = _run_to_terminal(ctx, sfn, control_sm, timeout_s=90)
    assert control["status"] == "FAILED", (
        f"retries eventually exhaust and the execution still fails, got {control['status']!r}"
    )
    assert control.get("error") == mismatch_error, (
        f"once retries exhaust, the surviving error must still be the handler's own "
        f"{mismatch_error!r}; got {control.get('error')!r}"
    )
    control_scheduled = [
        e for e in _history(sfn, control["executionArn"]) if e["type"] == _SCHEDULED_TYPE
    ]
    assert len(control_scheduled) == 3, (
        f"States.ALL must match the handler's error and retry MaxAttempts=2 times, i.e. "
        f"3 {_SCHEDULED_TYPE} events (1 initial + 2 retries); got {len(control_scheduled)}"
    )


def _definition(fn_arn: str, error_equals: list[str]) -> str:
    return json.dumps({
        "StartAt": "InvokeAlwaysRaises",
        "States": {
            "InvokeAlwaysRaises": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
                "Retry": [{
                    "ErrorEquals": error_equals,
                    "IntervalSeconds": 1,
                    "MaxAttempts": 2,
                    "BackoffRate": 2,
                }],
                "End": True,
            }
        },
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


def _create_function(ctx, lam, src, role_arn):
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


def _run_to_terminal(ctx, sfn, sm_arn, *, timeout_s: float):
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
        # The handler only raises Exception, so a Lambda.AWSLambdaException (the invoke itself
        # refused while the new roles propagate) or a trust refusal is setup, not the behaviour.
        propagating = "not authorized to assume" in (last.get("cause") or "") or (
            last.get("error") == "Lambda.AWSLambdaException"
        )
        if last["status"] != "FAILED" or not propagating:
            return last
        time.sleep(5.0)
    raise AssertionError(f"execution never left the IAM propagation race in {timeout_s}s: {last!r}")


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
