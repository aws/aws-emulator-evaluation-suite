"""oversized-lambda-error-cause-truncated-name-still-caught."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "oversized-lambda-error-cause-truncated-name-still-caught"
GROUP = "error_handling"
SERVICES = ["lambda", "stepfunctions"]

_UNDER_SIZE = 2000
_OVER_SIZE = 300 * 1024
_CAUSE_CAP = 32768

_HANDLER_SRC = (
    "def handler(event, context):\n"
    '    raise Exception("x" * int(event["size"]))\n'
)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Lambda task's error message well past the per-state payload quota has its Cause
    silently truncated to 32768 bytes while the error name survives and Catch still matches it.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_role = _create_role(ctx, iam, "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                        "logs:PutLogEvents"], "Resource": "*"},
    ])
    fn_name, fn_arn = _create_function(ctx, lam, fn_role)

    sm_role = _create_role(ctx, iam, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}])

    # ---- direct Task-error path: break exactly the message size ----
    direct_sm = _create_state_machine(ctx, sfn, _direct_definition(fn_arn), sm_role)

    under = _run_to_terminal(ctx, sfn, direct_sm, {"size": _UNDER_SIZE}, timeout_s=150)
    assert under["status"] == "SUCCEEDED", (
        f"positive control: a {_UNDER_SIZE}-byte error must be caught by name and SUCCEED via "
        f"the Catch transition, got {under['status']!r}"
    )
    under_out = json.loads(under["output"])
    assert under_out["Error"] == "Exception", f"caught error name was {under_out!r}"
    under_cause = json.loads(under_out["Cause"])
    assert under_cause["errorMessage"] == "x" * _UNDER_SIZE, (
        f"a {_UNDER_SIZE}-byte message under the 32768 cap must reach the Catch intact, got "
        f"length {len(under_cause['errorMessage'])!r}"
    )

    over = _run_to_terminal(ctx, sfn, direct_sm, {"size": _OVER_SIZE}, timeout_s=90)
    assert over["status"] == "SUCCEEDED", (
        f"a {_OVER_SIZE}-byte error, well past the 256 KiB state payload quota, must still be "
        f"caught by name and SUCCEED via the Catch transition, got {over['status']!r}"
    )
    over_out = json.loads(over["output"])
    assert over_out["Error"] == "Exception", (
        f"the error name must survive truncation unchanged; got {over_out.get('Error')!r}"
    )
    over_cause = over_out["Cause"]
    assert len(over_cause) == _CAUSE_CAP, (
        f"a cause past the 256 KiB quota is truncated to exactly {_CAUSE_CAP} bytes, not "
        f"rejected or passed through whole; got {len(over_cause)!r} bytes"
    )
    assert over_cause.endswith("..."), (
        f"a truncated cause ends with '...'; got {over_cause[-10:]!r}"
    )
    assert over_cause.startswith('{"errorMessage":"' + "x" * 10), (
        f"the truncated cause must still start with the real payload; got {over_cause[:40]!r}"
    )


def _direct_definition(fn_arn: str) -> str:
    """A Task whose Lambda raises, caught by exact error name so the surviving Cause is visible
    as the execution's own output."""
    return json.dumps({
        "StartAt": "Invoke",
        "States": {
            "Invoke": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
                "Catch": [{"ErrorEquals": ["Exception"], "Next": "Caught"}],
                "End": True,
            },
            "Caught": {"Type": "Pass", "End": True},
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

def _run_to_terminal(ctx, sfn, sm_arn, payload, *, timeout_s: float):
    """Start one execution and poll DescribeExecution every 2s to a terminal status, retrying the
    start itself while the state machine's role is not yet assumable by Step Functions."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-behav-x-"),
            input=json.dumps(payload),
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
