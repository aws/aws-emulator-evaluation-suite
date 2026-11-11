"""resultselector-path-missing-field-states-runtime."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resultselector-path-missing-field-states-runtime"
GROUP = "input_output_processing"
SERVICES = ["lambda", "stepfunctions"]

_LAMBDA_SRC = (
    "def handler(event, context):\n"
    "    return {'product': 'bananas'}\n"
)
_GOOD_OUTPUT = {"product": "bananas"}


def _definition(fn_arn: str) -> dict:
    """Choice-routed Task states sharing one Lambda invoked by its direct ARN (the raw task
    result is then the function's return value itself, unwrapped), differing only in
    ResultSelector."""
    invoke = {"Type": "Task", "Resource": fn_arn}
    good = dict(invoke, ResultSelector={"product.$": "$.product"}, End=True)
    bad = dict(invoke, ResultSelector={"count.$": "$.count"}, End=True)
    return {
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [{"Variable": "$.mode", "StringEquals": "bad", "Next": "BadInvoke"}],
                "Default": "GoodInvoke",
            },
            "GoodInvoke": good,
            "BadInvoke": bad,
        },
    }


def _zip_handler(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("handler.py", src)
    return buf.getvalue()


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                     budget_s: float = 180.0) -> None:
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent."""
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


def _make_role(ctx, iam, service: str, statements: list) -> str:
    name = ctx.unique_name("sim2real-behav-rsmf-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(
        RoleName=name, PolicyName="inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity"))
    return arn


def _create_function(ctx, lam, role_arn: str) -> str:
    """Create the inline-source function, retrying while the fresh role is not yet assumable."""
    name = ctx.unique_name("sim2real-behav-rsmf-fn-")
    deadline = time.monotonic() + 180.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="handler.handler", Code={"ZipFile": _zip_handler(_LAMBDA_SRC)},
                MemorySize=128, Timeout=10,
                Tags={"sim2real": "1", "sim2real-check": CHECK},
            )["FunctionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last = exc.response["Error"]
            time.sleep(2.0)
            continue
        ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))
        ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                                  "ResourceNotFoundException"))
        lam.get_waiter("function_active_v2").wait(
            FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
        return arn
    raise AssertionError(f"Lambda never became creatable within 180s; last error {last!r}")


def _create_state_machine(ctx, sfn, definition: dict, role_arn: str) -> str:
    """An EXPRESS state machine, polling every 2s against a deadline while the fresh role
    (and its lambda:InvokeFunction grant) propagates."""
    name = ctx.unique_name("sim2real-behav-rsmf-sm-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="EXPRESS",
                tags=[{"key": "sim2real", "value": "1"}, {"key": "sim2real-check", "value": CHECK}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
            continue
        ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
        return arn
    raise AssertionError(f"CreateStateMachine still AccessDenied 120s after role creation: {last!r}")


def _sync_until_role_ready(sfn, sm_arn: str, *, payload: str, deadline: float) -> dict:
    """StartSyncExecution, retrying only while a freshly granted role has not yet propagated:
    either the call itself raises AccessDenied, or the sync response reports States.TaskFailed
    naming role-assumption. Neither is the behavior under test."""
    last = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.start_sync_execution(stateMachineArn=sm_arn, input=payload)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
            continue
        cause = resp.get("cause") or ""
        propagating = "not authorized to assume" in cause or (
            resp.get("error") == "Lambda.AWSLambdaException" and "lambda:InvokeFunction" in cause
        )
        if resp.get("status") != "FAILED" or not propagating:
            return resp
        last = resp
        time.sleep(2.0)
    raise AssertionError(f"StartSyncExecution kept failing on role-assumption: {last!r}")


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ResultSelector ``.$`` path absent from the raw task result ends FAILED with
    States.Runtime, naming the field and the exact result it could not find it in.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/input-output-inputpath-params.html
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_arn = _create_function(ctx, lam, _make_role(ctx, iam, "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                       "logs:PutLogEvents"], "Resource": "*"}]))
    sm_role = _make_role(ctx, iam, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}])
    sm_arn = _create_state_machine(ctx, sfn, _definition(fn_arn), sm_role)

    deadline = time.monotonic() + 120.0

    # --- Positive control: ResultSelector names a field the raw result actually has -------
    ok = _sync_until_role_ready(sfn, sm_arn, payload=json.dumps({"mode": "ok"}), deadline=deadline)
    assert ok["status"] == "SUCCEEDED", (
        "the mode=ok path (ResultSelector selecting an existing field) must report "
        f"SUCCEEDED; got {ok['status']!r} error={ok.get('error')!r} cause={ok.get('cause')!r}"
    )
    assert json.loads(ok["output"]) == _GOOD_OUTPUT, (
        f"expected ResultSelector to produce {_GOOD_OUTPUT!r}, got {ok['output']!r}"
    )

    # --- The subject: ResultSelector names a field absent from the raw result -------------
    try:
        bad = _sync_until_role_ready(
            sfn, sm_arn, payload=json.dumps({"mode": "bad"}), deadline=deadline)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            "StartSyncExecution must report a ResultSelector runtime failure inside a "
            f"successful response carrying status=FAILED; it raised {err.get('Code')!r} "
            f"instead ({err.get('Message')!r})"
        ) from exc

    assert bad["status"] == "FAILED", (
        "a ResultSelector '.$' path absent from the raw task result must report status "
        f"FAILED; got {bad['status']!r}"
    )
    assert bad.get("error") == "States.Runtime", (
        f"the sync response must carry error 'States.Runtime'; got {bad.get('error')!r}"
    )
    raw_result = json.dumps(_GOOD_OUTPUT)
    expected_cause = (
        "An error occurred while executing the state 'BadInvoke' (entered at the event "
        f"id #4). The JSONPath '$.count' specified for the field 'count.$' could "
        f"not be found in the input '{raw_result}'"
    )
    assert bad.get("cause") == expected_cause, (
        f"expected cause {expected_cause!r}, got {bad.get('cause')!r}"
    )
    assert "output" not in bad, (
        f"a FAILED synchronous Express execution has no output; it carried "
        f"output={bad.get('output')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
