"""outputpath-null-empty-output-pass-lambda-activity."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "outputpath-null-empty-output-pass-lambda-activity"
GROUP = "input_output_processing"
SERVICES = ["lambda", "stepfunctions"]

_LAMBDA_SRC = (
    "def handler(event, context):\n"
    "    return {'should_be_discarded': True, 'tag': 'lambda'}\n"
)
_PASS_RESULT = {"should_be_discarded": True, "tag": "pass"}
_ACTIVITY_REPLY = {"should_be_discarded": True, "tag": "activity"}
_EXEC_INPUT = {"val": 1}


def _definition(fn_arn: str, activity_arn: str) -> dict:
    """A Parallel with one branch per state shape, each producing a non-empty result and
    then discarding it with ``OutputPath: null``, plus a Pass control branch carrying the
    same Result with no OutputPath at all, proving Result on its own is not empty."""
    return {
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Parallel",
                "Branches": [
                    {
                        "StartAt": "PassBranch",
                        "States": {
                            "PassBranch": {
                                "Type": "Pass",
                                "Result": _PASS_RESULT,
                                "OutputPath": None,
                                "End": True,
                            }
                        },
                    },
                    {
                        "StartAt": "PassControlBranch",
                        "States": {
                            "PassControlBranch": {
                                "Type": "Pass",
                                "Result": _PASS_RESULT,
                                "End": True,
                            }
                        },
                    },
                    {
                        "StartAt": "LambdaBranch",
                        "States": {
                            "LambdaBranch": {
                                "Type": "Task",
                                "Resource": fn_arn,
                                "OutputPath": None,
                                "End": True,
                            }
                        },
                    },
                    {
                        "StartAt": "ActivityBranch",
                        "States": {
                            "ActivityBranch": {
                                "Type": "Task",
                                "Resource": activity_arn,
                                "OutputPath": None,
                                "TimeoutSeconds": 120,
                                "End": True,
                            }
                        },
                    },
                ],
                "End": True,
            }
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
    name = ctx.unique_name("sim2real-behav-opnull-role-")
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
    name = ctx.unique_name("sim2real-behav-opnull-fn-")
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


def _create_activity(ctx, sfn) -> str:
    arn = sfn.create_activity(
        name=ctx.unique_name("sim2real-behav-opnull-act-"),
        tags=[{"key": "sim2real", "value": "1"}, {"key": "sim2real-check", "value": CHECK}],
    )["activityArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_activity(activityArn=arn), "ActivityDoesNotExist"))
    return arn


def _create_state_machine(ctx, sfn, definition: dict, role_arn: str) -> str:
    """A STANDARD machine (Activities need one), polling every 2s against a deadline while
    the fresh role (and its lambda:InvokeFunction grant) propagates."""
    name = ctx.unique_name("sim2real-behav-opnull-sm-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD",
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


def _poll_activity_task(sfn, activity_arn: str, *, worker_name: str, timeout_s: float) -> dict | None:
    """GetActivityTask long-polls up to ~60s server-side and returns empty on expiry/timeout."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sfn.get_activity_task(activityArn=activity_arn, workerName=worker_name)
        if resp.get("taskToken"):
            return resp
    return None


def _wait_terminal(sfn, exec_arn: str, *, timeout_s: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _is_role_propagation_failure(desc: dict) -> bool:
    return desc.get("status") == "FAILED" and (
        "not authorized to assume" in (desc.get("cause") or "")
    )


def _run_once(ctx, sfn, sm_arn: str, activity_arn: str) -> dict:
    """Start one execution, reply to its Activity branch with a non-empty payload, then wait
    for the execution to go terminal. A failure from stale IAM-role propagation is reported
    to the caller as-is, to be retried with a fresh execution."""
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-x-"),
        input=json.dumps(_EXEC_INPUT),
    )["executionArn"]
    ctx.on_cleanup(lambda a=exec_arn: sfn.stop_execution(executionArn=a))

    worker_name = ctx.unique_name("sim2real-behav-worker-")
    task = _poll_activity_task(sfn, activity_arn, worker_name=worker_name, timeout_s=15.0)
    if task is not None:
        try:
            sfn.send_task_success(taskToken=task["taskToken"], output=json.dumps(_ACTIVITY_REPLY))
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("TaskTimedOut", "TaskDoesNotExist",
                                                       "InvalidToken"):
                raise

    return _wait_terminal(sfn, exec_arn, timeout_s=60.0)


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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """``OutputPath: null`` makes the output the empty object for Pass, a Lambda Task and an
    Activity Task alike, discarding a genuinely non-empty result each one produced.

    Reference: https://docs.aws.amazon.com/cdk/api/v2/docs/aws-cdk-lib.aws_stepfunctions.PassProps.html
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_arn = _create_function(ctx, lam, _make_role(ctx, iam, "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                       "logs:PutLogEvents"], "Resource": "*"}]))
    activity_arn = _create_activity(ctx, sfn)
    sm_role = _make_role(ctx, iam, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}])
    sm_arn = _create_state_machine(ctx, sfn, _definition(fn_arn, activity_arn), sm_role)

    deadline = time.monotonic() + 240.0
    exec_arn = None
    final = _run_once(ctx, sfn, sm_arn, activity_arn)
    while _is_role_propagation_failure(final) and time.monotonic() < deadline:
        final = _run_once(ctx, sfn, sm_arn, activity_arn)
    assert final["status"] == "SUCCEEDED", (
        f"the fan-out execution must SUCCEED, got {final['status']!r} error={final.get('error')!r} "
        f"cause={final.get('cause')!r}"
    )
    exec_arn = final["executionArn"]
    pass_out, pass_control_out, lambda_out, activity_out = json.loads(final["output"])
    assert pass_control_out == _PASS_RESULT, (
        "the control branch (same Result, no OutputPath) must carry it through unchanged, "
        f"proving Result itself is not empty; got {pass_control_out!r}"
    )
    assert pass_out == {}, (
        f"OutputPath: null must discard the Pass state's Result entirely; got {pass_out!r}"
    )
    assert lambda_out == {}, (
        f"OutputPath: null must discard the Lambda task's own result entirely; got {lambda_out!r}"
    )
    assert activity_out == {}, (
        f"OutputPath: null must discard the Activity task's reported output entirely; "
        f"got {activity_out!r}"
    )

    # Positive control for the Lambda and Activity branches: their own raw-result history
    # events (recorded before OutputPath ever runs) show a genuinely non-empty value, so the
    # empty outputs above are OutputPath discarding it, not the branch having nothing to give.
    events = _history(sfn, exec_arn)
    succeeded = {
        e["type"]: e for e in events
        if e["type"] in ("LambdaFunctionSucceeded", "ActivitySucceeded")
    }
    lambda_raw = json.loads(succeeded["LambdaFunctionSucceeded"]["lambdaFunctionSucceededEventDetails"]["output"])
    assert lambda_raw == {"should_be_discarded": True, "tag": "lambda"}, (
        f"the Lambda task's own raw result, recorded before OutputPath runs, must be the "
        f"function's non-empty return value; history recorded {lambda_raw!r}"
    )
    activity_raw = json.loads(succeeded["ActivitySucceeded"]["activitySucceededEventDetails"]["output"])
    assert activity_raw == _ACTIVITY_REPLY, (
        f"the Activity task's own raw result, recorded before OutputPath runs, must be the "
        f"worker's reply {_ACTIVITY_REPLY!r}; history recorded {activity_raw!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
