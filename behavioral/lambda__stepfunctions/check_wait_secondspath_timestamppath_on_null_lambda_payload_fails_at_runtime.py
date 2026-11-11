"""wait-secondspath-timestamppath-on-null-lambda-payload-fails-at-runtime."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "wait-secondspath-timestamppath-on-null-lambda-payload-fails-at-runtime"
GROUP = "error_handling"
SERVICES = ["lambda", "stepfunctions"]

_HANDLER_SRC = (
    "def handler(event, context):\n"
    "    if event.get('mode') == 'null':\n"
    "        return None\n"
    "    return event.get('wait')\n"
)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:negative-classes", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A Wait whose SecondsPath or TimestampPath resolves into a Lambda result that is JSON null
    fails the execution with States.Runtime, naming the unresolved path -- while the identical
    machine waits and succeeds once the Lambda payload actually carries the field.
    """
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    sfn = ctx.client("stepfunctions")

    fn_role = _lambda_role(ctx, iam)
    fn_name, fn_arn = _create_function(ctx, lam, _HANDLER_SRC, fn_role)
    sm_role = _make_role(ctx, iam, "states.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}])

    seconds_sm = _create_state_machine(ctx, sfn, _definition(fn_arn, "SecondsPath"), sm_role)
    timestamp_sm = _create_state_machine(ctx, sfn, _definition(fn_arn, "TimestampPath"), sm_role)

    # Positive control: the Lambda payload actually carries the field the Wait reads.
    when = (datetime.now(timezone.utc) + timedelta(seconds=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    seconds_ok = _await_role_assumable(sfn, seconds_sm, payload=json.dumps({"wait": {"seconds": 1}}))
    assert seconds_ok["status"] == "SUCCEEDED", (
        f"SecondsPath resolving into a real field must let the Wait succeed; got "
        f"{seconds_ok['status']!r}, cause {seconds_ok.get('cause')!r}"
    )
    timestamp_ok = _run_to_terminal(sfn, timestamp_sm, payload=json.dumps({"wait": {"when": when}}))
    assert timestamp_ok["status"] == "SUCCEEDED", (
        f"TimestampPath resolving into a real field must let the Wait succeed; got "
        f"{timestamp_ok['status']!r}, cause {timestamp_ok.get('cause')!r}"
    )

    # Negative: the Lambda returns JSON null, so the same path has nothing to resolve into.
    seconds_fail = _run_to_terminal(sfn, seconds_sm, payload=json.dumps({"mode": "null"}))
    _assert_wait_runtime_failure(sfn, seconds_fail, "SecondsPath", "$.val.seconds")

    timestamp_fail = _run_to_terminal(sfn, timestamp_sm, payload=json.dumps({"mode": "null"}))
    _assert_wait_runtime_failure(sfn, timestamp_fail, "TimestampPath", "$.val.when")


def _assert_wait_runtime_failure(sfn, execution: dict, path_field: str, path_expr: str) -> None:
    assert execution["status"] == "FAILED", (
        f"a {path_field} with nothing to resolve must FAIL the execution; got {execution['status']!r}"
    )
    assert execution.get("error") == "States.Runtime", (
        f"a {path_field} with nothing to resolve must fail with States.Runtime; got "
        f"{execution.get('error')!r}"
    )
    entered_id = _wait_entered_event_id(sfn, execution["executionArn"])
    expected_cause = (
        f"An error occurred while executing the state 'Wait' (entered at the event id "
        f"#{entered_id}). The {path_field} parameter does not reference an input value: {path_expr}"
    )
    assert execution.get("cause") == expected_cause, (
        f"expected cause {expected_cause!r}, got {execution.get('cause')!r}"
    )


def _wait_entered_event_id(sfn, exec_arn: str) -> int:
    """The id of the single WaitStateEntered event, read from the execution's own history."""
    events = [e for e in _history(sfn, exec_arn) if e["type"] == "WaitStateEntered"]
    assert len(events) == 1, f"expected exactly one WaitStateEntered event, found {len(events)}"
    return events[0]["id"]


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


def _definition(fn_arn: str, path_field: str) -> str:
    """A LambdaInvoke task feeding its Payload into a Wait that reads ``path_field`` from it."""
    return json.dumps({
        "StartAt": "Invoke",
        "States": {
            "Invoke": {
                "Type": "Task", "Resource": "arn:aws:states:::lambda:invoke",
                "Parameters": {"FunctionName": fn_arn, "Payload.$": "$"},
                "ResultSelector": {"val.$": "$.Payload"},
                "Next": "Wait",
            },
            "Wait": {
                "Type": "Wait",
                path_field: f"$.val.{'seconds' if path_field == 'SecondsPath' else 'when'}",
                "End": True,
            },
        },
    })


_TAGS = {"sim2real:managed": "true", "sim2real": CHECK[:200]}
_TAGLIST = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
_SFN_TAGLIST = [{"key": k, "value": v} for k, v in _TAGS.items()]
_FN_CREATE_TIMEOUT_S = 240
_TRUST_BARRIER_TIMEOUT_S = 240


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _zip_handler(src: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("handler.py", src)
    return buf.getvalue()


def _make_role(ctx, iam, service, statements):
    name = ctx.unique_name("sim2real-scn-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": service},
                           "Action": "sts:AssumeRole"}],
        }),
        Tags=_TAGLIST,
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=name, PolicyName="inline",
                        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                                   "Statement": statements}))
    ctx.on_cleanup(_teardown(
        lambda: iam.delete_role_policy(RoleName=name, PolicyName="inline"), "NoSuchEntity"))
    return arn


def _lambda_role(ctx, iam):
    return _make_role(ctx, iam, "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream",
                                       "logs:PutLogEvents"], "Resource": "*"}])


def _create_function(ctx, lam, src, role_arn, **extra):
    name = ctx.unique_name("sim2real-scn-fn-")
    deadline = time.monotonic() + _FN_CREATE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        try:
            arn = lam.create_function(
                FunctionName=name, Runtime="python3.12", Role=role_arn,
                Handler="handler.handler", Code={"ZipFile": _zip_handler(src)},
                Timeout=20, MemorySize=128, Tags=_TAGS, **extra,
            )["FunctionArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            last = exc.response["Error"]
            time.sleep(5.0)
            continue
        ctx.on_cleanup(lambda: _reap_log_group(ctx.client("logs"), f"/aws/lambda/{name}"))
        ctx.on_cleanup(_teardown(lambda: lam.delete_function(FunctionName=name),
                                 "ResourceNotFoundException"))
        lam.get_waiter("function_active_v2").wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
        return name, arn
    raise AssertionError(
        f"no Lambda became creatable within {_FN_CREATE_TIMEOUT_S}s; last error {last!r}"
    )


def _reap_log_group(logs, name: str, *, reads: int = 3, interval_s: float = 5.0,
                    budget_s: float = 180.0) -> None:
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


def _create_state_machine(ctx, sfn, definition, role_arn):
    name = ctx.unique_name("sim2real-scn-sm-")
    arn = sfn.create_state_machine(name=name, definition=definition, roleArn=role_arn,
                                   type="STANDARD", tags=_SFN_TAGLIST)["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn),
                             "StateMachineDoesNotExist"))
    return arn


def _poll_until(probe, predicate, *, timeout_s=180.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _run_to_terminal(sfn, sm_arn, *, payload="{}"):
    ex = sfn.start_execution(
        stateMachineArn=sm_arn,
        name="sim2real-x-" + uuid.uuid4().hex[:12],
        input=payload,
    )["executionArn"]
    return _poll_until(lambda: sfn.describe_execution(executionArn=ex),
                       lambda d: d["status"] != "RUNNING",
                       description=f"execution {ex} reached a terminal status")


def _is_propagation_lag(cause: str) -> bool:
    """True when ``cause`` names a fresh role's credentials not yet usable, not a real failure."""
    return any(marker in cause for marker in (
        "not authorized to assume",
        "UnrecognizedClientException",
        "InvalidClientTokenId",
        "security token included in the request is invalid",
    ))


def _await_role_assumable(sfn, sm_arn, *, payload="{}"):
    """Run executions until one leaves the role-trust-propagation race, win or lose."""
    deadline = time.monotonic() + _TRUST_BARRIER_TIMEOUT_S
    last = {}
    while time.monotonic() < deadline:
        last = _run_to_terminal(sfn, sm_arn, payload=payload)
        if last["status"] != "FAILED" or not _is_propagation_lag(last.get("cause") or ""):
            return last
        time.sleep(5.0)
    raise AssertionError(
        f"the state machine never left the role-trust race within {_TRUST_BARRIER_TIMEOUT_S}s: "
        f"last status {last.get('status')!r}, cause {(last.get('cause') or '')[:300]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
