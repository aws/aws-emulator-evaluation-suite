"""map-itemselector-invalid-context-path-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "map-itemselector-invalid-context-path-rejected"
GROUP = "map_state"
SERVICES = ["stepfunctions"]

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_sfn_role(ctx) -> str:
    """An execution role this check owns; Map/Pass states call no AWS service."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnmap-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_state_machine(ctx, definition, role_arn, name):
    """Create a STANDARD machine, retrying while the freshly created role's trust propagates."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn
    raise AssertionError(f"CreateStateMachine kept refusing the freshly created role: {last!r}")


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _run_to_terminal(ctx, sm_arn, exec_name, input_data, *, timeout_s=60.0):
    """Start one named execution and poll DescribeExecution every 2s against a deadline."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=exec_name, input=json.dumps(input_data)
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] in _TERMINAL:
            return desc
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {desc!r}")


def _stop_if_running(sfn, exec_arn):
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn, error="sim2real.cleanup")


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events = []
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        events.extend(page["events"])
    return events


def _fmt_ts(dt) -> str:
    """AWS's rendering of a context-object timestamp: ISO-8601, millisecond precision, 'Z'."""
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{dt.microsecond // 1000:03d}Z"


def _expected_cause(*, exec_desc, sm_arn, sm_name, role_arn, state_name, event_id,
                     entered_time, item_index, item_value, bad_field, bad_path):
    """The exact States.Runtime cause AWS renders when a context-object path is unresolved:
    the field and path that failed, plus the full $$ context object it searched."""
    context_obj = {
        "Execution": {
            "Id": exec_desc["executionArn"],
            "Input": exec_desc["input_obj"],
            "StartTime": _fmt_ts(exec_desc["startDate"]),
            "Name": exec_desc["name"],
            "RoleArn": role_arn,
            "RedriveCount": 0,
        },
        "StateMachine": {"Id": sm_arn, "Name": sm_name},
        "State": {"Name": state_name, "EnteredTime": _fmt_ts(entered_time), "RetryCount": 0},
        "Map": {"Item": {"Index": item_index, "Value": item_value}},
    }
    context_json = json.dumps(context_obj, separators=(",", ":"))
    return (
        f"An error occurred while executing the state '{state_name}' "
        f"(entered at the event id #{event_id}). The JSONPath '{bad_path}' specified for "
        f"the field '{bad_field}' could not be found in the input '{context_json}'"
    )


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A Map ItemSelector referencing a non-existent $$.Map.Item field fails the execution
    with States.Runtime naming the unresolved JSONPath and the full context object searched;
    the same Map given a real $$.Map.Item.Index field succeeds.
    """
    role_arn = _create_sfn_role(ctx)
    sm_name = ctx.unique_name("sim2real-behav-sfnmap-")
    bad_path = "$$.Map.Item.Invalid"
    bad_field = "bad.$"
    definition = {
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [{"Variable": "$.mode", "StringEquals": "bad", "Next": "BadMap"}],
                "Default": "GoodMap",
            },
            "GoodMap": {
                "Type": "Map",
                "ItemsPath": "$.items",
                "ItemSelector": {"idx.$": "$$.Map.Item.Index"},
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "INLINE"},
                    "StartAt": "PG",
                    "States": {"PG": {"Type": "Pass", "End": True}},
                },
                "End": True,
            },
            "BadMap": {
                "Type": "Map",
                "ItemsPath": "$.items",
                "ItemSelector": {bad_field: bad_path},
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "INLINE"},
                    "StartAt": "PB",
                    "States": {"PB": {"Type": "Pass", "End": True}},
                },
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, definition, role_arn, sm_name)

    # --- Positive control: a valid $$.Map.Item.Index reference succeeds ------------------
    items = [10, 20, 30]
    good = _run_to_terminal(
        ctx, sm_arn, ctx.unique_name("sim2real-x-good-"), {"mode": "good", "items": items}
    )
    assert good["status"] == "SUCCEEDED", (
        f"the control Map with a valid $$.Map.Item.Index reference must succeed, got "
        f"{good['status']!r} error={good.get('error')!r} cause={good.get('cause')!r}"
    )
    good_out = json.loads(good["output"])
    assert good_out == [{"idx": 0}, {"idx": 1}, {"idx": 2}], (
        f"expected one {{'idx': i}} per item in order, got {good_out!r}"
    )

    # --- The subject: $$.Map.Item.Invalid is not a field of the context object -----------
    bad_exec_name = ctx.unique_name("sim2real-x-bad-")
    bad = _run_to_terminal(ctx, sm_arn, bad_exec_name, {"mode": "bad", "items": items})
    assert bad["status"] == "FAILED", (
        f"a Map ItemSelector referencing the non-existent field {bad_path!r} must fail the "
        f"execution, got {bad['status']!r} output={bad.get('output')!r}"
    )
    assert bad.get("error") == "States.Runtime", (
        f"expected error 'States.Runtime', got {bad.get('error')!r} cause={bad.get('cause')!r}"
    )

    events = _history(ctx, bad["executionArn"])
    entered = [
        e for e in events
        if e["type"] == "MapStateEntered" and e["stateEnteredEventDetails"]["name"] == "BadMap"
    ]
    assert len(entered) == 1, (
        f"expected exactly one MapStateEntered(BadMap) event, got history types "
        f"{[e['type'] for e in events]!r}"
    )
    bad_desc = dict(bad)
    bad_desc["input_obj"] = {"mode": "bad", "items": items}
    expected_cause = _expected_cause(
        exec_desc=bad_desc,
        sm_arn=sm_arn,
        sm_name=sm_name,
        role_arn=role_arn,
        state_name="BadMap",
        event_id=entered[0]["id"],
        entered_time=entered[0]["timestamp"],
        item_index=0,
        item_value=items[0],
        bad_field=bad_field,
        bad_path=bad_path,
    )
    assert bad.get("cause") == expected_cause, (
        f"expected cause {expected_cause!r}, got {bad.get('cause')!r}"
    )
    assert bad.get("output") is None, f"a failed Map produced output {bad.get('output')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
