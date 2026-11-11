"""map-legacy-parameters-field-with-iterator-and-item-context."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "map-legacy-parameters-field-with-iterator-and-item-context"
GROUP = "map_state"
SERVICES = ["stepfunctions"]

_TRUST = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _create_sfn_role(ctx) -> str:
    """A Step Functions execution role this check creates and deletes."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnlegacy-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn: str, definition: dict) -> str:
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnlegacy-")
    deadline = time.monotonic() + 60.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn, type="STANDARD"
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn: str, input_data: dict) -> str:
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(input_data))["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn: str, *, timeout_s=30.0) -> dict:
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _get_output(desc: dict):
    raw = desc.get("output")
    return None if raw is None else json.loads(raw)


def _get_history_events(ctx, exec_arn: str) -> list:
    sfn = ctx.client("stepfunctions")
    events: list = []
    kwargs = {"executionArn": exec_arn}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        token = resp.get("nextToken")
        if not token:
            break
        kwargs["nextToken"] = token
    return events


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Map state's legacy Map-level Parameters field (ItemSelector's predecessor) referencing
    $$.Map.Item.Index/Value, combined with the legacy Iterator field (not ItemProcessor), replaces
    each item the same way ItemSelector does and keeps results in input order."""
    letters = ["a", "b", "c", "d", "e"]
    definition = {
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Map",
                "ItemsPath": "$.items",
                "MaxConcurrency": 3,
                "Parameters": {
                    "idx.$": "$$.Map.Item.Index",
                    "letter.$": "$$.Map.Item.Value.letter",
                    "batch.$": "$.batch",
                },
                "Iterator": {
                    "StartAt": "Tag",
                    "States": {
                        "Tag": {
                            "Type": "Pass",
                            "Parameters": {
                                "slot.$": "$.idx",
                                "tagged.$": "States.Format('{}-{}-{}', $.batch, $.idx, $.letter)",
                                "keys.$": "States.Array($.batch, $.letter)",
                            },
                            "End": True,
                        }
                    },
                },
                "End": True,
            }
        },
    }
    input_data = {"batch": "b7", "items": [{"letter": ltr, "noise": ltr * 3} for ltr in letters]}

    sm_arn = _create_state_machine(ctx, role_arn=_create_sfn_role(ctx), definition=definition)
    exec_arn = _start_execution(ctx, sm_arn, input_data)
    desc = _wait_execution_complete(ctx, exec_arn)
    assert desc["status"] == "SUCCEEDED", (
        f"Map execution must succeed, got {desc.get('status')} error={desc.get('error')!r} "
        f"cause={desc.get('cause')!r}"
    )
    out = _get_output(desc)
    assert isinstance(out, list) and len(out) == len(letters), (
        f"Map output must be a {len(letters)}-element array, got {out!r}"
    )

    expected = [
        {"slot": i, "tagged": f"b7-{i}-{ltr}", "keys": ["b7", ltr]}
        for i, ltr in enumerate(letters)
    ]
    assert out == expected, (
        f"Map results must be positionally aligned with the input array and built from the "
        f"legacy Parameters projection.\nexpected: {expected!r}\ngot     : {out!r}"
    )
    # The raw item is not visible to the iteration -- the legacy Parameters field replaced it,
    # exactly as ItemSelector does.
    assert all("noise" not in item for item in out), (
        f"the legacy Parameters field must replace the raw item; the original 'noise' field "
        f"leaked through: {out!r}"
    )

    # Legacy Iterator mode: one MapIteration per item, and no Map Run resource (only
    # ItemProcessor's DISTRIBUTED mode creates one).
    events = _get_history_events(ctx, exec_arn)
    started = [e for e in events if e["type"] == "MapIterationStarted"]
    assert len(started) == len(letters), (
        f"expected {len(letters)} MapIterationStarted events, got {len(started)}: "
        f"{[e['type'] for e in events]}"
    )
    map_runs = ctx.client("stepfunctions").list_map_runs(executionArn=exec_arn)["mapRuns"]
    assert map_runs == [], (
        f"a legacy Iterator Map must not create a Map Run, got {map_runs!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
