"""map-item-selector-context-and-result-ordering."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "map-item-selector-context-and-result-ordering"
GROUP = 'map_state'
SERVICES = ['stepfunctions']


def _create_sfn_role(ctx):
    """A Step Functions execution role this check creates and deletes."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_state_machine(ctx, definition, *, name=None, sm_type="STANDARD"):
    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-behav-sm-")
    role_arn = _create_sfn_role(ctx)
    # A role created moments ago may not yet be assumable by Step Functions; retry within a bound.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _start_execution(ctx, sm_arn, *, input_data=None, name=None):
    sfn = ctx.client("stepfunctions")
    kwargs = {"stateMachineArn": sm_arn}
    if input_data is not None:
        kwargs["input"] = json.dumps(input_data)
    if name is not None:
        kwargs["name"] = name
    exec_arn = sfn.start_execution(**kwargs)["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))
    return exec_arn


def _wait_execution_complete(ctx, exec_arn, *, timeout_s=30):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"):
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _get_output(resp):
    raw = resp.get("output")
    return None if raw is None else json.loads(raw)


def _get_history_events(ctx, exec_arn, *, reverse=False):
    sfn = ctx.client("stepfunctions")
    events = []
    kwargs = {"executionArn": exec_arn, "reverseOrder": reverse}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        events.extend(resp["events"])
        if "nextToken" not in resp:
            break
        kwargs["nextToken"] = resp["nextToken"]
    return events


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An inline Map's ItemSelector replaces each item with an object built from $$.Map.Item.Index,
    $$.Map.Item.Value and the Map state's input $, results stay in input order under MaxConcurrency 3,
    and inline mode starts one iteration per item and creates no Map Run."""
    letters = ["a", "b", "c", "d", "e"]
    definition = {
        "StartAt": "Fan",
        "States": {
            "Fan": {
                "Type": "Map",
                "ItemsPath": "$.items",
                "MaxConcurrency": 3,
                "ItemSelector": {
                    "idx.$": "$$.Map.Item.Index",
                    "letter.$": "$$.Map.Item.Value.letter",
                    "batch.$": "$.batch",
                },
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "INLINE"},
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
    exec_arn = _start_execution(
        ctx, _create_state_machine(ctx, definition), input_data=input_data
    )
    desc = _wait_execution_complete(ctx, exec_arn, timeout_s=120)
    assert desc["status"] == "SUCCEEDED", (
        f"Map execution must succeed, got {desc.get('status')} error={desc.get('error')} "
        f"cause={desc.get('cause')}"
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
        f"ItemSelector projection.\nexpected: {expected!r}\ngot     : {out!r}"
    )
    # The raw item is not visible to the iteration -- ItemSelector replaced it.
    assert all("noise" not in item for item in out), (
        f"ItemSelector must replace the raw item; the original 'noise' field leaked through: {out!r}"
    )

    # Inline mode: one MapIteration per item, and no Map Run resource.
    events = _get_history_events(ctx, exec_arn)
    started = [e for e in events if e["type"] == "MapIterationStarted"]
    assert len(started) == len(letters), (
        f"expected {len(letters)} MapIterationStarted events, got {len(started)}: "
        f"{[e['type'] for e in events]}"
    )
    map_runs = ctx.client("stepfunctions").list_map_runs(executionArn=exec_arn)["mapRuns"]
    assert map_runs == [], (
        f"an INLINE Map must not create a Map Run (only DISTRIBUTED does), got {map_runs!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
