"""map-maxconcurrency-one-succeeds-at-3000-serial-iterations."""
from __future__ import annotations

import json
import time
from collections import Counter

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "map-maxconcurrency-one-succeeds-at-3000-serial-iterations"
GROUP = "map_state"
SERVICES = ["stepfunctions"]

_ITEMS = 3000
_MAP_STATE = "M"


def _create_sfn_role(ctx):
    """Create an execution role Step Functions may assume, deleted at cleanup."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _call_once_role_assumable(create, **kwargs):
    """Call ``create``, retrying while a just-created role is not yet assumable."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return create(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _create_state_machine(ctx, role_arn, definition):
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    arn = _call_once_role_assumable(
        sfn.create_state_machine,
        name=name,
        definition=json.dumps(definition),
        roleArn=role_arn,
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _wait_terminal(ctx, exec_arn, *, timeout_s):
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


def _history_event_type_counts(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    counts = Counter()
    kwargs = {"executionArn": exec_arn, "maxResults": 1000}
    while True:
        resp = sfn.get_execution_history(**kwargs)
        counts.update(e["type"] for e in resp["events"])
        token = resp.get("nextToken")
        if not token:
            return counts
        kwargs["nextToken"] = token


def _definition():
    return {
        "StartAt": _MAP_STATE,
        "States": {
            _MAP_STATE: {
                "Type": "Map",
                "ItemsPath": "$.items",
                "MaxConcurrency": 1,
                "Iterator": {"StartAt": "Echo", "States": {"Echo": {"Type": "Pass", "End": True}}},
                "End": True,
            }
        },
    }


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An inline Map with MaxConcurrency=1 over 3,000 items succeeds, returning all
    3,000 results in item order with no iteration dropped, duplicated or truncated.

    Reference: https://docs.aws.amazon.com/step-functions/latest/dg/amazon-states-language-map-state.html
    """
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn, _definition())

    sfn = ctx.client("stepfunctions")
    payload = {"items": list(range(_ITEMS))}
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(payload))["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=exec_arn))

    result = _wait_terminal(ctx, exec_arn, timeout_s=600.0)
    assert result["status"] == "SUCCEEDED", (
        f"a MaxConcurrency=1 inline Map over {_ITEMS} items must succeed; got "
        f"status={result['status']!r} error={result.get('error')!r} "
        f"cause={result.get('cause')!r}"
    )
    output = json.loads(result["output"])
    assert output == list(range(_ITEMS)), (
        f"the Map must return all {_ITEMS} results in item order with none dropped, "
        f"duplicated or reordered; expected a {_ITEMS}-element identity list, got "
        f"{len(output)} element(s) "
        f"(first mismatch at {next((i for i, (a, b) in enumerate(zip(output, range(_ITEMS))) if a != b), 'n/a')!r})"
    )

    counts = _history_event_type_counts(ctx, exec_arn)
    assert counts.get("MapIterationStarted") == _ITEMS, (
        f"history must record exactly {_ITEMS} MapIterationStarted events, got "
        f"{counts.get('MapIterationStarted')!r}"
    )
    assert counts.get("MapIterationSucceeded") == _ITEMS, (
        f"history must record exactly {_ITEMS} MapIterationSucceeded events, got "
        f"{counts.get('MapIterationSucceeded')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
