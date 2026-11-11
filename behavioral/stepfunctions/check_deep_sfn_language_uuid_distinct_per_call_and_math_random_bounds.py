"""deep-sfn-language-uuid-distinct-per-call-and-math-random-bounds."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-uuid-distinct-per-call-and-math-random-bounds"
GROUP = 'intrinsic_functions'
SERVICES = ['stepfunctions']

_UUID_V4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_ITEMS = 40


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Every States.UUID() call yields a distinct v4 UUID (80 calls across 40 Map iterations), and
    40 draws of States.MathRandom(1, 3) are all 1 or 2 (end is exclusive) with both values seen.
    """
    definition = {
        "StartAt": "Each",
        "States": {
            "Each": {
                "Type": "Map",
                "ItemsPath": "$.items",
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "INLINE"},
                    "StartAt": "Gen",
                    "States": {"Gen": {
                        "Type": "Pass",
                        "Parameters": {
                            "i.$": "$",
                            "u1.$": "States.UUID()",
                            "u2.$": "States.UUID()",
                            "r.$": "States.MathRandom(1, 3)",
                        },
                        "End": True,
                    }},
                },
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, _create_sfn_role(ctx))
    desc = _run_execution(ctx, sm_arn, {"items": list(range(_ITEMS))})
    assert desc["status"] == "SUCCEEDED", (
        f"execution must succeed, got {desc['status']!r} error={desc.get('error')!r} "
        f"cause={desc.get('cause')!r}"
    )
    out = json.loads(desc["output"])
    assert isinstance(out, list) and [o.get("i") for o in out] == list(range(_ITEMS)), (
        f"Map output must hold one result per item in item order, got {str(out)[:300]!r}"
    )
    uuids = [o["u1"] for o in out] + [o["u2"] for o in out]
    bad = [u for u in uuids if not (isinstance(u, str) and _UUID_V4.match(u))]
    assert not bad, f"States.UUID() returned non-v4 values: {bad[:5]!r}"
    assert len(set(uuids)) == 2 * _ITEMS, (
        f"{2 * _ITEMS} UUID() calls produced only {len(set(uuids))} distinct values -- the value "
        f"is being reused across calls"
    )
    same_state = [o for o in out if o["u1"] == o["u2"]]
    assert not same_state, f"two UUID() calls in one Parameters block collided: {same_state[:3]!r}"
    draws = [o.get("r") for o in out]
    assert all(isinstance(r, int) and not isinstance(r, bool) for r in draws), (
        f"MathRandom must return integers, got {draws!r}"
    )
    assert set(draws) <= {1, 2}, (
        f"MathRandom(1, 3) must stay in [1, 3) with an exclusive end, got {sorted(set(draws))!r}"
    )
    assert set(draws) == {1, 2}, (
        f"{_ITEMS} MathRandom(1, 3) draws never varied: {sorted(set(draws))!r}"
    )


_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _create_sfn_role(ctx, statements=None):
    """An execution role this check owns. Pass/Choice/Wait/Fail machines need no permissions,
    but CreateStateMachine still requires a role Step Functions can assume."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnlang-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "states.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Description="sim2real-behav sfn language check role",
        Tags=[{"Key": "sim2real", "Value": "sfn-language"}],
    )["Role"]["Arn"]

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)
    if statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=f"{role_name}-policy",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
        )
    return role_arn


def _create_state_machine(ctx, definition, role_arn):
    """Create a STANDARD machine, absorbing IAM trust propagation with a bounded retry."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnlang-sm-")
    deadline = time.monotonic() + 90.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "sfn-language"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3)
            continue
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn
    raise AssertionError(f"CreateStateMachine kept refusing the freshly created role: {last!r}")


def _stop_if_running(sfn, exec_arn):
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn, error="sim2real.cleanup")


def _run_execution(ctx, sm_arn, payload, *, timeout_s=150.0):
    """Start one execution and poll DescribeExecution until it is terminal."""
    sfn = ctx.client("stepfunctions")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=ctx.unique_name("sim2real-x-"), input=json.dumps(payload)
    )["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, exec_arn))
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = sfn.describe_execution(executionArn=exec_arn)
        if desc["status"] in _TERMINAL:
            return desc
        time.sleep(1)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {desc!r}")


def _history(ctx, exec_arn):
    sfn = ctx.client("stepfunctions")
    events = []
    for page in sfn.get_paginator("get_execution_history").paginate(executionArn=exec_arn):
        events.extend(page["events"])
    return events


def _entered(events):
    """Names of every state entered, in history order."""
    return [e["stateEnteredEventDetails"]["name"] for e in events
            if e["type"].endswith("StateEntered")]


def _exited(events):
    return [e["stateExitedEventDetails"]["name"] for e in events
            if e["type"].endswith("StateExited")]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
