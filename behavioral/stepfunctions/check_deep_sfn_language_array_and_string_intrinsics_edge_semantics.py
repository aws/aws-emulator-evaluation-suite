"""deep-sfn-language-array-and-string-intrinsics-edge-semantics."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-array-and-string-intrinsics-edge-semantics"
GROUP = 'intrinsic_functions'
SERVICES = ['stepfunctions']


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Intrinsic edge cases: StringSplit drops empty tokens and splits on each delimiter character,
    ArrayRange counts down, ArrayPartition/Unique/Length/GetItem handle edges, Format escapes.
    """
    # Python's str.split keeps empty strings and treats '-_' as one separator; range() with a
    # negative step is easy to get wrong, so these edges catch host-language shortcuts.
    definition = {
        "StartAt": "Eval",
        "States": {
            "Eval": {
                "Type": "Pass",
                "Parameters": {
                    "split_empty.$": "States.StringSplit($.csv, ',')",
                    "split_multi.$": "States.StringSplit($.mixed, '-_')",
                    "range_down.$": "States.ArrayRange(9, 1, -2)",
                    "part_big.$": "States.ArrayPartition($.two, 5)",
                    "unique.$": "States.ArrayUnique($.words)",
                    "len_empty.$": "States.ArrayLength($.empty)",
                    "get_obj.$": "States.ArrayGetItem($.objs, 1)",
                    "formatted.$": "States.Format('x\\{\\} {} \\'q\\' {}', $.s, $.n)",
                },
                "End": True,
            }
        },
    }
    sm_arn = _create_state_machine(ctx, definition, _create_sfn_role(ctx))
    payload = {
        "csv": "a,,b,", "mixed": "a-b_c", "two": [1, 2],
        "words": ["b", "a", "b", "c", "a"], "empty": [],
        "objs": [{"id": "a"}, {"id": "b", "v": [1]}], "s": "val", "n": 3,
    }
    desc = _run_execution(ctx, sm_arn, payload)
    assert desc["status"] == "SUCCEEDED", (
        f"evaluation must succeed, got {desc['status']!r} error={desc.get('error')!r} "
        f"cause={desc.get('cause')!r}"
    )
    out = json.loads(desc["output"])
    assert out.get("split_empty") == ["a", "b"], (
        f"StringSplit('a,,b,', ',') must drop empty tokens and yield ['a', 'b'], "
        f"got {out.get('split_empty')!r}"
    )
    assert out.get("split_multi") == ["a", "b", "c"], (
        f"StringSplit('a-b_c', '-_') must split on each delimiter character, "
        f"got {out.get('split_multi')!r}"
    )
    assert out.get("range_down") == [9, 7, 5, 3, 1], (
        f"ArrayRange(9, 1, -2) must count down inclusively, got {out.get('range_down')!r}"
    )
    assert out.get("part_big") == [[1, 2]], (
        f"ArrayPartition([1,2], 5) must yield a single chunk [[1, 2]], got {out.get('part_big')!r}"
    )
    unique = out.get("unique")
    assert isinstance(unique, list) and len(unique) == 3 and set(unique) == {"a", "b", "c"}, (
        f"ArrayUnique(['b','a','b','c','a']) must hold exactly a, b, c once each, got {unique!r}"
    )
    assert out.get("len_empty") == 0, f"ArrayLength([]) must be 0, got {out.get('len_empty')!r}"
    assert out.get("get_obj") == {"id": "b", "v": [1]}, (
        f"ArrayGetItem(objs, 1) must return the second object intact, got {out.get('get_obj')!r}"
    )
    assert out.get("formatted") == "x{} val 'q' 3", (
        f"States.Format with escaped braces/quotes must yield \"x{{}} val 'q' 3\", "
        f"got {out.get('formatted')!r}"
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
