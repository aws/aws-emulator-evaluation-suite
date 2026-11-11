"""deep-sfn-language-choice-nested-and-or-not-path-comparators."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-choice-nested-and-or-not-path-comparators"
GROUP = 'choice_state'
SERVICES = ['stepfunctions']

_RULES = [
    {"And": [
        {"Variable": "$.n", "NumericLessThanPath": "$.limit"},
        {"Or": [
            {"Variable": "$.flag", "BooleanEqualsPath": "$.want"},
            {"Not": {"Variable": "$.name", "StringGreaterThanEqualsPath": "$.floor"}},
        ]},
        {"Variable": "$.t", "TimestampLessThanEqualsPath": "$.deadline"},
    ], "Next": "R1"},
    {"And": [
        {"Variable": "$.n", "NumericGreaterThanEqualsPath": "$.limit"},
        {"Variable": "$.opt", "IsPresent": False},
    ], "Next": "R2"},
    {"Or": [
        {"Variable": "$.opt", "IsNull": True},
        {"Variable": "$.n", "NumericEqualsPath": "$.name"},
    ], "Next": "R3"},
]

_BASE = {"n": 3, "limit": 5, "flag": True, "want": False, "name": "alpha", "floor": "beta",
         "t": "2026-01-01T00:00:00Z", "deadline": "2026-01-01T00:00:00Z", "opt": 1}


def _without(d, key):
    return {k: v for k, v in d.items() if k != key}


# (label, input, expected terminal Pass state)
_CASES = [
    ("R1 via Not(StringGreaterThanEqualsPath)", dict(_BASE), "R1"),
    ("R1 via BooleanEqualsPath", dict(_BASE, want=True, name="zeta"), "R1"),
    ("R1 blocked: both Or arms false", dict(_BASE, name="zeta"), "D"),
    ("R1 blocked: timestamp one second late", dict(_BASE, t="2026-01-01T00:00:01Z"), "D"),
    ("R2: >= limit and opt absent", dict(_without(_BASE, "opt"), n=5), "R2"),
    ("R3 via IsNull", dict(_BASE, n=9, opt=None), "R3"),
    ("NumericEqualsPath against a string is false", dict(_BASE, n=9, opt=2), "D"),
]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Choice evaluates nested And/Or/Not over five *Path comparators plus IsPresent/IsNull, and a
    numeric Path comparison against a string is false, not an error: seven executions that each flip
    one input field enter the expected branch, so every arm of the tree decides the route."""
    states = {"C": {"Type": "Choice", "Choices": _RULES, "Default": "D"}}
    for target in ("R1", "R2", "R3", "D"):
        states[target] = {"Type": "Pass", "Result": target, "End": True}
    sm_arn = _create_state_machine(ctx, {"StartAt": "C", "States": states}, _create_sfn_role(ctx))

    routed = {}
    for label, payload, _want in _CASES:
        desc = _run_execution(ctx, sm_arn, payload)
        assert desc["status"] == "SUCCEEDED", (
            f"[{label}] execution must succeed, got {desc['status']!r} "
            f"error={desc.get('error')!r} cause={desc.get('cause')!r}"
        )
        routed[label] = (json.loads(desc["output"]), desc["executionArn"])
    wrong = {label: routed[label][0] for label, _p, want in _CASES if routed[label][0] != want}
    assert not wrong, (
        f"Choice routed incorrectly: got {wrong!r}; expected "
        f"{ {label: want for label, _p, want in _CASES}!r}"
    )
    # The route is taken from the history too, so an output that merely echoes a literal cannot
    # stand in for the transition.
    label, _p, want = _CASES[0]
    entered = _entered(_history(ctx, routed[label][1]))
    assert entered == ["C", want], f"[{label}] entered {entered!r}, expected ['C', {want!r}]"


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
