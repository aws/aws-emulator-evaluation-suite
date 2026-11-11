"""deep-sfn-language-path-pipeline-applies-in-documented-order."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-sfn-language-path-pipeline-applies-in-documented-order"
GROUP = 'input_output_processing'
SERVICES = ['stepfunctions']


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """On one Parallel state, InputPath, Parameters, ResultSelector, ResultPath (onto the raw input) and
    OutputPath apply in the documented order, each leaving a distinct mark in the output; ResultPath
    '$' replaces the input and ResultPath null discards the result."""
    definition = {
        "StartAt": "Pipeline",
        "States": {
            "Pipeline": {
                "Type": "Parallel",
                "InputPath": "$.inner",
                "Parameters": {"fromInput.$": "$.val", "lit": "P"},
                "Branches": [
                    {"StartAt": "Seen", "States": {"Seen": {
                        "Type": "Pass", "Parameters": {"seen.$": "$", "tag": "b0"}, "End": True}}},
                    {"StartAt": "Fixed", "States": {"Fixed": {
                        "Type": "Pass", "Result": {"tag": "b1"}, "End": True}}},
                ],
                "ResultSelector": {"first.$": "$[0].seen", "second.$": "$[1].tag"},
                "ResultPath": "$.inner.res",
                "OutputPath": "$.inner",
                "Next": "Discard",
            },
            "Discard": {"Type": "Pass", "Result": {"gone": True}, "ResultPath": None,
                        "Next": "Replace"},
            "Replace": {"Type": "Pass", "Result": {"replaced": True, "n": 2}, "ResultPath": "$",
                        "Next": "AfterReplace"},
            "AfterReplace": {"Type": "Pass", "End": True},
        },
    }
    sm_arn = _create_state_machine(ctx, definition, _create_sfn_role(ctx))
    payload = {"inner": {"val": 7, "keep": "k"}, "outer": "drop"}
    desc = _run_execution(ctx, sm_arn, payload)
    assert desc["status"] == "SUCCEEDED", (
        f"execution must succeed, got {desc['status']!r} error={desc.get('error')!r} "
        f"cause={desc.get('cause')!r}"
    )
    assert json.loads(desc["output"]) == {"replaced": True, "n": 2}, (
        f"ResultPath '$' must replace the whole input with the Result, got {desc['output']!r}"
    )

    events = _history(ctx, desc["executionArn"])
    exits = {e["stateExitedEventDetails"]["name"]: json.loads(e["stateExitedEventDetails"]["output"])
             for e in events if e["type"].endswith("StateExited")}
    want_pipeline = {"val": 7, "keep": "k",
                     "res": {"first": {"fromInput": 7, "lit": "P"}, "second": "b1"}}
    assert exits.get("Pipeline") == want_pipeline, (
        f"the five-filter pipeline produced {exits.get('Pipeline')!r}, expected {want_pipeline!r}"
    )
    assert "outer" not in exits["Pipeline"], (
        f"OutputPath '$.inner' must drop the top-level 'outer' key: {exits['Pipeline']!r}"
    )
    seen = exits["Pipeline"]["res"]["first"]
    assert "keep" not in seen and "val" not in seen, (
        f"the branch saw {seen!r}: Parameters must REPLACE the InputPath-filtered input, not merge"
    )
    assert exits.get("Discard") == want_pipeline, (
        f"ResultPath null must pass the input through unchanged, got {exits.get('Discard')!r}"
    )
    assert "gone" not in json.dumps(exits.get("Discard")), (
        f"ResultPath null leaked the discarded Result: {exits.get('Discard')!r}"
    )
    assert exits.get("Replace") == {"replaced": True, "n": 2}, (
        f"ResultPath '$' state output was {exits.get('Replace')!r}"
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
