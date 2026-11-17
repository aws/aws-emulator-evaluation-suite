"""create-state-machine-next-and-end-together-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-next-and-end-together-rejected"
GROUP = "definition_validation"
SERVICES = ["stepfunctions"]

_EXPECTED = ("Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: There should only be one "
             "of the following fields: [Next, End] at /States/A'")


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """CreateStateMachine refuses a Pass state carrying both Next and End with the exact schema
    message and creates nothing; the same state with End alone is created and runs to SUCCEEDED."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    done = {"Type": "Pass", "End": True}

    good = {"StartAt": "A", "States": {"A": {"Type": "Pass", "End": True}}}
    arn = _create_state_machine(ctx, role_arn, good)
    exe = _run_to_terminal(sfn, arn, {"k": "v"})
    assert exe["status"] == "SUCCEEDED", f"the End-only machine must succeed, got {exe!r}"
    assert json.loads(exe["output"]) == {"k": "v"}, f"Pass must echo its input, got {exe['output']!r}"

    bad = {"StartAt": "A", "States": {"A": {"Type": "Pass", "Next": "B", "End": True}, "B": done}}
    name, code, message = _refused_create(ctx, role_arn, bad)
    assert code == "InvalidDefinition", f"expected InvalidDefinition, got {code!r}"
    assert message == _EXPECTED, f"expected {_EXPECTED!r}, got {message!r}"
    assert not _listed(sfn, name), f"{name} must not exist after an InvalidDefinition refusal"


_TRUST = json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}]})


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_sfn_role(ctx) -> str:
    """A role Step Functions can assume; these definitions call no other service."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnrole-")
    arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=_TRUST, Description=f"sim2real {CHECK}",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create_state_machine(ctx, role_arn, definition) -> str:
    """CreateStateMachine, retrying only AccessDeniedException while the fresh role propagates."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-")
    deadline = time.monotonic() + 120.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=json.dumps(definition), roleArn=role_arn,
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn),
                                     "StateMachineDoesNotExist"))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(2.0)


def _refused_create(ctx, role_arn, definition):
    """CreateStateMachine expected to be refused; a wrongly created machine is still deleted."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-bad-")
    try:
        arn = sfn.create_state_machine(
            name=name, definition=json.dumps(definition), roleArn=role_arn,
            tags=[{"key": "sim2real", "value": CHECK}],
        )["stateMachineArn"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return name, err.get("Code"), err.get("Message")
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn),
                             "StateMachineDoesNotExist"))
    raise AssertionError(f"expected CreateStateMachine to be refused, it created {name!r}")


def _listed(sfn, name) -> bool:
    """Whether a state machine called ``name`` appears anywhere in the paginated listing."""
    for page in sfn.get_paginator("list_state_machines").paginate():
        if any(sm["name"] == name for sm in page.get("stateMachines", [])):
            return True
    return False


def _run_to_terminal(sfn, sm_arn, payload) -> dict:
    """Start an execution and poll DescribeExecution to its terminal status."""
    exe = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(payload))["executionArn"]
    deadline = time.monotonic() + 120.0
    while True:
        desc = sfn.describe_execution(executionArn=exe)
        if desc["status"] != "RUNNING":
            return desc
        assert time.monotonic() < deadline, f"execution still RUNNING at the deadline: {desc!r}"
        time.sleep(1.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
