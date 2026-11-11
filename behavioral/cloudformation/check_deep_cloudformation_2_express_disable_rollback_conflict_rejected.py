"""deep-cloudformation-2-express-disable-rollback-conflict-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cloudformation-2-express-disable-rollback-conflict-rejected"
GROUP = 'deploy'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


def _wait_terminal(cf, stack_id, *, timeout_s=600, interval_s=3):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        last = stack["StackStatus"]
        if last in _TERMINAL_STATES:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_id} still {last!r} after {timeout_s}s")
        time.sleep(interval_s)


def _resource_statuses(cf, stack_id):
    seen = set()
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for ev in page["StackEvents"]:
            seen.add((ev["LogicalResourceId"], ev["ResourceStatus"]))
    return seen


def _delete_param_quietly(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise


def _delete_stack(cf, stack_id):
    try:
        cf.delete_stack(StackName=stack_id)
        _wait_terminal(cf, stack_id)
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"stack {stack_id} teardown failed: {exc!r}") from exc


def _template(name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "A": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": name, "Type": "String", "Value": "resource-a"},
            },
            "B": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": {"Ref": "A"}, "Type": "String", "Value": "resource-b"},
            },
        },
    })


@tags("plane:control", "concern:deploy", "axis:rejection", "cap:c1")
def run(ctx) -> None:
    """Conflicting top-level vs DeploymentConfig DisableRollback is refused with no stack created;
    the agreeing pair is accepted and its no-rollback effect is real."""
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    stack_name = ctx.unique_name("sim2real-behav-drconf-")
    param = "/" + ctx.unique_name("sim2real-behav-drconf-")
    ctx.on_cleanup(lambda: _delete_param_quietly(ssm, param))

    # Negative: the two rollback switches disagree.
    try:
        resp = cf.create_stack(
            StackName=stack_name, TemplateBody=_template(param),
            DeploymentConfig={"Mode": "EXPRESS", "DisableRollback": False},
            DisableRollback=True,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        # Registered in the try body, on the statement after the apply: if the refusal ever stops
        # happening, the stack it created is torn down before anything else can raise.
        ctx.on_cleanup(lambda: _delete_stack(cf, resp["StackId"]))
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        msg = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            f"conflicting DisableRollback values were accepted and created stack "
            f"{resp['StackId']!r}"
        )
    assert code == "ValidationError", (
        f"conflicting DisableRollback must be refused with ValidationError; got {code!r}"
    )
    assert msg == (
        "Conflicting values for DisableRollback: the top-level DisableRollback and "
        "DeploymentConfig.DisableRollback must not be set to different values."
    ), msg

    # Effect absent: no stack exists under the name the refused call used.
    try:
        found = cf.describe_stacks(StackName=stack_name)["Stacks"]
        absent = None
    except ClientError as exc:
        found = None
        absent = exc.response.get("Error", {}).get("Code")
        absent_msg = exc.response.get("Error", {}).get("Message")
    assert absent == "ValidationError", (
        f"the refused CreateStack must leave no stack {stack_name!r}; DescribeStacks -> "
        f"{found!r} / {absent!r}"
    )
    assert absent_msg == f"Stack with id {stack_name} does not exist", absent_msg

    # Positive control: same name and template, the two values agreeing; resource B's designed
    # runtime failure must leave the stack CREATE_FAILED with resource A still alive at SSM.
    stack_id = cf.create_stack(
        StackName=stack_name, TemplateBody=_template(param),
        DeploymentConfig={"Mode": "EXPRESS", "DisableRollback": True},
        DisableRollback=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))

    stack = _wait_terminal(cf, stack_id)
    events = _resource_statuses(cf, stack_id)
    assert ("A", "CREATE_COMPLETE") in events and ("B", "CREATE_FAILED") in events, (
        f"control: A must be created and B must fail by design; events={sorted(events)!r}"
    )
    assert stack["StackStatus"] == "CREATE_FAILED", (
        f"control: agreed DisableRollback=true must leave the failed create un-rolled-back; got "
        f"{stack['StackStatus']!r}"
    )
    assert stack.get("StackStatusReason") == (
        "The following resource(s) failed to create via Express Mode: [B]. "
    ), stack.get("StackStatusReason")
    assert stack.get("DisableRollback") is True, (
        f"control: stack must report DisableRollback=True; got {stack.get('DisableRollback')!r}"
    )
    value = ssm.get_parameter(Name=param)["Parameter"]["Value"]
    assert value == "resource-a", f"control: A must survive at SSM; GetParameter -> {value!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
