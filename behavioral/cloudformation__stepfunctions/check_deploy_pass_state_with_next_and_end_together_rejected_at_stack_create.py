"""deploy-pass-state-with-next-and-end-together-rejected-at-stack-create."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-pass-state-with-next-and-end-together-rejected-at-stack-create"
GROUP = "deploy"
SERVICES = ["cloudformation", "stepfunctions"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}

# CloudFormation's resource-handler wrapping of the service error; the request id and token vary.
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)


def _role_props():
    return {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            },
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
        },
    }


def _template(sm_name: str, definition_string: str) -> str:
    return json.dumps({
        "Resources": {
            "ExecRole": _role_props(),
            "MyStateMachine": {
                "Type": "AWS::StepFunctions::StateMachine",
                "Properties": {
                    "StateMachineName": sm_name,
                    "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "DefinitionString": definition_string,
                    "Tags": [{"Key": "sim2real", "Value": CHECK}],
                },
            },
        },
    })


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_stack(cf, stack_name: str) -> None:
    cf.delete_stack(StackName=stack_name)
    cf.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _stack_events(cf, stack_name: str) -> list[dict]:
    out = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        out.extend(page["StackEvents"])
    return out


def _machine_create_failed_reason(cf, stack_name: str) -> str:
    hits = [
        e for e in _stack_events(cf, stack_name)
        if e["LogicalResourceId"] == "MyStateMachine" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(hits) == 1, (
        f"expected exactly one CREATE_FAILED event for MyStateMachine, got "
        f"{[(e['ResourceStatus'], e.get('ResourceStatusReason')) for e in _stack_events(cf, stack_name) if e['LogicalResourceId'] == 'MyStateMachine']!r}"
    )
    return hits[0].get("ResourceStatusReason") or ""


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN stack whose state machine has a Pass state declaring both `Next` and `End` fails
    that resource with Step Functions' schema-validation diagnostic, rolls the stack back and
    never brings the state machine into existence; the same template with only `End` deploys.
    """
    cf = ctx.client("cloudformation")
    sfn = ctx.client("stepfunctions")

    bad_stack = ctx.unique_name("sim2real-cfnsfn-bad-")
    bad_sm_name = ctx.unique_name("sim2real-sm-bad-")
    bad_definition = json.dumps({
        "StartAt": "Only",
        "States": {"Only": {"Type": "Pass", "Next": "Only", "End": True}},
    })

    cf.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(bad_sm_name, bad_definition),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cf, bad_stack))

    status = _poll_until(
        lambda: cf.describe_stacks(StackName=bad_stack)["Stacks"][0]["StackStatus"],
        lambda s: s in _TERMINAL,
        description=f"stack {bad_stack} terminal",
    )
    assert status == "ROLLBACK_COMPLETE", (
        f"stack with a Pass state declaring both Next and End ended in {status!r}, expected "
        f"ROLLBACK_COMPLETE"
    )

    reason = _machine_create_failed_reason(cf, bad_stack)
    match = _REASON.match(reason)
    assert match is not None, f"MyStateMachine's CREATE_FAILED reason is not a resource-handler message: {reason!r}"
    got_error = (match["message"], match["service"], match["status"], match["handler"])
    want_error = (
        "Invalid State Machine Definition: 'SCHEMA_VALIDATION_FAILED: There should only be one of "
        "the following fields: [Next, End] at /States/Only'",
        "Sfn", "400", "InvalidRequest",
    )
    assert got_error == want_error, f"MyStateMachine CREATE_FAILED reason: expected {want_error!r}, got {got_error!r}"

    bad_sm_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{bad_sm_name}"
    code, message = _error(lambda: sfn.describe_state_machine(stateMachineArn=bad_sm_arn))
    assert code == "StateMachineDoesNotExist", (
        f"DescribeStateMachine on the never-created machine {bad_sm_arn!r} returned {code!r}, "
        f"expected 'StateMachineDoesNotExist'"
    )
    expected_message = f"State Machine Does Not Exist: '{bad_sm_arn}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    good_stack = ctx.unique_name("sim2real-cfnsfn-good-")
    good_sm_name = ctx.unique_name("sim2real-sm-good-")
    good_definition = json.dumps(
        {"StartAt": "Only", "States": {"Only": {"Type": "Pass", "End": True}}}
    )
    cf.create_stack(
        StackName=good_stack,
        TemplateBody=_template(good_sm_name, good_definition),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cf, good_stack))
    cf.get_waiter("stack_create_complete").wait(
        StackName=good_stack, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    good_status = cf.describe_stacks(StackName=good_stack)["Stacks"][0]["StackStatus"]
    assert good_status == "CREATE_COMPLETE", (
        f"positive control with only End set ended in {good_status!r}, expected CREATE_COMPLETE "
        f"— the rejection above must be about the conflicting fields, not the account"
    )
    good_sm_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{good_sm_name}"
    definition = json.loads(sfn.describe_state_machine(stateMachineArn=good_sm_arn)["definition"])
    assert definition == json.loads(good_definition), (
        f"the control state machine reads back definition {definition!r}"
    )
    roles = _stack_roles(cf, good_stack)

    for stack_name in (bad_stack, good_stack):
        _delete_stack(cf, stack_name)
        got = _error(lambda stack_name=stack_name: cf.describe_stacks(StackName=stack_name))
        assert got == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
            f"DescribeStacks after the in-band delete of {stack_name}: {got!r}"
        )
    got = _error(lambda: sfn.describe_state_machine(stateMachineArn=good_sm_arn))
    assert got == ("StateMachineDoesNotExist", f"State Machine Does Not Exist: '{good_sm_arn}'"), (
        f"the control state machine after its stack delete: {got!r}"
    )
    _assert_roles_gone(ctx.client("iam"), roles)


def _stack_roles(cfn, stack: str) -> list[str]:
    """Names of every AWS::IAM::Role the stack created, read before its delete."""
    resources = cfn.describe_stack_resources(StackName=stack)["StackResources"]
    return sorted(r["PhysicalResourceId"] for r in resources if r["ResourceType"] == "AWS::IAM::Role")


def _assert_roles_gone(iam, roles: list[str]) -> None:
    """Each role answers NoSuchEntity with IAM's exact message."""
    for role in roles:
        try:
            iam.get_role(RoleName=role)
        except ClientError as exc:
            got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
            assert got == ("NoSuchEntity", f"The role with name {role} cannot be found."), (
                f"GetRole({role!r}) after the stack delete: {got!r}"
            )
            continue
        raise AssertionError(f"role {role!r} survived the stack delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
