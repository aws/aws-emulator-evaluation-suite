"""deploy-dynamodb-provisioned-billing-without-throughput-rejected-at-stack-create."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-dynamodb-provisioned-billing-without-throughput-rejected-at-stack-create"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb", "stepfunctions"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}

# CloudFormation's resource-handler wrapping of the handler's own validation error; the token varies.
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>[^"]*)" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)


def _role_props() -> dict:
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


def _template(*, table_name: str, sm_name: str, provisioned: bool) -> str:
    sm_definition = json.dumps({"StartAt": "Only", "States": {"Only": {"Type": "Pass", "End": True}}})
    table_props = {
        "TableName": table_name,
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    }
    if provisioned:
        table_props["BillingMode"] = "PROVISIONED"
    else:
        table_props["BillingMode"] = "PAY_PER_REQUEST"
    return json.dumps({
        "Resources": {
            "MyTable": {"Type": "AWS::DynamoDB::Table", "Properties": table_props},
            "SfnRole": _role_props(),
            "MyStateMachine": {
                "Type": "AWS::StepFunctions::StateMachine",
                "Properties": {
                    "StateMachineName": sm_name,
                    "RoleArn": {"Fn::GetAtt": ["SfnRole", "Arn"]},
                    "DefinitionString": sm_definition,
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


def _resource_create_failed_reason(cf, stack_name: str, logical_id: str) -> str:
    hits = [
        e for e in _stack_events(cf, stack_name)
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(hits) == 1, (
        f"expected exactly one CREATE_FAILED event for {logical_id}, got "
        f"{[(e['ResourceStatus'], e.get('ResourceStatusReason')) for e in _stack_events(cf, stack_name) if e['LogicalResourceId'] == logical_id]!r}"
    )
    return hits[0].get("ResourceStatusReason") or ""


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CFN stack whose DynamoDB table declares BillingMode PROVISIONED with no
    ProvisionedThroughput fails that resource at DynamoDB's own parameter validation and rolls
    back without creating the table or the sibling state machine; PAY_PER_REQUEST deploys both.
    """
    cf = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    sfn = ctx.client("stepfunctions")

    bad_stack = ctx.unique_name("sim2real-cfnddb-bad-")
    bad_table_name = ctx.unique_name("sim2real-tbl-bad-")
    bad_sm_name = ctx.unique_name("sim2real-sm-bad-")

    cf.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(table_name=bad_table_name, sm_name=bad_sm_name, provisioned=True),
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
        f"stack with BillingMode PROVISIONED and no ProvisionedThroughput ended in {status!r}, "
        f"expected ROLLBACK_COMPLETE"
    )

    reason = _resource_create_failed_reason(cf, bad_stack, "MyTable")
    match = _REASON.match(reason)
    assert match is not None, f"MyTable's CREATE_FAILED reason is not a resource-handler message: {reason!r}"
    got_error = (match["message"], match["handler"])
    want_error = ("Property ProvisionedThroughput cannot be empty", "InvalidRequest")
    assert got_error == want_error, f"MyTable CREATE_FAILED reason: expected {want_error!r}, got {got_error!r}"

    table_code, table_message = _error(lambda: ddb.describe_table(TableName=bad_table_name))
    assert table_code == "ResourceNotFoundException", (
        f"DescribeTable on the never-created table {bad_table_name!r} returned {table_code!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    expected_table_message = f"Requested resource not found: Table: {bad_table_name} not found"
    assert table_message == expected_table_message, (
        f"expected message {expected_table_message!r}, got {table_message!r}"
    )

    bad_sm_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{bad_sm_name}"
    sm_code, sm_message = _error(lambda: sfn.describe_state_machine(stateMachineArn=bad_sm_arn))
    assert sm_code == "StateMachineDoesNotExist", (
        f"DescribeStateMachine on the never-created machine {bad_sm_arn!r} returned {sm_code!r}, "
        f"expected 'StateMachineDoesNotExist'"
    )
    expected_sm_message = f"State Machine Does Not Exist: '{bad_sm_arn}'"
    assert sm_message == expected_sm_message, (
        f"expected message {expected_sm_message!r}, got {sm_message!r}"
    )

    good_stack = ctx.unique_name("sim2real-cfnddb-good-")
    good_table_name = ctx.unique_name("sim2real-tbl-good-")
    good_sm_name = ctx.unique_name("sim2real-sm-good-")
    cf.create_stack(
        StackName=good_stack,
        TemplateBody=_template(table_name=good_table_name, sm_name=good_sm_name,
                               provisioned=False),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cf, good_stack))
    cf.get_waiter("stack_create_complete").wait(
        StackName=good_stack, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    good_status = cf.describe_stacks(StackName=good_stack)["Stacks"][0]["StackStatus"]
    assert good_status == "CREATE_COMPLETE", (
        f"positive control under PAY_PER_REQUEST ended in {good_status!r}, expected "
        f"CREATE_COMPLETE — the rejection above must be about the missing throughput, not the "
        f"account"
    )
    good_sm_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{good_sm_name}"
    assert ddb.describe_table(TableName=good_table_name)["Table"]["BillingModeSummary"][
        "BillingMode"] == "PAY_PER_REQUEST", "the control table must read back PAY_PER_REQUEST"
    roles = _stack_roles(cf, good_stack)

    for stack_name in (bad_stack, good_stack):
        _delete_stack(cf, stack_name)
        got = _error(lambda stack_name=stack_name: cf.describe_stacks(StackName=stack_name))
        assert got == ("ValidationError", f"Stack with id {stack_name} does not exist"), (
            f"DescribeStacks after the in-band delete of {stack_name}: {got!r}"
        )
    got = _error(lambda: ddb.describe_table(TableName=good_table_name))
    assert got == ("ResourceNotFoundException",
                   f"Requested resource not found: Table: {good_table_name} not found"), (
        f"the control table after its stack delete: {got!r}"
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
