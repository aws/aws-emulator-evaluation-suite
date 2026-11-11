"""deploy-cfn-dynamodb-getatt-unknown-attribute-rejected-after-the-table-is-built."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-dynamodb-getatt-unknown-attribute-rejected-after-the-table-is-built"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb"]

_BAD_ATTRIBUTE = "NoSuchAttr"
_REASON = f"Requested attribute {_BAD_ATTRIBUTE} does not exist in schema for AWS::DynamoDB::Table"


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Fn::GetAtt naming an attribute AWS::DynamoDB::Table lacks passes ValidateTemplate and
    CreateStack, then fails the stack with the exact schema reason and rolls back, deleting the table;
    added by UpdateStack, it rolls the update back with outputs and table untouched."""
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")

    # POSITIVE CONTROL: the same table with only the supported Arn output deploys.
    good_table = ctx.unique_name("sim2real-xsvc-cfnga-ok-")
    good = cfn.create_stack(StackName=ctx.unique_name("sim2real-xsvc-cfnga-ok-stk-"),
                            TemplateBody=_template(good_table, bad=False),
                            Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, good))

    bad_table = ctx.unique_name("sim2real-xsvc-cfnga-bad-")
    bad_template = _template(bad_table, bad=True)
    validated = cfn.validate_template(TemplateBody=bad_template)
    assert validated.get("Parameters") == [], (
        f"ValidateTemplate accepts the template; it answered {validated!r}")
    bad = cfn.create_stack(StackName=ctx.unique_name("sim2real-xsvc-cfnga-bad-stk-"),
                           TemplateBody=bad_template,
                           Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, bad))

    stack = _poll_stack(cfn, good, _CREATE_TERMINAL)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the control stack must deploy; got {stack['StackStatus']!r}")
    control_outputs = _outputs(stack)
    control = ddb.describe_table(TableName=good_table)["Table"]
    assert control_outputs == {"Arn": control["TableArn"]}, (
        f"the control stack's outputs must be exactly its Arn; got keys {sorted(control_outputs)!r}")

    stack = _poll_stack(cfn, bad, _CREATE_TERMINAL)
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"an unknown GetAtt attribute must fail the stack and roll it back; got "
        f"{stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}")
    events = _events(cfn, bad)
    table_timeline = [e["ResourceStatus"] for e in events if e["LogicalResourceId"] == "Table"]
    assert table_timeline[-2:] == ["DELETE_IN_PROGRESS", "DELETE_COMPLETE"] \
        and "CREATE_COMPLETE" in table_timeline, (
            f"the table must be built and then deleted by the rollback; its timeline was "
            f"{table_timeline!r}")
    reasons = [e.get("ResourceStatusReason") for e in events
               if e["LogicalResourceId"] == e["StackName"] and e["ResourceStatus"] == "ROLLBACK_IN_PROGRESS"]
    assert reasons == [f"{_REASON}. Rollback requested by user."], (
        f"the stack's ROLLBACK_IN_PROGRESS reason must name the unknown attribute; got {reasons!r}")
    err = _error(lambda: ddb.describe_table(TableName=bad_table))
    assert err["Code"] == "ResourceNotFoundException", f"the rolled-back table: got {err!r}"
    assert err["Message"] == f"Requested resource not found: Table: {bad_table} not found", (
        f"the rolled-back table: message was {err['Message']!r}")

    # The same bad output added to the healthy stack: the update rolls back, nothing changes.
    cfn.update_stack(StackName=good, TemplateBody=_template(good_table, bad=True))
    stack = _poll_stack(cfn, good, _UPDATE_TERMINAL)
    assert stack["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"adding the unknown GetAtt by update must roll the update back; got "
        f"{stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}")
    reasons = [e.get("ResourceStatusReason") for e in _events(cfn, good)
               if e["LogicalResourceId"] == e["StackName"]
               and e["ResourceStatus"] == "UPDATE_ROLLBACK_IN_PROGRESS"]
    assert reasons == [_REASON], (
        f"the stack's UPDATE_ROLLBACK_IN_PROGRESS reason must name the unknown attribute; got "
        f"{reasons!r}")
    assert _outputs(stack) == control_outputs, (
        f"a rolled-back update must leave the outputs as they were; got keys {sorted(_outputs(stack))!r}")
    after = ddb.describe_table(TableName=good_table)["Table"]
    assert (after["TableId"], after["TableStatus"]) == (control["TableId"], "ACTIVE"), (
        f"the control table must be the same ACTIVE table after the rollback; status "
        f"{after['TableStatus']!r}, same id {after['TableId'] == control['TableId']}")


def _error(fn) -> dict:
    """The ClientError's Error dict; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _template(table: str, *, bad: bool) -> str:
    outputs = {"Arn": {"Value": {"Fn::GetAtt": ["Table", "Arn"]}}}
    if bad:
        outputs["Bad"] = {"Value": {"Fn::GetAtt": ["Table", _BAD_ATTRIBUTE]}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Table": {"Type": "AWS::DynamoDB::Table", "Properties": {
            "TableName": table,
            "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }}},
        "Outputs": outputs,
    })


STACK_TIMEOUT_S = 780.0
TEARDOWN_TIMEOUT_S = 600.0
_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
_UPDATE_TERMINAL = {"UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
                    "UPDATE_ROLLBACK_FAILED"}


def _poll_stack(cfn, stack_id: str, terminal: set) -> dict:
    """Poll DescribeStacks until the stack reaches one of `terminal`; raise on timeout."""
    deadline = time.monotonic() + STACK_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if last["StackStatus"] in terminal:
            return last
        time.sleep(5.0)
    raise AssertionError(
        f"stack did not reach any of {sorted(terminal)!r} within {STACK_TIMEOUT_S}s "
        f"(last={last and last['StackStatus']!r})")


def _poll(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    """Poll probe() until predicate(result); raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last result: {last!r}")


def _outputs(stack: dict) -> dict:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _events(cfn, stack_id: str) -> list:
    """Every stack event, oldest first."""
    events = [e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
              for e in page["StackEvents"]]
    return list(reversed(events))


def _physical_id(cfn, stack_id: str, logical: str) -> str:
    resources = [r for page in cfn.get_paginator("list_stack_resources").paginate(
        StackName=stack_id) for r in page["StackResourceSummaries"]]
    match = [r["PhysicalResourceId"] for r in resources if r["LogicalResourceId"] == logical]
    assert len(match) == 1, f"the stack must own exactly one {logical}; it lists {resources!r}"
    return match[0]


def _delete_stack_and_wait(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; anything else raises."""
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + TEARDOWN_TIMEOUT_S
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            break
        time.sleep(5.0)
    raise RuntimeError(f"stack did not delete (last status {status!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
