"""deploy-cfn-dynamodb-getatt-stream-arn-follows-stream-view-change."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-dynamodb-getatt-stream-arn-follows-stream-view-change"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Fn::GetAtt on a CloudFormation DynamoDB table resolves Arn to TableArn and StreamArn to
    LatestStreamArn; an UpdateStack from NEW_AND_OLD_IMAGES to KEYS_ONLY keeps the TableId and Arn
    but replaces the stream, and the StreamArn output follows the new LatestStreamArn."""
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-xsvc-cfnstr-")

    stack_id = cfn.create_stack(StackName=ctx.unique_name("sim2real-xsvc-cfnstr-stk-"),
                                TemplateBody=_template(table, "NEW_AND_OLD_IMAGES"),
                                Tags=[{"Key": "sim2real", "Value": CHECK}])["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))
    stack = _poll_stack(cfn, stack_id, _CREATE_TERMINAL)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the streamed table stack must deploy; got {stack['StackStatus']!r}: "
        f"{stack.get('StackStatusReason')!r}")

    first = _outputs(stack)
    described = ddb.describe_table(TableName=table)["Table"]
    assert first["Arn"] == described["TableArn"], "GetAtt Arn differs from DescribeTable's TableArn"
    assert first["Arn"] == f"arn:aws:dynamodb:{ctx.region}:{ctx.account}:table/{table}", (
        "GetAtt Arn is not the table ARN built from this region, account and table name")
    assert first["StreamArn"] == described["LatestStreamArn"], (
        "GetAtt StreamArn differs from DescribeTable's LatestStreamArn")
    assert first["StreamArn"].startswith(first["Arn"] + "/stream/"), (
        "GetAtt StreamArn must be a stream of this table (TableArn + '/stream/<label>')")
    assert described["StreamSpecification"] == {"StreamEnabled": True,
                                                "StreamViewType": "NEW_AND_OLD_IMAGES"}, (
        f"DescribeTable StreamSpecification is {described['StreamSpecification']!r}")
    table_id = described["TableId"]

    cfn.update_stack(StackName=stack_id, TemplateBody=_template(table, "KEYS_ONLY"))
    stack = _poll_stack(cfn, stack_id, _UPDATE_TERMINAL)
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"changing StreamViewType must update the stack; got {stack['StackStatus']!r}: "
        f"{stack.get('StackStatusReason')!r}")

    second = _outputs(stack)
    described = ddb.describe_table(TableName=table)["Table"]
    assert described["TableId"] == table_id, "the TableId changed: the table was replaced"
    assert second["Arn"] == first["Arn"], "GetAtt Arn changed although the table was not replaced"
    assert described["StreamSpecification"] == {"StreamEnabled": True, "StreamViewType": "KEYS_ONLY"}, (
        f"after the update DescribeTable StreamSpecification is {described['StreamSpecification']!r}")
    assert second["StreamArn"] != first["StreamArn"], (
        "a new stream view type creates a new stream, but GetAtt StreamArn kept the old stream's ARN")
    assert second["StreamArn"] == described["LatestStreamArn"], (
        "after the update GetAtt StreamArn differs from DescribeTable's LatestStreamArn")
    assert second["StreamArn"].startswith(first["Arn"] + "/stream/"), (
        "the new StreamArn must still be a stream of the same table")


def _template(table: str, view: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Table": {"Type": "AWS::DynamoDB::Table", "Properties": {
            "TableName": table,
            "BillingMode": "PAY_PER_REQUEST",
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
            "StreamSpecification": {"StreamViewType": view},
            "Tags": [{"Key": "sim2real", "Value": CHECK}],
        }}},
        "Outputs": {"Arn": {"Value": {"Fn::GetAtt": ["Table", "Arn"]}},
                    "StreamArn": {"Value": {"Fn::GetAtt": ["Table", "StreamArn"]}}},
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
