"""deploy-cfn-dynamodb-table-kinesis-stream-specification-nonexistent-stream-rejected."""

from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-dynamodb-table-kinesis-stream-specification-nonexistent-stream-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb", "kinesis"]

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
_STACK_TIMEOUT_S = 900.0
_DESTINATION_TIMEOUT_S = 600.0


_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)
_NOT_STABILIZED = (
    "NotStabilized",
    "Resource of type 'AWS::DynamoDB::Table' with identifier '<name>' did not stabilize.",
)


def _good_template(stream_name: str, table_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Stream": {
                    "Type": "AWS::Kinesis::Stream",
                    "Properties": {"Name": stream_name, "ShardCount": 1},
                },
                "Table": {
                    "Type": "AWS::DynamoDB::Table",
                    "Properties": {
                        "TableName": table_name,
                        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                        "BillingMode": "PROVISIONED",
                        "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
                        "KinesisStreamSpecification": {
                            "StreamArn": {"Fn::GetAtt": ["Stream", "Arn"]}
                        },
                        "Tags": [{"Key": "sim2real", "Value": CHECK}],
                    },
                },
            },
            "Outputs": {"StreamArn": {"Value": {"Fn::GetAtt": ["Stream", "Arn"]}}},
        }
    )


def _broken_template(table_name: str, missing_stream_arn: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Table": {
                    "Type": "AWS::DynamoDB::Table",
                    "Properties": {
                        "TableName": table_name,
                        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                        "BillingMode": "PROVISIONED",
                        "ProvisionedThroughput": {"ReadCapacityUnits": 1, "WriteCapacityUnits": 1},
                        "KinesisStreamSpecification": {"StreamArn": missing_stream_arn},
                        "Tags": [{"Key": "sim2real", "Value": CHECK}],
                    },
                },
            },
        }
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_stack(ctx, cfn, stack_id: str, terminal: set) -> dict:
    """Poll DescribeStacks until the stack reaches one of ``terminal``; raise on timeout."""
    timeout_s = _budget_s(ctx, _STACK_TIMEOUT_S)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if last["StackStatus"] in terminal:
            return last
        time.sleep(5.0)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"stack {stack_id} reaching {sorted(terminal)!r}: the run budget ended "
            f"first; not graded"
        )
    raise AssertionError(
        f"stack did not reach any of {sorted(terminal)!r} within {timeout_s}s "
        f"(last={last and last['StackStatus']!r})"
    )


def _destinations(ddb, table_name: str) -> list:
    """``(StreamArn, DestinationStatus)`` of every Kinesis streaming destination of the table."""
    resp = ddb.describe_kinesis_streaming_destination(TableName=table_name)
    return [
        (d["StreamArn"], d["DestinationStatus"])
        for d in resp.get("KinesisDataStreamDestinations", [])
    ]


def _poll_destinations_active(ctx, ddb, table_name: str, stream_arn: str) -> list:
    """Poll until the table's destinations are exactly ``[(stream_arn, "ACTIVE")]``."""
    timeout_s = _budget_s(ctx, _DESTINATION_TIMEOUT_S)
    deadline = time.monotonic() + timeout_s
    want = [(stream_arn, "ACTIVE")]
    last = None
    while time.monotonic() < deadline:
        last = _destinations(ddb, table_name)
        if last == want:
            return last
        time.sleep(5.0)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"destination {stream_arn} reaching ACTIVE: the run budget ended first; not graded"
        )
    raise AssertionError(
        f"destination for {stream_arn!r} did not reach ACTIVE within {timeout_s}s (last={last!r})"
    )


def _outputs(stack: dict) -> dict:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _stack_events(cfn, stack_id: str) -> list:
    events = [
        e
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id)
        for e in page["StackEvents"]
    ]
    return list(reversed(events))


def _resource_failure_reason(cfn, stack_id: str, logical_id: str) -> str:
    reasons = [
        e.get("ResourceStatusReason")
        for e in _stack_events(cfn, stack_id)
        if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert len(reasons) == 1, (
        f"expected exactly one CREATE_FAILED event for {logical_id!r}; got {reasons!r}"
    )
    return reasons[0]


def _masked(text: str, *names: str) -> str:
    """``text`` with RequestToken and this run's own resource names replaced by placeholders."""
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def _handler_reason(reason: str, *names: str) -> tuple:
    """``(HandlerErrorCode, masked message)`` of a resource-handler failure reason."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return m["code"], _masked(m["message"], *names)


def _delete_stack_and_wait(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by id, whatever its state, and wait for DELETE_COMPLETE; anything else
    raises."""
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + _budget_s(ctx, _STACK_TIMEOUT_S)
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            break
        time.sleep(5.0)
    raise RuntimeError(f"stack did not delete (last status {status!r})")


def _partition_of(arn: str) -> str:
    """The partition field of an ARN AWS returned."""
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], f"not an ARN: {arn!r}"
    return parts[1]


def _table_absent(ddb, table_name: str) -> bool:
    """Whether DescribeTable refuses ``table_name`` with its exact not-found pair."""
    want = (
        "ResourceNotFoundException",
        f"Requested resource not found: Table: {table_name} not found",
    )
    try:
        ddb.describe_table(TableName=table_name)
    except ClientError as exc:
        err = exc.response["Error"]
        found = (err.get("Code"), err.get("Message"))
        assert found == want, f"expected {want!r} once the table is gone, got {found!r}"
        return True
    return False


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation DynamoDB table whose KinesisStreamSpecification.StreamArn names a Kinesis
    stream that was never created fails NotStabilized and is rolled back; pointed by Fn::GetAtt at
    a stream in the same stack it deploys with that stream as its one ACTIVE destination."""
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    kinesis = ctx.client("kinesis")

    control_stream = ctx.unique_name("sim2real-cfnkds-ctl-stream-")
    control_table = ctx.unique_name("sim2real-cfnkds-ctl-table-")
    control_stack_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-cfnkds-ctl-stack-"),
        TemplateBody=_good_template(control_stream, control_table),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, cfn, control_stack_id))

    control_stack = _poll_stack(ctx, cfn, control_stack_id, _CREATE_TERMINAL)
    assert control_stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the control stack (a real stream) must deploy; got {control_stack['StackStatus']!r}: "
        f"{control_stack.get('StackStatusReason')!r}"
    )
    partition = _partition_of(control_stack_id)
    control_stream_arn = (
        f"arn:{partition}:kinesis:{ctx.region}:{ctx.account}:stream/{control_stream}"
    )
    control_outputs = _outputs(control_stack)
    assert control_outputs["StreamArn"] == control_stream_arn, (
        f"Fn::GetAtt Stream.Arn is {control_outputs['StreamArn']!r}, expected {control_stream_arn!r}"
    )
    summary = kinesis.describe_stream_summary(StreamName=control_stream)["StreamDescriptionSummary"]
    got_stream = (summary["StreamARN"], summary["StreamStatus"], summary["OpenShardCount"])
    assert got_stream == (control_stream_arn, "ACTIVE", 1), (
        f"DescribeStreamSummary of the stack's stream is {got_stream!r}, expected "
        f"{(control_stream_arn, 'ACTIVE', 1)!r}"
    )
    _poll_destinations_active(ctx, ddb, control_table, control_stream_arn)

    missing_name = ctx.unique_name("sim2real-cfnkds-missing-")
    missing_stream_arn = f"arn:{partition}:kinesis:{ctx.region}:{ctx.account}:stream/{missing_name}"
    broken_table = ctx.unique_name("sim2real-cfnkds-broken-table-")
    broken_stack_id = cfn.create_stack(
        StackName=ctx.unique_name("sim2real-cfnkds-broken-stack-"),
        TemplateBody=_broken_template(broken_table, missing_stream_arn),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, cfn, broken_stack_id))

    broken_stack = _poll_stack(ctx, cfn, broken_stack_id, _CREATE_TERMINAL)
    assert broken_stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"the stack referencing a nonexistent stream must roll back; got "
        f"{broken_stack['StackStatus']!r}: {broken_stack.get('StackStatusReason')!r}"
    )
    reason = _resource_failure_reason(cfn, broken_stack_id, "Table")
    got = _handler_reason(reason, broken_table)
    assert got == _NOT_STABILIZED, (
        f"expected (message, handler code) {_NOT_STABILIZED!r}, got {got!r}"
    )
    deadline = time.monotonic() + _budget_s(ctx, _DESTINATION_TIMEOUT_S)
    absent = _table_absent(ddb, broken_table)
    while not absent and time.monotonic() < deadline:
        time.sleep(5.0)
        absent = _table_absent(ddb, broken_table)
    if not absent and _budget_spent(ctx):
        raise TimeoutError(
            f"table {broken_table} going away: the run budget ended first; not graded"
        )
    assert absent, f"table {broken_table!r} must not exist after the stack rolled back"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
