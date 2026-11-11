"""cfn-dynamodb-table-in-place-update-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-dynamodb-table-in-place-update-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: DynamoDB's refusal of a table that no longer exists.
_NOT_FOUND_CODE = "ResourceNotFoundException"
_NOT_FOUND_MESSAGE = "Requested resource not found: Table: {table} not found"


def _template(table_name: str, read_capacity: int) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Table": {
                    "Type": "AWS::DynamoDB::Table",
                    # TableName is create-only, so changing it replaces the table.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "TableName": table_name,
                        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                        "BillingMode": "PROVISIONED",
                        "ProvisionedThroughput": {
                            "ReadCapacityUnits": read_capacity,
                            "WriteCapacityUnits": 1,
                        },
                        "Tags": _TAGS,
                    },
                },
            },
            "Outputs": {"TableArn": {"Value": {"Fn::GetAtt": ["Table", "Arn"]}}},
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation table reads back as templated, updates in place and survives replacement.

    Items round-trip; a ReadCapacityUnits change keeps the table, a TableName change under
    UpdateReplacePolicy Retain keeps the old table and item; delete: ResourceNotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-dynamodb-table.html
    """
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    first = ctx.unique_name("sim2real-cfntbl-a-")
    second = ctx.unique_name("sim2real-cfntbl-b-")
    stack_name = ctx.unique_name("sim2real-cfntbl-stack-")
    ref = {"stack": stack_name}

    # The replaced table is retained, so it outlives the stack and needs its own teardown.
    ctx.on_cleanup(lambda: _delete_table(ctx, ddb, first))
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref))

    # ---- 1. create: CloudFormation's view, DynamoDB's view, and an item round trip
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(first, 1),
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Table"] == first, (
        f"the table's physical id must be its TableName {first!r}"
    )
    first_arn = f"arn:aws:dynamodb:{ctx.region}:{ctx.account}:table/{first}"
    assert _outputs(stack)["TableArn"] == first_arn, f"GetAtt Table.Arn: {_outputs(stack)!r}"
    _assert_table(ddb, first, first_arn, read_capacity=1)
    first_key = ctx.unique_name("k-")
    first_marker = ctx.unique_name("m-")
    _assert_round_trip(ddb, first, first_key, first_marker)

    # ---- 2. in-place: a new ReadCapacityUnits, the same table and item
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(first, 2), Tags=_TAGS)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Table"] == first, "an in-place update keeps the table"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Table"), first, "Table")
    _assert_table(ddb, first, first_arn, read_capacity=2)
    _assert_item(ddb, first, first_key, first_marker)

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new table, the old one kept
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=_template(second, 2), Tags=_TAGS)
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Table"] == second, (
        f"the stack must track the replacement {second!r}"
    )
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Table"), first, second, "Table"
    )
    second_arn = f"arn:aws:dynamodb:{ctx.region}:{ctx.account}:table/{second}"
    assert _outputs(stack)["TableArn"] == second_arn, f"GetAtt after replacement: {stack!r}"
    _assert_table(ddb, second, second_arn, read_capacity=2)
    fresh = ddb.get_item(TableName=second, Key={"pk": {"S": first_key}}, ConsistentRead=True)
    assert "Item" not in fresh, f"the replacement table starts empty, it holds {fresh['Item']!r}"
    _assert_round_trip(ddb, second, ctx.unique_name("k-"), ctx.unique_name("m-"))
    _assert_table(ddb, first, first_arn, read_capacity=2)
    _assert_item(ddb, first, first_key, first_marker)

    # ---- 4. delete: DynamoDB no longer knows the stack's table
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx, lambda: ddb.describe_table(TableName=second), _NOT_FOUND_CODE, f"table {second}"
    )
    want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(table=second))
    assert got == want, f"DescribeTable after the stack delete answered {got!r}, expected {want!r}"


def _assert_table(ddb, name: str, arn: str, *, read_capacity: int) -> None:
    """DescribeTable reports the template's table exactly."""
    table = ddb.describe_table(TableName=name)["Table"]
    got = {
        "TableName": table.get("TableName"),
        "TableArn": table.get("TableArn"),
        "TableStatus": table.get("TableStatus"),
        "KeySchema": table.get("KeySchema"),
        "AttributeDefinitions": table.get("AttributeDefinitions"),
        "Read": table.get("ProvisionedThroughput", {}).get("ReadCapacityUnits"),
        "Write": table.get("ProvisionedThroughput", {}).get("WriteCapacityUnits"),
    }
    want = {
        "TableName": name,
        "TableArn": arn,
        "TableStatus": "ACTIVE",
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
        "Read": read_capacity,
        "Write": 1,
    }
    assert got == want, f"DescribeTable {name}: {got!r}, expected {want!r}"


def _assert_round_trip(ddb, table: str, key: str, marker: str) -> None:
    ddb.put_item(TableName=table, Item={"pk": {"S": key}, "marker": {"S": marker}})
    _assert_item(ddb, table, key, marker)


def _assert_item(ddb, table: str, key: str, marker: str) -> None:
    item = ddb.get_item(TableName=table, Key={"pk": {"S": key}}, ConsistentRead=True).get("Item")
    want = {"pk": {"S": key}, "marker": {"S": marker}}
    assert item == want, f"GetItem {table} pk={key!r}: {item!r}, expected {want!r}"


def _delete_table(ctx, ddb, name: str) -> None:
    """Delete the retained table and wait until DynamoDB no longer knows it."""
    try:
        ddb.delete_table(TableName=name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == _NOT_FOUND_CODE:
            return
        # A table already being deleted refuses a second DeleteTable; wait for it to go.
        if code != "ResourceInUseException" or _status(ddb, name) != "DELETING":
            raise
    _wait_error(ctx, lambda: ddb.describe_table(TableName=name), _NOT_FOUND_CODE, f"table {name}")


def _status(ddb, name: str) -> str | None:
    try:
        return ddb.describe_table(TableName=name)["Table"]["TableStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _NOT_FOUND_CODE:
            raise
        return None


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message.
    """
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done."""
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"])
    _delete_stack(ctx, cfn, stack["StackId"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
