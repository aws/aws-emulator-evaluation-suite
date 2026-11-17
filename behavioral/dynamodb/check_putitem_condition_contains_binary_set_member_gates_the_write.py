"""putitem-condition-contains-binary-set-member-gates-the-write."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "putitem-condition-contains-binary-set-member-gates-the-write"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_COND_FAILED = ("ConditionalCheckFailedException", "The conditional request failed")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success fails too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _normalized(item):
    """``item`` with its BS member order sorted; DynamoDB sets carry no element order."""
    out = dict(item)
    if "chunks" in out and "BS" in out["chunks"]:
        out["chunks"] = {"BS": sorted(out["chunks"]["BS"])}
    return out


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutItem ConditionExpression `contains(#c, :v)` over a BS tests binary-set membership
    by exact byte value: it fails, item unchanged, for a binary value absent from the set, and
    holds, replacing the item, for a binary value present in it.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbbs-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "target"}}
    member = b"\x01\x02"
    other_member = b"\xaa\xbb"
    not_a_member = b"\x99\x99"
    initial = {**key, "chunks": {"BS": [member, other_member]}}
    ddb.put_item(TableName=table, Item=initial)

    names = {"#c": "chunks"}

    # not_a_member is absent from the BS by exact byte value, so contains() is false and the
    # conditional write is refused, leaving the item exactly as it was.
    expect_error(
        lambda: ddb.put_item(
            TableName=table, Item={**key, "chunks": {"BS": [member, other_member]}, "written": {"BOOL": True}},
            ConditionExpression="contains(#c, :v)",
            ExpressionAttributeNames=names, ExpressionAttributeValues={":v": {"B": not_a_member}},
        ),
        *_COND_FAILED,
    )
    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert _normalized(unchanged) == _normalized(initial), (
        f"PutItem under a failing contains() condition left {unchanged!r}, expected {initial!r} unchanged"
    )

    # member is present in the BS by exact byte value, so contains() holds and the write
    # replaces the item.
    ddb.put_item(
        TableName=table, Item={**key, "chunks": {"BS": [member, other_member]}, "written": {"BOOL": True}},
        ConditionExpression="contains(#c, :v)",
        ExpressionAttributeNames=names, ExpressionAttributeValues={":v": {"B": member}},
    )
    replaced = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    expected = {**key, "chunks": {"BS": [member, other_member]}, "written": {"BOOL": True}}
    assert _normalized(replaced) == _normalized(expected), (
        f"PutItem under a holding contains() condition left {replaced!r}, expected {expected!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
