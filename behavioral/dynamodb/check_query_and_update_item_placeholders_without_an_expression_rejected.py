"""query-and-update-item-placeholders-without-an-expression-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-and-update-item-placeholders-without-an-expression-rejected"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_EAN_MSG = "ExpressionAttributeNames can only be specified when using expressions"
_EAV_MSG = "ExpressionAttributeValues can only be specified when using expressions"
_UPDATE_EAN_MSG = "1 validation error detected: " + _EAN_MSG
_UPDATE_EAV_MSG = "1 validation error detected: " + _EAV_MSG


def _teardown(undo, *not_found, timeout_s=300.0):
    """A cleanup running undo() where a failed delete raises; in-use is retried every 2 s."""
    def run_undo():
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                undo()
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code in not_found:
                    return
                if code != "ResourceInUseException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2)
    return run_undo


def _wait_active(ddb, ctx, table):
    """Poll DescribeTable every 2 s until the table and its indexes are ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE" and all(
            g.get("IndexStatus") == "ACTIVE" for g in desc.get("GlobalSecondaryIndexes", [])
        ):
            return desc
        time.sleep(2)
    raise AssertionError(f"table {table} not ACTIVE before the deadline: {desc!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """ExpressionAttributeNames or Values on a legacy-KeyConditions Query, or on an UpdateItem with
    no UpdateExpression or ConditionExpression, is ValidationException and creates no item.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ExpressionAttributeNames.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-placeholders-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)
    item = {"pk": {"S": "k1"}, "foo": {"S": "a"}}
    ddb.put_item(TableName=table, Item=item)
    key_conditions = {"pk": {"AttributeValueList": [{"S": "k1"}], "ComparisonOperator": "EQ"}}
    absent = {"pk": {"S": "k2"}}

    cases = [
        ("Query KeyConditions with ExpressionAttributeNames", _EAN_MSG,
         lambda: ddb.query(TableName=table, KeyConditions=key_conditions,
                           ExpressionAttributeNames={"#a": "pk"})),
        ("Query KeyConditions with ExpressionAttributeValues", _EAV_MSG,
         lambda: ddb.query(TableName=table, KeyConditions=key_conditions,
                           ExpressionAttributeValues={":v": {"S": "x"}})),
        ("UpdateItem with only ExpressionAttributeNames", _UPDATE_EAN_MSG,
         lambda: ddb.update_item(TableName=table, Key=absent, ExpressionAttributeNames={"#a": "foo"})),
        ("UpdateItem with only ExpressionAttributeValues", _UPDATE_EAV_MSG,
         lambda: ddb.update_item(TableName=table, Key=absent,
                                 ExpressionAttributeValues={":v": {"S": "x"}})),
    ]
    for label, want, fn in cases:
        code, msg = _error(fn)
        assert (code, msg) == ("ValidationException", want), f"{label} gave {code!r}: {msg!r}"

    items = ddb.scan(TableName=table, ConsistentRead=True)["Items"]
    assert items == [item], f"table after the refused calls holds {items!r}, expected only {item!r}"

    page = ddb.query(TableName=table, KeyConditions=key_conditions, ConsistentRead=True)
    assert page["Items"] == [item], f"Query with KeyConditions alone returned {page['Items']!r}"
    ddb.update_item(TableName=table, Key=absent, UpdateExpression="SET #a = :v",
                    ExpressionAttributeNames={"#a": "foo"},
                    ExpressionAttributeValues={":v": {"S": "x"}})
    got = ddb.get_item(TableName=table, Key=absent, ConsistentRead=True).get("Item")
    assert got == {**absent, "foo": {"S": "x"}}, f"UpdateItem SET #a = :v left {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
