"""expression-attribute-keys-without-prefix-rejected-on-item-ops."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "expression-attribute-keys-without-prefix-rejected-on-item-ops"
GROUP = "expressions"
SERVICES = ["dynamodb"]

# Write operations prefix expression validation messages; GetItem does not.
_WRITE_PREFIX = "1 validation error detected: "
_READ_PREFIX = ""


def _bad_name_msg(prefix, key):
    return f'{prefix}ExpressionAttributeNames contains invalid key: Syntax error; key: "{key}"'


def _bad_value_msg(prefix, key):
    return f'{prefix}ExpressionAttributeValues contains invalid key: Syntax error; key: "{key}"'


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
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + max(0.0, (ctx.time_left() or 300.0) - 30.0)
    desc = None
    while time.monotonic() < deadline:
        desc = ddb.describe_table(TableName=table)["Table"]
        if desc["TableStatus"] == "ACTIVE":
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


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An ExpressionAttributeNames key without '#' or an ExpressionAttributeValues key without
    ':' is a syntax error naming the key on PutItem, GetItem, UpdateItem and DeleteItem.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ExpressionAttributeNames.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-eakey-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, ctx, table)

    key = {"pk": {"S": "item1"}}
    seeded = {**key, "v": {"S": "val"}}
    ddb.put_item(TableName=table, Item=seeded)
    new_key = {"pk": {"S": "new"}}

    arms = [
        ("PutItem name 'bad'", _bad_name_msg(_WRITE_PREFIX, "bad"), lambda: ddb.put_item(
            TableName=table, Item=new_key, ConditionExpression="attribute_not_exists(pk)",
            ExpressionAttributeNames={"bad": "pk"})),
        ("GetItem name 'nohash'", _bad_name_msg(_READ_PREFIX, "nohash"), lambda: ddb.get_item(
            TableName=table, Key=key, ProjectionExpression="v",
            ExpressionAttributeNames={"nohash": "v"})),
        ("UpdateItem name 'missing_hash'", _bad_name_msg(_WRITE_PREFIX, "missing_hash"), lambda: ddb.update_item(
            TableName=table, Key=key, UpdateExpression="SET v = :val",
            ExpressionAttributeNames={"missing_hash": "v"},
            ExpressionAttributeValues={":val": {"S": "new"}})),
        ("DeleteItem name 'nope'", _bad_name_msg(_WRITE_PREFIX, "nope"), lambda: ddb.delete_item(
            TableName=table, Key=key, ConditionExpression="attribute_exists(v)",
            ExpressionAttributeNames={"nope": "v"})),
        ("PutItem value 'nocolon'", _bad_value_msg(_WRITE_PREFIX, "nocolon"), lambda: ddb.put_item(
            TableName=table, Item=new_key, ConditionExpression="attribute_not_exists(pk)",
            ExpressionAttributeValues={"nocolon": {"S": "x"}})),
        ("UpdateItem value 'val'", _bad_value_msg(_WRITE_PREFIX, "val"), lambda: ddb.update_item(
            TableName=table, Key=key, UpdateExpression="SET v = :val",
            ExpressionAttributeValues={"val": {"S": "new"}})),
        ("DeleteItem value 'nocolon'", _bad_value_msg(_WRITE_PREFIX, "nocolon"), lambda: ddb.delete_item(
            TableName=table, Key=key, ConditionExpression="v = :v",
            ExpressionAttributeValues={"nocolon": {"S": "val"}})),
    ]
    for label, want, call in arms:
        code, msg = _error(call)
        assert (code, msg) == ("ValidationException", want), f"{label} gave {code!r}: {msg!r}"

    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert item == seeded, f"after the refused requests item1 is {item!r}, expected {seeded!r}"
    absent = ddb.get_item(TableName=table, Key=new_key, ConsistentRead=True).get("Item")
    assert absent is None, f"a refused PutItem stored {absent!r}"

    # Positive control: the same requests with prefixed keys succeed.
    got = ddb.get_item(TableName=table, Key=key, ProjectionExpression="#v",
                       ExpressionAttributeNames={"#v": "v"}, ConsistentRead=True).get("Item")
    assert got == {"v": {"S": "val"}}, f"GetItem projecting #v returned {got!r}"
    ddb.update_item(TableName=table, Key=key, UpdateExpression="SET #v = :val",
                    ExpressionAttributeNames={"#v": "v"},
                    ExpressionAttributeValues={":val": {"S": "new"}})
    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert item == {**key, "v": {"S": "new"}}, f"the well-formed UpdateItem left {item!r}"
    ddb.put_item(TableName=table, Item=new_key, ConditionExpression="attribute_not_exists(#pk)",
                 ExpressionAttributeNames={"#pk": "pk"})
    stored = ddb.get_item(TableName=table, Key=new_key, ConsistentRead=True).get("Item")
    assert stored == new_key, f"the well-formed conditional PutItem stored {stored!r}"
    ddb.delete_item(TableName=table, Key=key, ConditionExpression="attribute_exists(#v)",
                    ExpressionAttributeNames={"#v": "v"})
    gone = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert gone is None, f"the well-formed conditional DeleteItem left {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
