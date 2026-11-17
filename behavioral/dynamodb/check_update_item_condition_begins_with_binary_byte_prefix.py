"""update-item-condition-begins-with-binary-byte-prefix."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-condition-begins-with-binary-byte-prefix"
GROUP = "conditions"
SERVICES = ["dynamodb"]

_CCFE = ("ConditionalCheckFailedException", "The conditional request failed")


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


def _item(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem's ConditionExpression begins_with on a Binary attribute evaluates by raw byte
    prefix: a non-prefix byte string fails the write with ConditionalCheckFailedException and
    leaves the item unchanged, while a true byte prefix — shorter than or equal in length — applies it.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbbwb-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    pk = "bin-item"
    payload = b"\x01\x02\xff\x00\x80"
    ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "bindata": {"B": payload}, "rev": {"N": "0"}})

    # A byte string that is not a prefix of the stored value: the condition evaluates false.
    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key={"pk": {"S": pk}},
            UpdateExpression="SET rev = :r",
            ConditionExpression="begins_with(bindata, :p)",
            ExpressionAttributeValues={":r": {"N": "1"}, ":p": {"B": b"\x01\x03"}},
        ),
        *_CCFE,
    )
    item = _item(ddb, table, pk)
    assert item == {"pk": {"S": pk}, "bindata": {"B": payload}, "rev": {"N": "0"}}, (
        f"a rejected UpdateItem must leave the item unchanged, got {item!r}"
    )

    # A byte string longer than the stored value can never be a prefix of it either.
    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key={"pk": {"S": pk}},
            UpdateExpression="SET rev = :r",
            ConditionExpression="begins_with(bindata, :p)",
            ExpressionAttributeValues={":r": {"N": "1"}, ":p": {"B": payload + b"\x00"}},
        ),
        *_CCFE,
    )
    item = _item(ddb, table, pk)
    assert item == {"pk": {"S": pk}, "bindata": {"B": payload}, "rev": {"N": "0"}}, (
        f"a rejected UpdateItem on an over-length operand must leave the item unchanged, got {item!r}"
    )

    # A true byte prefix, shorter than the stored value: the condition holds and the write lands.
    ddb.update_item(
        TableName=table, Key={"pk": {"S": pk}},
        UpdateExpression="SET rev = :r",
        ConditionExpression="begins_with(bindata, :p)",
        ExpressionAttributeValues={":r": {"N": "1"}, ":p": {"B": b"\x01\x02"}},
    )
    item = _item(ddb, table, pk)
    assert item == {"pk": {"S": pk}, "bindata": {"B": payload}, "rev": {"N": "1"}}, (
        f"UpdateItem under a holding begins_with prefix condition left {item!r}"
    )

    # A byte string equal to the whole stored value is itself a true prefix.
    ddb.update_item(
        TableName=table, Key={"pk": {"S": pk}},
        UpdateExpression="SET rev = :r",
        ConditionExpression="begins_with(bindata, :p)",
        ExpressionAttributeValues={":r": {"N": "2"}, ":p": {"B": payload}},
    )
    item = _item(ddb, table, pk)
    assert item == {"pk": {"S": pk}, "bindata": {"B": payload}, "rev": {"N": "2"}}, (
        f"UpdateItem under an exact-length begins_with prefix condition left {item!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
