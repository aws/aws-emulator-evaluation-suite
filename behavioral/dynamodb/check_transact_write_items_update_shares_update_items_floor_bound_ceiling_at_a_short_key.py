"""transact-write-items-update-shares-update-items-floor-bound-ceiling-at-a-short-key."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-update-shares-update-items-floor-bound-ceiling-at-a-short-key"
GROUP = "limits"
SERVICES = ["dynamodb"]

_CAP = 409600
_ITEM_TOO_LARGE = ("ValidationException", "Item size to update has exceeded the maximum allowed size")


def _error(fn):
    """(code, message) of the ClientError fn() raises; raises if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code!r}, got {got_code!r} ({got_message!r})"
    assert got_message == message, f"unexpected message {got_message!r}"


def _item_bytes(key: dict, data_value: str) -> int:
    """Encoded size of {key, 'v': {'S': data_value}}: every attribute name's and value's bytes."""
    total = len("v") + len(data_value)
    for name, value in key.items():
        total += len(name) + len(value["S"])
    return total


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TransactWriteItems' Update action, on a one-byte key, is bound by the same floor-bound
    ceiling as a standalone UpdateItem, not the flat 409600-byte item cap, and a statement
    exceeding it raises the identical ValidationException code and message.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ServiceQuotas.html#limits-items
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbtxnupd-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "k", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "k", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 30})

    # Every key below is one byte, far under the 22-byte floor that keeps UpdateItem's own
    # ceiling flat and short of the flat 409600-byte item cap.
    control_key = {"k": {"S": "0"}}
    ddb.put_item(TableName=table, Item={**control_key, "v": {"S": "start"}})

    # Positive control: a standalone UpdateItem's own ceiling for this short key tops out 20
    # bytes below the flat cap (409600 minus the 22-byte floor, plus the 2 preexisting key
    # bytes); at that ceiling it succeeds.
    ceiling_total = _CAP - 20
    ceiling_value = "x" * (ceiling_total - _item_bytes(control_key, ""))
    ddb.update_item(
        TableName=table, Key=control_key, UpdateExpression="SET v = :v",
        ExpressionAttributeValues={":v": {"S": ceiling_value}},
    )
    control_got = ddb.get_item(TableName=table, Key=control_key, ConsistentRead=True)["Item"]
    assert _item_bytes(control_key, control_got["v"]["S"]) == ceiling_total, (
        f"UpdateItem's own ceiling write landed at "
        f"{_item_bytes(control_key, control_got['v']['S'])} bytes, expected {ceiling_total}"
    )

    # Refusal: targeting the flat 409600-byte cap on this short key is 20 bytes past
    # UpdateItem's own ceiling, and UpdateItem refuses it -- the item stays at its seeded value.
    refuse_key = {"k": {"S": "1"}}
    ddb.put_item(TableName=table, Item={**refuse_key, "v": {"S": "start"}})
    over_ceiling_value = "x" * (_CAP - _item_bytes(refuse_key, ""))
    expect_error(
        lambda: ddb.update_item(
            TableName=table, Key=refuse_key, UpdateExpression="SET v = :v",
            ExpressionAttributeValues={":v": {"S": over_ceiling_value}},
        ),
        *_ITEM_TOO_LARGE,
    )
    refused = ddb.get_item(TableName=table, Key=refuse_key, ConsistentRead=True)["Item"]
    assert refused["v"]["S"] == "start", (
        f"a refused UpdateItem must leave the item unchanged, got {refused['v']['S']!r}"
    )

    # TransactWriteItems' Update, on the same short-key shape, accepts exactly the same
    # ceiling a standalone UpdateItem accepts -- it does not get the flat 409600-byte cap
    # UpdateItem is denied here.
    txn_key = {"k": {"S": "2"}}
    ddb.put_item(TableName=table, Item={**txn_key, "v": {"S": "start"}})
    txn_ceiling_value = "x" * (ceiling_total - _item_bytes(txn_key, ""))
    assert len(txn_ceiling_value) == len(ceiling_value), "txn and UpdateItem targeted different totals"
    ddb.transact_write_items(TransactItems=[{"Update": {
        "TableName": table,
        "Key": txn_key,
        "UpdateExpression": "SET v = :v",
        "ExpressionAttributeValues": {":v": {"S": txn_ceiling_value}},
    }}])
    txn_got = ddb.get_item(TableName=table, Key=txn_key, ConsistentRead=True)["Item"]
    assert txn_got["v"]["S"] == txn_ceiling_value, (
        f"the {ceiling_total}-byte value must round-trip whole through TransactWriteItems Update, "
        f"got {len(txn_got['v']['S'])} bytes back"
    )
    assert _item_bytes(txn_key, txn_got["v"]["S"]) == ceiling_total, (
        f"stored item size is {_item_bytes(txn_key, txn_got['v']['S'])}, expected {ceiling_total}"
    )

    # And TransactWriteItems' Update refuses the same statement UpdateItem refuses, with the
    # identical ValidationException code and message -- the call itself fails, not a
    # TransactionCanceledException wrapping a per-item cancellation reason.
    over_key = {"k": {"S": "3"}}
    ddb.put_item(TableName=table, Item={**over_key, "v": {"S": "start"}})
    txn_over_ceiling_value = "x" * (_CAP - _item_bytes(over_key, ""))
    assert len(txn_over_ceiling_value) == len(over_ceiling_value), (
        "txn and UpdateItem targeted different over-ceiling totals"
    )
    expect_error(
        lambda: ddb.transact_write_items(TransactItems=[{"Update": {
            "TableName": table,
            "Key": over_key,
            "UpdateExpression": "SET v = :v",
            "ExpressionAttributeValues": {":v": {"S": txn_over_ceiling_value}},
        }}]),
        *_ITEM_TOO_LARGE,
    )
    over_unchanged = ddb.get_item(TableName=table, Key=over_key, ConsistentRead=True)["Item"]
    assert over_unchanged["v"]["S"] == "start", (
        f"a TransactWriteItems Update refused for size must leave the item unchanged, "
        f"got {over_unchanged['v']['S']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
