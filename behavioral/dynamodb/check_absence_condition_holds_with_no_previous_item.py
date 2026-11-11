"""absence-condition-holds-with-no-previous-item."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "absence-condition-holds-with-no-previous-item"
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
    """With no item at a key — never written, or most recently deleted —
    attribute_not_exists(pk) holds for DeleteItem and PutItem, while attribute_exists(pk)
    fails them both with ConditionalCheckFailedException and leaves no item behind.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbabs-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # A key that was never written: a presence condition fails DeleteItem.
    never_written = "never-written"
    expect_error(
        lambda: ddb.delete_item(TableName=table, Key={"pk": {"S": never_written}},
                                ConditionExpression="attribute_exists(pk)"),
        *_CCFE,
    )
    assert _item(ddb, table, never_written) is None, (
        f"a rejected DeleteItem must not create {never_written!r}, got {_item(ddb, table, never_written)!r}"
    )

    # The identical key's absence condition holds: DeleteItem succeeds with no effect.
    deleted_response = ddb.delete_item(TableName=table, Key={"pk": {"S": never_written}},
                                       ConditionExpression="attribute_not_exists(pk)")
    assert "Attributes" not in deleted_response, (
        f"DeleteItem on a never-written key returned Attributes: {deleted_response.get('Attributes')!r}"
    )
    assert _item(ddb, table, never_written) is None, (
        f"expected {never_written!r} to remain absent, got {_item(ddb, table, never_written)!r}"
    )

    # A key that was written, then most recently deleted: the same two conditions apply.
    deleted_key = "most-recently-deleted"
    ddb.put_item(TableName=table, Item={"pk": {"S": deleted_key}, "marker": {"S": "seed"}})
    present = _item(ddb, table, deleted_key)
    assert present == {"pk": {"S": deleted_key}, "marker": {"S": "seed"}}, (
        f"expected the seeded item before delete, got {present!r}"
    )

    ddb.delete_item(TableName=table, Key={"pk": {"S": deleted_key}})
    assert _item(ddb, table, deleted_key) is None, (
        f"expected {deleted_key!r} absent right after its unconditional delete, got {_item(ddb, table, deleted_key)!r}"
    )

    # A presence condition fails PutItem against the now-deleted key.
    expect_error(
        lambda: ddb.put_item(TableName=table, Item={"pk": {"S": deleted_key}, "marker": {"S": "should-not-land"}},
                             ConditionExpression="attribute_exists(pk)"),
        *_CCFE,
    )
    assert _item(ddb, table, deleted_key) is None, (
        f"a rejected PutItem must not resurrect {deleted_key!r}, got {_item(ddb, table, deleted_key)!r}"
    )

    # The absence condition holds for PutItem against the deleted key, and the write lands.
    ddb.put_item(TableName=table, Item={"pk": {"S": deleted_key}, "marker": {"S": "restored"}},
                 ConditionExpression="attribute_not_exists(pk)")
    restored = _item(ddb, table, deleted_key)
    assert restored == {"pk": {"S": deleted_key}, "marker": {"S": "restored"}}, (
        f"expected the restored PutItem to land, got {restored!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
