"""update-item-set-list-index-on-missing-item-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-set-list-index-on-missing-item-rejected"
GROUP = "update-expression"
SERVICES = ["dynamodb"]
ERR_VALIDATION = "ValidationException"
MSG_INVALID_PATH = "The document path provided in the update expression is invalid for update"


def _table(ctx, ddb) -> str:
    name = ctx.unique_name("sim2real-behav-ddbnp-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _stored(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")


def _error(fn):
    """(code, message) of the ClientError fn raises. Raises if fn SUCCEEDS."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call was expected to be rejected but succeeded: {resp!r}")


@tags(
    "dp:api",
    "plane:data",
    "concern:data-plane",
    "concern:negative-classes",
    "axis:rejection",
    "cap:c1",
)
def run(ctx) -> None:
    """SET b[1] on a key holding no item is rejected with ValidationException and creates no
    item; the same expression succeeds once the item exists with a list attribute b.
    """
    ddb = ctx.client("dynamodb")
    t = _table(ctx, ddb)
    key = {"pk": {"S": "no-item"}}
    vals = {":v": {"S": "x"}}

    assert _stored(ddb, t, "no-item") is None, "the key already holds an item before the test"
    code, msg = _error(lambda: ddb.update_item(
        TableName=t, Key=key, UpdateExpression="SET b[1] = :v", ExpressionAttributeValues=vals,
    ))
    assert code == ERR_VALIDATION, f"SET b[1] on a missing item: expected {ERR_VALIDATION}, got {code!r} ({msg!r})"
    assert msg == MSG_INVALID_PATH, f"SET b[1] on a missing item: expected {MSG_INVALID_PATH!r}, got {msg!r}"
    assert _stored(ddb, t, "no-item") is None, "the rejected SET b[1] created an item anyway"

    # Positive control: once the item exists with b as a list, the same bracket-indexed SET works.
    key2 = {"pk": {"S": "has-item"}}
    ddb.put_item(TableName=t, Item={**key2, "b": {"L": [{"S": "v0"}]}})
    resp = ddb.update_item(
        TableName=t, Key=key2, UpdateExpression="SET b[1] = :v", ExpressionAttributeValues=vals,
        ReturnValues="ALL_NEW",
    )
    assert resp["Attributes"] == {**key2, "b": {"L": [{"S": "v0"}, {"S": "x"}]}}, (
        f"SET b[1] once the item and list exist returned ALL_NEW {resp['Attributes']!r}, "
        f"expected b=[v0, x]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
