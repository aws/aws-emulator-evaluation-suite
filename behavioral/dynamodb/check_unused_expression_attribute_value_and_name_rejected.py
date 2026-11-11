"""unused-expression-attribute-value-and-name-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unused-expression-attribute-value-and-name-rejected"
GROUP = "update-expression"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0


def _error(fn):
    """(code, message) of the ClientError fn() raises; RAISES if the call unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call unexpectedly SUCCEEDED where an error was required: {resp!r}")


def _delete_table_when_possible(ddb, table_name):
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            teardown_code = exc.response.get("Error", {}).get("Code", "")
            if teardown_code not in ("ResourceNotFoundException",):
                raise RuntimeError(
                    f"dynamodb table {table_name!r} could not be deleted: {code}"
                ) from exc
            return


def _create_table(ctx, ddb):
    name = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_when_possible(ddb, name))
    deadline = time.monotonic() + _TABLE_ACTIVE_BUDGET_S
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return name
        time.sleep(2.0)
    raise AssertionError(f"table {name!r} not ACTIVE within {_TABLE_ACTIVE_BUDGET_S}s: {status!r}")


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An UpdateItem with an unused ExpressionAttributeValues or ExpressionAttributeNames entry raises
    ValidationException with the exact message and writes nothing, while the same update without it sets n to 6.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "strict"}}
    ddb.put_item(TableName=table, Item={**key, "n": {"N": "5"}})

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET n = :v",
        ExpressionAttributeValues={":v": {"N": "6"}, ":extra": {"N": "7"}},
    ))
    assert code == "ValidationException", (
        f"an unused ExpressionAttributeValues key answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    expected = (
        "1 validation error detected: Value provided in ExpressionAttributeValues unused in "
        "expressions: keys: {:extra}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET n = :v",
        ExpressionAttributeNames={"#unused": "zzz"},
        ExpressionAttributeValues={":v": {"N": "6"}},
    ))
    assert code == "ValidationException", (
        f"an unused ExpressionAttributeNames key answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    expected = (
        "1 validation error detected: Value provided in ExpressionAttributeNames unused in "
        "expressions: keys: {#unused}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert item == {**key, "n": {"N": "5"}}, (
        f"after two refused updates the item is {item!r}; expected n still 5 -- a refused "
        f"request must not apply its (otherwise valid) SET"
    )

    # Positive control: the same update, minus the stray entries.
    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET n = :v",
        ExpressionAttributeValues={":v": {"N": "6"}}, ReturnValues="UPDATED_NEW",
    )
    assert resp["Attributes"] == {"n": {"N": "6"}}, (
        f"the clean update returned {resp['Attributes']!r}, expected n=6"
    )
    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert final == {**key, "n": {"N": "6"}}, f"final item {final!r}, expected n=6"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
