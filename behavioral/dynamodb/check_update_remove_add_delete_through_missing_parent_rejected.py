"""update-remove-add-delete-through-missing-parent-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-remove-add-delete-through-missing-parent-rejected"
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
            raise


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


_PATH_INVALID = "The document path provided in the update expression is invalid for update"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """REMOVE, ADD and DELETE each reject a nested path whose top-level attribute does not
    exist at all, leaving the item unchanged, while the same path is legal once that attribute
    is created as a map."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "doc"}}
    original = {**key, "keep": {"S": "k"}}
    ddb.put_item(TableName=table, Item=original)

    # REMOVE through a path whose top-level attribute ("m") does not exist at all.
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="REMOVE m.a",
    ))
    assert code == "ValidationException", (
        f"REMOVE m.a with no stored m answered {code!r} ({message!r}), expected ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"REMOVE m.a refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    # ADD through the same missing top-level attribute.
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD m.a :one",
        ExpressionAttributeValues={":one": {"N": "1"}},
    ))
    assert code == "ValidationException", (
        f"ADD m.a :one with no stored m answered {code!r} ({message!r}), expected ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"ADD m.a :one refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    # DELETE through the same missing top-level attribute.
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE m.a :v",
        ExpressionAttributeValues={":v": {"SS": ["x"]}},
    ))
    assert code == "ValidationException", (
        f"DELETE m.a :v with no stored m answered {code!r} ({message!r}), expected ValidationException"
    )
    assert message == _PATH_INVALID, (
        f"DELETE m.a :v refusal message is {message!r}, expected {_PATH_INVALID!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == original, (
        f"after the three refused missing-parent updates the item is {unchanged!r}, expected it "
        f"unchanged from {original!r}"
    )
    assert "m" not in unchanged, (
        f"a refused update through a missing parent must not create it: {unchanged!r}"
    )

    # Positive controls: the same path forms once the top-level attribute exists as a map.
    ddb.update_item(TableName=table, Key=key, UpdateExpression="SET m = :empty",
                     ExpressionAttributeValues={":empty": {"M": {}}})

    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD m.a :one",
        ExpressionAttributeValues={":one": {"N": "1"}}, ReturnValues="UPDATED_NEW",
    )
    assert resp["Attributes"] == {"m": {"M": {"a": {"N": "1"}}}}, (
        f"ADD m.a :one once m exists returned {resp['Attributes']!r}, expected m={{a: 1}}"
    )

    ddb.update_item(TableName=table, Key=key, UpdateExpression="REMOVE m.a")
    after_remove = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after_remove["m"] == {"M": {}}, (
        f"REMOVE m.a once m exists left {after_remove['m']!r}, expected an empty map"
    )

    # DELETE through an existing map parent against a set member that is itself absent is a
    # documented no-op, not a path error: it still demonstrates the parent path is now valid.
    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE m.tags :v",
        ExpressionAttributeValues={":v": {"SS": ["x"]}},
    )
    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert final == {**key, "keep": {"S": "k"}, "m": {"M": {}}}, (
        f"final item is {final!r}, expected keep intact and m={{}}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
