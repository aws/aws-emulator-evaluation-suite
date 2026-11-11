"""update-list-append-on-ghost-attribute-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-list-append-on-ghost-attribute-rejected"
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


_MISSING_ATTR = "The provided expression refers to an attribute that does not exist in the item"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """`list_append` naming an attribute the item does not have raises ValidationException
    naming the ghost attribute and leaves the item unchanged; the same call against an
    existing list attribute still appends.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "doc"}}
    original = {**key, "kept": {"S": "k"}, "history": {"L": [{"S": "a"}]}}
    ddb.put_item(TableName=table, Item=original)

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET ghost = list_append(ghost, :l)",
        ExpressionAttributeValues={":l": {"L": [{"S": "x"}]}},
    ))
    assert code == "ValidationException", (
        f"list_append(ghost, :l) on an absent attribute answered {code!r} ({message!r}), "
        f"expected ValidationException"
    )
    assert message == _MISSING_ATTR, (
        f"list_append(ghost, :l) refusal message is {message!r}, expected {_MISSING_ATTR!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == original, (
        f"after the refused list_append the item is {unchanged!r}, expected it unchanged "
        f"from {original!r}"
    )
    assert "ghost" not in unchanged, (
        f"a refused list_append must not create the attribute it named: {unchanged!r}"
    )

    # Positive control: the identical function call against an existing list attribute appends.
    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET history = list_append(history, :l)",
        ExpressionAttributeValues={":l": {"L": [{"S": "b"}]}}, ReturnValues="UPDATED_NEW",
    )
    assert resp["Attributes"] == {"history": {"L": [{"S": "a"}, {"S": "b"}]}}, (
        f"list_append(history, :l) on an existing list returned {resp['Attributes']!r}, "
        f"expected [a, b]"
    )
    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert final == {**key, "kept": {"S": "k"}, "history": {"L": [{"S": "a"}, {"S": "b"}]}}, (
        f"final item is {final!r}, expected kept intact and history=[a, b]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
