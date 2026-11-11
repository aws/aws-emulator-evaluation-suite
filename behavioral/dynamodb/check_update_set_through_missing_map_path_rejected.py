"""update-set-through-missing-map-path-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-set-through-missing-map-path-rejected"
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
    """SET on a nested path whose parent map does not exist fails with ValidationException and
    writes nothing (no auto-created maps); once the map exists the same SET succeeds."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "doc"}}
    ddb.put_item(TableName=table, Item={**key, "keep": {"S": "k"}})

    for expr in ("SET m.a.b = :v", "SET m.a = :v"):
        code, message = _error(lambda expr=expr: ddb.update_item(
            TableName=table, Key=key, UpdateExpression=expr,
            ExpressionAttributeValues={":v": {"S": "deep"}},
        ))
        assert code == "ValidationException", (
            f"{expr!r} with no stored map m answered {code!r} ({message!r}), expected "
            f"ValidationException"
        )
        assert message == _PATH_INVALID, (
            f"{expr!r} refusal message is {message!r}, expected {_PATH_INVALID!r}"
        )

    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert item == {**key, "keep": {"S": "k"}}, (
        f"after two refused nested SETs the item is {item!r}; a refused update must not "
        f"auto-create the intermediate map"
    )

    # Positive control: create the parent, then the identical one-level SET is legal.
    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET m = :empty",
        ExpressionAttributeValues={":empty": {"M": {}}},
    )
    resp = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET m.a = :v",
        ExpressionAttributeValues={":v": {"S": "deep"}}, ReturnValues="UPDATED_NEW",
    )
    assert resp["Attributes"] == {"m": {"M": {"a": {"S": "deep"}}}}, (
        f"SET m.a once m exists returned {resp['Attributes']!r}, expected m={{a: deep}}"
    )
    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert final == {**key, "keep": {"S": "k"}, "m": {"M": {"a": {"S": "deep"}}}}, (
        f"final item {final!r}, expected keep intact and m={{a: deep}}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
