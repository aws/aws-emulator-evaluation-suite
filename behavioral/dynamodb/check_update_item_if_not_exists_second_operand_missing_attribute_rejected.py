"""update-item-if-not-exists-second-operand-missing-attribute-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-if-not-exists-second-operand-missing-attribute-rejected"
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
            raise RuntimeError(
                f"dynamodb table {table_name!r} could not be deleted: {code}"
            ) from exc


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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """`SET b = if_not_exists(b, a)` raises ValidationException with the exact message when
    both `b` and the document-path operand `a` are absent, and leaves the item unchanged.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "row-both-missing"}}
    ddb.put_item(TableName=table, Item={**key, "label": {"S": "orig"}})

    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET b = if_not_exists(b, a)",
    ))
    assert code == "ValidationException", (
        f"if_not_exists(b, a) with both b and a absent answered {code!r} ({message!r}), "
        f"expected ValidationException"
    )
    assert message == "The provided expression refers to an attribute that does not exist in the item", (
        f"the refusal's message is {message!r}; real AWS names the missing fallback operand as "
        f"an attribute that does not exist in the item"
    )

    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert item == {**key, "label": {"S": "orig"}}, (
        f"after the refused SET the item is {item!r}; a refused UpdateItem must change nothing"
    )

    # Positive control: the same expression succeeds once the fallback operand `a` exists.
    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET a = :v",
        ExpressionAttributeValues={":v": {"S": "fallback-value"}},
    )
    ok = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET b = if_not_exists(b, a)",
        ReturnValues="ALL_NEW",
    )["Attributes"]
    assert ok == {**key, "label": {"S": "orig"}, "a": {"S": "fallback-value"}, "b": {"S": "fallback-value"}}, (
        f"if_not_exists(b, a) with a present returned {ok!r}, expected b copied from a"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
